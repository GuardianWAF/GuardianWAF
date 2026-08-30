// Package tenant provides multi-tenancy support with namespace isolation.
package tenant

import (
	"sync"
	"time"
)

// RateTracker tracks request rates using a sliding window algorithm.
// Requests are bucketed per second: each slot counts the hits of one unix
// second, so a burst inside the window is counted instead of collapsed.
type RateTracker struct {
	mu        sync.RWMutex
	window    time.Duration
	slots     []int64   // per-second request counters, indexed by unix-second modulo
	secs      []int64   // unix second each bucket belongs to (staleness check)
	lastWrite time.Time // last Record() time, used by TenantRateLimiter.Cleanup
}

// NewRateTracker creates a new rate tracker with the given window size.
func NewRateTracker(window time.Duration) *RateTracker {
	// Pre-allocate slots for the window (one slot per second)
	slotCount := int(window.Seconds())
	if slotCount < 60 {
		slotCount = 60 // Minimum 60 slots (1 minute)
	}
	return &RateTracker{
		window: window,
		slots:  make([]int64, slotCount),
		secs:   make([]int64, slotCount),
	}
}

// Record records a request at the current time.
func (rt *RateTracker) Record() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	idx := int(now.Unix()) % len(rt.slots)
	if rt.secs[idx] != now.Unix() {
		rt.secs[idx] = now.Unix()
		rt.slots[idx] = 0
	}
	rt.slots[idx]++
	rt.lastWrite = now
}

// Count returns the number of requests in the window. Only buckets belonging
// to the exact seconds inside the window are summed — a stale bucket whose
// second has been reused by an older window rotation counts as zero.
func (rt *RateTracker) Count() int64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	now := time.Now().Unix()
	windowSecs := int64(rt.window.Seconds())
	if windowSecs > int64(len(rt.slots)) {
		windowSecs = int64(len(rt.slots))
	}
	var count int64
	for i := int64(0); i < windowSecs; i++ {
		idx := int((now - i) % int64(len(rt.slots)))
		if rt.secs[idx] == now-i {
			count += rt.slots[idx]
		}
	}
	return count
}

// Reset clears all recorded requests.
func (rt *RateTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for i := range rt.slots {
		rt.slots[i] = 0
		rt.secs[i] = 0
	}
	rt.lastWrite = time.Time{}
}

// TenantRateLimiter provides per-tenant rate limiting with sliding windows.
type TenantRateLimiter struct {
	mu           sync.RWMutex
	trackers     map[string]*RateTracker // key: tenant ID
	window       time.Duration
	defaultLimit int64
}

// NewTenantRateLimiter creates a new tenant rate limiter.
func NewTenantRateLimiter(window time.Duration) *TenantRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &TenantRateLimiter{
		trackers:     make(map[string]*RateTracker),
		window:       window,
		defaultLimit: 10000,
	}
}

// Record records a request for the given tenant.
func (trl *TenantRateLimiter) Record(tenantID string) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	tracker, exists := trl.trackers[tenantID]
	if !exists {
		tracker = NewRateTracker(trl.window)
		trl.trackers[tenantID] = tracker
	}
	tracker.Record()
}

// Check checks if the tenant has exceeded their rate limit.
func (trl *TenantRateLimiter) Check(tenantID string, limit int64) bool {
	trl.mu.RLock()
	defer trl.mu.RUnlock()

	tracker, exists := trl.trackers[tenantID]
	if !exists {
		return true // No requests yet, allow
	}

	if limit <= 0 {
		limit = trl.defaultLimit
	}

	return tracker.Count() < limit
}

// Count returns the current request count for a tenant.
func (trl *TenantRateLimiter) Count(tenantID string) int64 {
	trl.mu.RLock()
	defer trl.mu.RUnlock()

	tracker, exists := trl.trackers[tenantID]
	if !exists {
		return 0
	}
	return tracker.Count()
}

// Cleanup removes old trackers for tenants that haven't made requests recently.
func (trl *TenantRateLimiter) Cleanup(maxAge time.Duration) {
	trl.mu.Lock()
	defer trl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, tracker := range trl.trackers {
		tracker.mu.RLock()
		hasRecent := tracker.lastWrite.After(cutoff)
		tracker.mu.RUnlock()

		if !hasRecent {
			delete(trl.trackers, id)
		}
	}
}
