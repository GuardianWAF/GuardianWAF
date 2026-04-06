// Package tenant provides multi-tenancy support with namespace isolation.
package tenant

import (
	"sync"
	"time"
)

// RateTracker tracks request rates using a sliding window algorithm.
type RateTracker struct {
	mu       sync.RWMutex
	window   time.Duration
	slots    []time.Time
	position int
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
		slots:  make([]time.Time, slotCount),
	}
}

// Record records a request at the current time.
func (rt *RateTracker) Record() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	rt.slots[rt.position] = now
	rt.position = (rt.position + 1) % len(rt.slots)
}

// Count returns the number of requests in the window.
func (rt *RateTracker) Count() int64 {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	cutoff := time.Now().Add(-rt.window)
	var count int64
	for _, t := range rt.slots {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// Reset clears all recorded requests.
func (rt *RateTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for i := range rt.slots {
		rt.slots[i] = time.Time{}
	}
	rt.position = 0
}

// TenantRateLimiter provides per-tenant rate limiting with sliding windows.
type TenantRateLimiter struct {
	mu        sync.RWMutex
	trackers  map[string]*RateTracker // key: tenant ID
	window    time.Duration
	defaultLimit int64
}

// NewTenantRateLimiter creates a new tenant rate limiter.
func NewTenantRateLimiter(window time.Duration) *TenantRateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &TenantRateLimiter{
		trackers: make(map[string]*RateTracker),
		window:   window,
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
		// Check if any slot is recent
		hasRecent := false
		tracker.mu.RLock()
		for _, t := range tracker.slots {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		tracker.mu.RUnlock()

		if !hasRecent {
			delete(trl.trackers, id)
		}
	}
}
