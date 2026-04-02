package botdetect

import (
	"math"
	"sync"
	"time"
)

// BehaviorConfig holds thresholds for behavioral analysis.
type BehaviorConfig struct {
	Window             time.Duration // Sliding window duration
	RPSThreshold       int           // Requests per second threshold
	UniquePathsPerMin  int           // Unique paths per minute threshold
	ErrorRateThreshold int           // Error rate percentage threshold
	TimingStdDevMs     int           // Timing standard deviation threshold (milliseconds)
}

// DefaultBehaviorConfig returns a default behavioral analysis configuration.
func DefaultBehaviorConfig() BehaviorConfig {
	return BehaviorConfig{
		Window:             60 * time.Second,
		RPSThreshold:       10,
		UniquePathsPerMin:  50,
		ErrorRateThreshold: 30,
		TimingStdDevMs:     10,
	}
}

// bucket holds per-second aggregated metrics.
type bucket struct {
	requests  int
	errors    int
	paths     map[string]struct{}
	timings   []time.Duration
	timestamp time.Time
}

// BehaviorTracker tracks per-IP behavioral metrics in a sliding window.
type BehaviorTracker struct {
	mu       sync.Mutex
	window   time.Duration
	buckets  []bucket // ring buffer with 1-second granularity
	size     int      // ring buffer capacity
	current  int      // current bucket index
	lastTick time.Time
}

// newBehaviorTracker creates a new tracker with the given window duration.
func newBehaviorTracker(window time.Duration) *BehaviorTracker {
	size := max(int(window.Seconds()), 1)
	buckets := make([]bucket, size)
	now := time.Now()
	for i := range buckets {
		buckets[i].paths = make(map[string]struct{})
		buckets[i].timestamp = now
	}
	return &BehaviorTracker{
		window:   window,
		buckets:  buckets,
		size:     size,
		current:  0,
		lastTick: now,
	}
}

// advance moves the ring buffer forward to the current time, clearing expired buckets.
func (bt *BehaviorTracker) advance(now time.Time) {
	elapsed := now.Sub(bt.lastTick)
	ticks := int(elapsed.Seconds())
	if ticks <= 0 {
		return
	}
	if ticks > bt.size {
		ticks = bt.size
	}
	for range ticks {
		bt.current = (bt.current + 1) % bt.size
		bt.buckets[bt.current].requests = 0
		bt.buckets[bt.current].errors = 0
		bt.buckets[bt.current].paths = make(map[string]struct{})
		bt.buckets[bt.current].timings = bt.buckets[bt.current].timings[:0]
		bt.buckets[bt.current].timestamp = now
	}
	bt.lastTick = now
}

// record adds a request to the current bucket.
func (bt *BehaviorTracker) record(path string, isError bool, latency time.Duration) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()
	bt.advance(now)

	b := &bt.buckets[bt.current]
	b.requests++
	if isError {
		b.errors++
	}
	b.paths[path] = struct{}{}
	b.timings = append(b.timings, latency)
}

// analyze computes behavioral metrics over the full window.
func (bt *BehaviorTracker) analyze(cfg BehaviorConfig) (score int, findings []string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Now()
	bt.advance(now)

	var totalRequests int
	var totalErrors int
	uniquePaths := make(map[string]struct{})
	var allTimings []time.Duration

	for i := 0; i < bt.size; i++ {
		b := &bt.buckets[i]
		totalRequests += b.requests
		totalErrors += b.errors
		for p := range b.paths {
			uniquePaths[p] = struct{}{}
		}
		allTimings = append(allTimings, b.timings...)
	}

	// RPS check: total requests / window seconds
	windowSecs := bt.window.Seconds()
	if windowSecs < 1 {
		windowSecs = 1
	}
	rps := float64(totalRequests) / windowSecs
	if cfg.RPSThreshold > 0 && rps > float64(cfg.RPSThreshold) {
		score += 50
		findings = append(findings, "high request rate detected")
	}

	// Unique paths per minute check
	pathsPerMin := float64(len(uniquePaths)) / (windowSecs / 60.0)
	if cfg.UniquePathsPerMin > 0 && pathsPerMin > float64(cfg.UniquePathsPerMin) {
		score += 60
		findings = append(findings, "excessive path enumeration detected")
	}

	// Error rate check
	if totalRequests > 0 && cfg.ErrorRateThreshold > 0 {
		errorRate := (float64(totalErrors) / float64(totalRequests)) * 100
		if errorRate > float64(cfg.ErrorRateThreshold) {
			score += 45
			findings = append(findings, "high error rate detected")
		}
	}

	// Timing standard deviation check (machine-like behavior)
	if len(allTimings) >= 3 && cfg.TimingStdDevMs > 0 {
		stdDev := timingStdDev(allTimings)
		if stdDev < float64(cfg.TimingStdDevMs) {
			score += 55
			findings = append(findings, "machine-like request timing detected")
		}
	}

	return score, findings
}

// timingStdDev computes the standard deviation of request timings in milliseconds.
func timingStdDev(timings []time.Duration) float64 {
	if len(timings) == 0 {
		return 0
	}

	var sum float64
	for _, t := range timings {
		sum += float64(t.Milliseconds())
	}
	mean := sum / float64(len(timings))

	var variance float64
	for _, t := range timings {
		diff := float64(t.Milliseconds()) - mean
		variance += diff * diff
	}
	variance /= float64(len(timings))

	return math.Sqrt(variance)
}

// BehaviorManager manages per-IP behavior trackers.
type BehaviorManager struct {
	mu       sync.RWMutex
	trackers map[string]*BehaviorTracker
	config   BehaviorConfig
}

// NewBehaviorManager creates a new BehaviorManager with the given configuration.
func NewBehaviorManager(cfg BehaviorConfig) *BehaviorManager {
	return &BehaviorManager{
		trackers: make(map[string]*BehaviorTracker),
		config:   cfg,
	}
}

// getOrCreate retrieves or creates a tracker for the given IP.
func (bm *BehaviorManager) getOrCreate(ip string) *BehaviorTracker {
	bm.mu.RLock()
	tracker, ok := bm.trackers[ip]
	bm.mu.RUnlock()
	if ok {
		return tracker
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()
	// Double-check after acquiring write lock.
	if tracker, ok = bm.trackers[ip]; ok {
		return tracker
	}
	tracker = newBehaviorTracker(bm.config.Window)
	bm.trackers[ip] = tracker
	return tracker
}

// Record records a request for the given IP.
func (bm *BehaviorManager) Record(ip, path string, isError bool, latency time.Duration) {
	tracker := bm.getOrCreate(ip)
	tracker.record(path, isError, latency)
}

// Analyze returns a threat score and findings for the given IP based on behavioral patterns.
func (bm *BehaviorManager) Analyze(ip string) (score int, findings []string) {
	bm.mu.RLock()
	tracker, ok := bm.trackers[ip]
	bm.mu.RUnlock()
	if !ok {
		return 0, nil
	}
	return tracker.analyze(bm.config)
}

// Cleanup removes all trackers that have had no recent activity.
func (bm *BehaviorManager) Cleanup() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	for ip, tracker := range bm.trackers {
		tracker.mu.Lock()
		if now.Sub(tracker.lastTick) > tracker.window*2 {
			delete(bm.trackers, ip)
		}
		tracker.mu.Unlock()
	}
}

// TrackerCount returns the number of currently tracked IPs.
func (bm *BehaviorManager) TrackerCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.trackers)
}
