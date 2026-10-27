package proxy

import (
	"sync"
	"sync/atomic"
	"time"
)

const maxCircuitThreshold = int(1<<31 - 1)

// CircuitState represents the state of a circuit breaker.
type CircuitState int32

const (
	CircuitClosed   CircuitState = iota // normal operation
	CircuitOpen                         // failures exceeded threshold, reject fast
	CircuitHalfOpen                     // allowing one probe request
)

// String returns the state name.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern.
// It tracks consecutive failures and opens the circuit when a threshold is reached.
// After a reset timeout, it transitions to half-open and allows one probe request.
type CircuitBreaker struct {
	mu            sync.Mutex    // serializes admission and result transitions
	generation    uint64        // protected by mu; identifies the admitted circuit phase
	state         atomic.Int32  // CircuitState
	failures      atomic.Int32  // consecutive failure count
	threshold     int32         // failures before opening
	resetTimeout  time.Duration // how long to stay open before half-open
	lastFailure   atomic.Value  // stores time.Time of last failure
	halfOpenProbe atomic.Bool   // HalfOpen admission token; production never arms it — the Open→HalfOpen transitioner is the probe
}

// CircuitConfig configures the circuit breaker.
type CircuitConfig struct {
	Threshold    int           // consecutive failures before opening (default: 5)
	ResetTimeout time.Duration // time before half-open probe (default: 30s)
}

// NewCircuitBreaker creates a circuit breaker with the given config.
func NewCircuitBreaker(cfg CircuitConfig) *CircuitBreaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	} else if cfg.Threshold > maxCircuitThreshold {
		cfg.Threshold = maxCircuitThreshold
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	cb := &CircuitBreaker{
		// #nosec G115 -- cfg.Threshold is clamped to the int32 range above.
		threshold:    int32(cfg.Threshold),
		resetTimeout: cfg.ResetTimeout,
	}
	cb.lastFailure.Store(time.Time{})
	return cb
}

// canAttempt lets selection include a timed-out circuit without consuming its
// single half-open probe. Allow reserves that probe when the request is sent.
func (cb *CircuitBreaker) canAttempt() bool {
	if CircuitState(cb.state.Load()) != CircuitOpen {
		return true
	}
	last, _ := cb.lastFailure.Load().(time.Time)
	return time.Since(last) >= cb.resetTimeout
}

// Allow checks if the request should be allowed through.
// Returns true if allowed, false if circuit is open.
func (cb *CircuitBreaker) Allow() bool {
	_, allowed := cb.allow()
	return allowed
}

// allow captures the phase that owns this request's eventual result.
func (cb *CircuitBreaker) allow() (uint64, bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return cb.generation, true
	case CircuitOpen:
		// Check if reset timeout has elapsed
		last, _ := cb.lastFailure.Load().(time.Time)
		if time.Since(last) >= cb.resetTimeout {
			// Transition to half-open. The transitioning caller is the single
			// half-open probe: halfOpenProbe stays disarmed, so no concurrent
			// Allow() can win the HalfOpen probe CAS and slip in as a second
			// probe against an upstream that just failed threshold times.
			if cb.state.CompareAndSwap(int32(CircuitOpen), int32(CircuitHalfOpen)) {
				cb.generation++
				cb.failures.Store(0) // Reset so probe failure correctly re-opens
				return cb.generation, true
			}
			// Another goroutine already transitioned; reject
			return cb.generation, false
		}
		return cb.generation, false
	case CircuitHalfOpen:
		// Only one probe allowed — subsequent requests are rejected
		if cb.halfOpenProbe.CompareAndSwap(true, false) {
			return cb.generation, true
		}
		return cb.generation, false
	}
	return cb.generation, false
}

// RecordSuccess records a successful request. Resets failure count and
// only transitions from HalfOpen to Closed to prevent stale successes from
// prematurely closing the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.recordSuccessLocked()
}

func (cb *CircuitBreaker) recordSuccessLocked() {
	cb.failures.Store(0)
	if cb.state.CompareAndSwap(int32(CircuitHalfOpen), int32(CircuitClosed)) {
		cb.generation++
	}
}

// RecordFailure records a failed request. May open the circuit if threshold is reached.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.recordFailureLocked()
}

func (cb *CircuitBreaker) recordFailureLocked() {
	cb.lastFailure.Store(time.Now())

	// A failed probe while half-open means the target is still unhealthy. Reopen
	// immediately (rather than requiring another `threshold` failures, which the
	// half-open state can never accumulate because it admits only one probe) so
	// the reset-timeout half-open cycle can retry later instead of wedging in
	// half-open and rejecting every request forever.
	if CircuitState(cb.state.Load()) == CircuitHalfOpen {
		cb.failures.Store(cb.threshold)
		cb.state.Store(int32(CircuitOpen))
		cb.generation++
		return
	}

	failures := cb.failures.Add(1)
	if failures >= cb.threshold && CircuitState(cb.state.Load()) != CircuitOpen {
		cb.state.Store(int32(CircuitOpen))
		cb.generation++
	}
}

// recordResult ignores requests admitted before a later open/reset/recovery.
func (cb *CircuitBreaker) recordResult(generation uint64, success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if generation != cb.generation {
		return
	}
	if success {
		cb.recordSuccessLocked()
	} else {
		cb.recordFailureLocked()
	}
}

// cancelAttempt releases a canceled probe without counting a backend failure
// or extending its cooldown. The next request can probe the expired circuit.
func (cb *CircuitBreaker) cancelAttempt(generation uint64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if generation == cb.generation && CircuitState(cb.state.Load()) == CircuitHalfOpen {
		cb.state.Store(int32(CircuitOpen))
		cb.generation++
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Failures returns the current consecutive failure count.
func (cb *CircuitBreaker) Failures() int {
	return int(cb.failures.Load())
}

// Reset forces the circuit breaker back to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.generation++
	cb.failures.Store(0)
	cb.state.Store(int32(CircuitClosed))
}
