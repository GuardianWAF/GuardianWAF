package proxy

import (
	"sync/atomic"
	"time"
)

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
	state        atomic.Int32  // CircuitState
	failures     atomic.Int32  // consecutive failure count
	threshold    int32         // failures before opening
	resetTimeout time.Duration // how long to stay open before half-open
	lastFailure  atomic.Value  // stores time.Time of last failure
	halfOpenProbe atomic.Bool  // true while a probe request is in-flight
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
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	cb := &CircuitBreaker{
		threshold:    int32(cfg.Threshold),
		resetTimeout: cfg.ResetTimeout,
	}
	cb.lastFailure.Store(time.Time{})
	return cb
}

// Allow checks if the request should be allowed through.
// Returns true if allowed, false if circuit is open.
func (cb *CircuitBreaker) Allow() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has elapsed
		last, _ := cb.lastFailure.Load().(time.Time)
		if time.Since(last) >= cb.resetTimeout {
			// Transition to half-open: allow one probe
			if cb.state.CompareAndSwap(int32(CircuitOpen), int32(CircuitHalfOpen)) {
				cb.halfOpenProbe.Store(true)
				cb.failures.Store(0) // Reset so probe failure correctly re-opens
				return true
			}
			// Another goroutine already transitioned; reject
			return false
		}
		return false
	case CircuitHalfOpen:
		// Only one probe allowed — subsequent requests are rejected
		if cb.halfOpenProbe.CompareAndSwap(true, false) {
			return true
		}
		return false
	}
	return false
}

// RecordSuccess records a successful request. Resets failure count and
// only transitions from HalfOpen to Closed to prevent stale successes from
// prematurely closing the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failures.Store(0)
	cb.state.CompareAndSwap(int32(CircuitHalfOpen), int32(CircuitClosed))
}

// RecordFailure records a failed request. May open the circuit if threshold is reached.
func (cb *CircuitBreaker) RecordFailure() {
	failures := cb.failures.Add(1)
	cb.lastFailure.Store(time.Now())

	if failures >= cb.threshold {
		cb.state.Store(int32(CircuitOpen))
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
	cb.failures.Store(0)
	cb.state.Store(int32(CircuitClosed))
}
