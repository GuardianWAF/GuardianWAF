package proxy

import (
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed is the normal operating state; requests flow through.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the circuit is tripped; requests are rejected.
	CircuitOpen
	// CircuitHalfOpen allows a limited number of requests to test recovery.
	CircuitHalfOpen
)

// String returns a human-readable representation of the circuit state.
func (cs CircuitState) String() string {
	switch cs {
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

// CircuitBreaker manages circuit states per backend host.
type CircuitBreaker struct {
	mu               sync.RWMutex
	circuits         map[string]*circuit
	failureThreshold int
	successThreshold int
	timeout          time.Duration
}

type circuit struct {
	state       CircuitState
	failures    int
	successes   int
	lastFailure time.Time
}

// NewCircuitBreaker creates a new circuit breaker.
//   - failureThreshold: number of failures before opening the circuit
//   - successThreshold: number of successes in half-open before closing
//   - timeout: duration to wait in open state before transitioning to half-open
func NewCircuitBreaker(failureThreshold, successThreshold int, timeout time.Duration) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if successThreshold <= 0 {
		successThreshold = 2
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &CircuitBreaker{
		circuits:         make(map[string]*circuit),
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		timeout:          timeout,
	}
}

// getOrCreate returns the circuit for the host, creating one if it doesn't exist.
func (cb *CircuitBreaker) getOrCreate(host string) *circuit {
	c, ok := cb.circuits[host]
	if !ok {
		c = &circuit{state: CircuitClosed}
		cb.circuits[host] = c
	}
	return c
}

// Allow returns true if a request to the given host should be permitted.
func (cb *CircuitBreaker) Allow(host string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	c := cb.getOrCreate(host)

	switch c.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if the timeout has elapsed; if so, transition to half-open
		if time.Since(c.lastFailure) > cb.timeout {
			c.state = CircuitHalfOpen
			c.successes = 0
			c.failures = 0
			return true
		}
		return false
	case CircuitHalfOpen:
		// Allow requests in half-open state to test recovery
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful request to the given host.
func (cb *CircuitBreaker) RecordSuccess(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	c := cb.getOrCreate(host)

	switch c.state {
	case CircuitHalfOpen:
		c.successes++
		if c.successes >= cb.successThreshold {
			// Recovery confirmed; close the circuit
			c.state = CircuitClosed
			c.failures = 0
			c.successes = 0
		}
	case CircuitClosed:
		// Reset failure count on success in closed state
		c.failures = 0
	}
}

// RecordFailure records a failed request to the given host.
func (cb *CircuitBreaker) RecordFailure(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	c := cb.getOrCreate(host)
	c.lastFailure = time.Now()

	switch c.state {
	case CircuitClosed:
		c.failures++
		if c.failures >= cb.failureThreshold {
			c.state = CircuitOpen
		}
	case CircuitHalfOpen:
		// Any failure in half-open immediately trips back to open
		c.state = CircuitOpen
		c.failures = cb.failureThreshold // keep it at threshold
		c.successes = 0
	}
}

// State returns the current circuit state for a host.
func (cb *CircuitBreaker) State(host string) CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	c, ok := cb.circuits[host]
	if !ok {
		return CircuitClosed
	}
	return c.state
}
