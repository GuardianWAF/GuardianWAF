package proxy

import (
	"testing"
	"time"
)

// Regression tests for the half-open admission contract of CircuitBreaker:
// after the reset timeout elapses, exactly ONE probe request may pass while
// the circuit is half-open. The Open→HalfOpen transition used to arm
// halfOpenProbe AND admit the transitioning caller directly, so the next
// Allow() consumed the freshly-armed probe and slipped in as a second
// concurrent request to an upstream that just failed threshold times.

func TestCircuitBreakerHalfOpenAdmitsSingleProbe(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 2, ResetTimeout: 5 * time.Millisecond})

	// Open the circuit with consecutive failures.
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("state = %v after %d failures, want open", cb.State(), cb.Failures())
	}
	if cb.Allow() {
		t.Fatal("FAIL: open circuit admitted a request before reset timeout")
	}

	// Let the reset timeout elapse.
	time.Sleep(15 * time.Millisecond)

	first := cb.Allow()  // transitions Open→HalfOpen; this caller is the probe
	second := cb.Allow() // a probe is already in flight — must be rejected
	third := cb.Allow()  // still rejected

	if !first {
		t.Fatal("FAIL: no probe admitted after reset timeout")
	}
	if second {
		t.Fatal("FAIL: second Allow() admitted in half-open — transition armed a probe the next caller consumed, admitting two probes")
	}
	if third {
		t.Fatal("FAIL: third Allow() admitted in half-open")
	}

	// A failed probe must reopen the circuit immediately and reject traffic.
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("state = %v after failed probe, want open", cb.State())
	}
	if cb.Allow() {
		t.Fatal("FAIL: reopened circuit admitted a request before reset timeout")
	}

	// After another reset timeout, exactly one new probe is admitted.
	time.Sleep(15 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("FAIL: no probe admitted after reopen + reset timeout")
	}
	if cb.Allow() {
		t.Fatal("FAIL: second probe admitted after reopen")
	}

	// A successful probe closes the circuit and passes traffic again.
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Fatalf("state = %v after successful probe, want closed", cb.State())
	}
	if !cb.Allow() {
		t.Fatal("FAIL: closed circuit rejected a request after successful probe")
	}
}

// Boundary: the Open→HalfOpen transition must still fire when the reset
// timeout has elapsed (the fix must not reject everything forever).
func TestCircuitBreakerHalfOpenTransitionStillFiresAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 1, ResetTimeout: 5 * time.Millisecond})
	cb.RecordFailure()

	// Timeout not yet elapsed: reject.
	if cb.Allow() {
		t.Fatal("FAIL: open circuit admitted before reset timeout")
	}

	time.Sleep(15 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("FAIL: transition to half-open did not admit the probe after reset timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("state = %v while probe in flight, want half-open", cb.State())
	}
}
