// Package regexsafe provides hardened regex matching primitives shared
// across WAF detection layers.
//
// Background: Go's standard regexp package (RE2) is linear-time and
// immune to catastrophic backtracking, but a single large or
// pathological input can still hold the CPU for hundreds of
// milliseconds. Because RE2 has no cancellation API, a goroutine
// running re.FindStringSubmatch cannot be interrupted — the only
// protection is to abandon the wait.
//
// The two failure modes this package prevents:
//
//  1. Unbounded concurrency: a flood of slow regex matches spawns
//     unbounded goroutines, each holding CPU until it finishes
//     naturally. Without a semaphore, an attacker can exhaust
//     scheduler/CPU budget.
//
//  2. Unbounded per-request time: a single request that triggers
//     many regex matches can keep its goroutine alive indefinitely
//     without a per-request budget. An attacker amplifies this by
//     triggering many such requests in parallel.
//
// Design (mirrors internal/layers/rules/rules.go C1+C2 fix):
//
//   - Sem: a counting semaphore (buffered chan) bounds concurrent
//     regex goroutines across the whole process. Callers queue-and-wait
//     up to a deadline; if they time out waiting, Match* returns true
//     (fail closed) so detection is never silently bypassed.
//
//   - Per-regex ceiling: each individual match runs in a goroutine
//     with a hard timeout, clamped to the remaining per-request budget.
//
//   - Per-request budget: callers pass a *Deadline. When the budget
//     is exhausted, regexsafe returns true (fail closed) without
//     spawning a goroutine.
//
// Residual: Go regexp has no cancellation, so timed-out goroutines
// continue to completion (up to PerRegex ceiling). A future migration
// to regexp2 (NFA-based, cancellable) would eliminate this.
package regexsafe

import (
	"regexp"
	"sync/atomic"
	"time"
)

// PerRegex is the maximum time any single regex match may consume.
// Mirrors internal/layers/rules/rules.go's regexMatchTimeout.
const PerRegex = 500 * time.Millisecond

// PerRequest is the total wall-clock budget a single request may
// spend across all regexsafe.Match* calls. Mirrors the rules layer's
// regexTotalBudget.
const PerRequest = 2 * time.Second

// MaxConcurrent bounds the number of in-flight regex goroutines
// across all layers using this package. Mirrors the rules layer's
// maxConcurrentRegex (500).
const MaxConcurrent = 500

// sem is a process-wide counting semaphore for regex goroutines.
// Buffered chan of size MaxConcurrent; send=acquire, recv=release.
var sem = make(chan struct{}, MaxConcurrent)

// afterFunc is overridable for tests; production wires to time.After.
var afterFunc = time.After

// Deadline tracks the remaining per-request regex evaluation budget.
// A nil deadline means "no budget tracking" (tests only).
type Deadline struct {
	deadline time.Time
}

// NewDeadline creates a Deadline for a fresh request.
func NewDeadline() *Deadline {
	return &Deadline{deadline: time.Now().Add(PerRequest)}
}

// SetTestDeadline overrides the remaining budget for tests. Production
// code should use NewDeadline. Calling this on a Deadline already in use
// is a data race; synchronize or use a fresh Deadline.
func (d *Deadline) SetTestDeadline(remaining time.Duration) {
	d.deadline = time.Now().Add(remaining)
}

// Exhausted reports whether the per-request budget is spent.
func (d *Deadline) Exhausted() bool {
	if d == nil {
		return false
	}
	return time.Now().After(d.deadline)
}

// Remaining returns the time left until the deadline, clamped to >= 0.
// Returns PerRegex when d is nil (no limit).
func (d *Deadline) Remaining() time.Duration {
	if d == nil {
		return PerRegex
	}
	r := time.Until(d.deadline)
	if r < 0 {
		return 0
	}
	return r
}

// activeGoroutines tracks in-flight regex goroutines for diagnostics.
// Updated atomically; never blocks matching.
var activeGoroutines atomic.Int64

// ActiveGoroutines returns the current count of in-flight regexsafe
// goroutines. Useful for tests and metrics.
func ActiveGoroutines() int64 { return activeGoroutines.Load() }

// acquireSem attempts to take a semaphore slot, queueing up to wait.
// Returns true if the slot was acquired, false if the wait timed out
// (caller must fail closed).
func acquireSem(d *Deadline) bool {
	semWait := d.Remaining()
	if semWait == 0 {
		return false
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
	}
	select {
	case sem <- struct{}{}:
		return true
	case <-afterFunc(semWait):
		return false
	}
}

// releaseSem returns a slot to the semaphore.
func releaseSem() { <-sem }

// Match is the hardened equivalent of re.MatchString.
// Returns true if the regex matches, false if it does not, or
// true (fail closed) when the per-request budget is exhausted or
// the semaphore could not be acquired in time.
//
// Fail-closed semantics: under saturation or budget exhaustion the
// caller treats the value as matching, so security rules that
// depend on regexMatch do not get silently bypassed.
func Match(re *regexp.Regexp, s string, d *Deadline) bool {
	if d != nil && d.Exhausted() {
		return true
	}
	if !acquireSem(d) {
		return true
	}
	defer releaseSem()

	per := PerRegex
	if rem := d.Remaining(); rem < per {
		per = rem
	}
	if per == 0 {
		return true
	}

	activeGoroutines.Add(1)
	defer activeGoroutines.Add(-1)

	done := make(chan bool, 1)
	go func() { done <- re.MatchString(s) }()
	select {
	case matched := <-done:
		return matched
	case <-afterFunc(per):
		return false
	}
}

// FindSubmatch is the hardened equivalent of re.FindStringSubmatch.
// Returns nil when the regex does not match or when the call is
// abandoned due to budget/semaphore pressure. Callers must treat nil
// as "no match" — this is the safe default for CRS-style rules where
// absence of a match means the request is allowed.
//
// For security layers that need fail-closed semantics, use Match
// (boolean) instead. FindSubmatch is intentionally fail-open because
// CRS SecRules are explicit allow/deny predicates: a missing match
// means the rule did not fire, which is the correct behavior for
// match-then-act chains.
func FindSubmatch(re *regexp.Regexp, s string, d *Deadline) []string {
	if d != nil && d.Exhausted() {
		return nil
	}
	if !acquireSem(d) {
		return nil
	}
	defer releaseSem()

	per := PerRegex
	if rem := d.Remaining(); rem < per {
		per = rem
	}
	if per == 0 {
		return nil
	}

	activeGoroutines.Add(1)
	defer activeGoroutines.Add(-1)

	done := make(chan []string, 1)
	go func() { done <- re.FindStringSubmatch(s) }()
	select {
	case matches := <-done:
		return matches
	case <-afterFunc(per):
		return nil
	}
}