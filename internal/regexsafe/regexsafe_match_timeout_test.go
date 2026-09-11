package regexsafe

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// Regression (bug-hunt round 29): Match's per-regex ceiling timeout branch
// returned false (fail-open) — the ONLY abandonment path that did. Budget
// exhaustion, semaphore timeout, and zero remaining budget all fail closed,
// and the documented contract is that a fail-closed rule never silently
// vanishes. Returning false on per-regex timeout let an input that keeps one
// regex past its ceiling (oversized body, capture-heavy pattern) bypass
// virtual patches and other fail-closed security rules.
//
// The fix returns true on the ceiling timeout, matching every sibling branch.
// FindSubmatch intentionally stays fail-open (CRS match-then-act predicates)
// and is pinned here to keep the two contracts distinct.
//
// Determinism: SetTestDeadline clamps the per-regex ceiling to 3ms; a 32MB
// scan needs ≥10ms on any hardware (more under -race), so the timeout branch
// fires on every run with an order-of-magnitude margin.

func TestMatch_FailClosedOnPerRegexTimeout(t *testing.T) {
	d := NewDeadline()
	d.SetTestDeadline(3 * time.Millisecond) // ceiling clamps to the remaining budget
	re := regexp.MustCompile("a")
	big := strings.Repeat("a", 32<<20)

	if !Match(re, big, d) {
		t.Fatal("FAIL: per-regex ceiling timeout returned false (fail-open) — Match must fail closed on every abandonment path")
	}
}

func TestFindSubmatch_StaysFailOpenOnPerRegexTimeout(t *testing.T) {
	d := NewDeadline()
	d.SetTestDeadline(3 * time.Millisecond)
	re := regexp.MustCompile("a")
	big := strings.Repeat("a", 32<<20)

	if got := FindSubmatch(re, big, d); got != nil {
		t.Fatalf("FindSubmatch must stay fail-open (nil) on per-regex timeout, got %v", got)
	}
}
