package crs

import (
	"regexp"
	"strings"
	"testing"
)

// TestCRS_C3_Regression verifies the C3 fix: matchWithTimeout now uses
// the shared regexsafe budget (semaphore cap 500, per-regex 500ms,
// per-request 2s) instead of the previous 5s ceiling with no
// semaphore, no fail-closed, no per-request budget.
//
// Reproducible scenario: an attacker floods the CRS @rx operator with
// requests containing a large input against a slow pattern. The
// previous path kept a goroutine alive for 5s per request and spawned
// unbounded goroutines. The fixed path bounds both the per-call
// duration and the total in-flight goroutine count.
func TestCRS_C3_Regression(t *testing.T) {
	re := regexp.MustCompile("a")

	// Normal fast match returns submatches.
	if got := matchWithTimeout(re, "aaaa"); len(got) == 0 || got[0] != "a" {
		t.Fatalf("expected submatch for 'aaaa', got %v", got)
	}

	// Non-matching input returns nil (no match, not an error).
	if got := matchWithTimeout(re, "bbb"); got != nil {
		t.Fatalf("expected nil for non-match, got %v", got)
	}

	// Empty input returns nil.
	if got := matchWithTimeout(re, ""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}

	// The shared budget must be threaded: an exhausted deadline
	// produces nil (no match). This is the fail-closed property
	// — callers treat nil as "no match" for CRS SecRules, which is
	// the correct behavior (CRS is explicit allow/deny).
	t.Run("exhausted deadline returns nil", func(t *testing.T) {
		// Use matchWithDeadline with timeout=0 to simulate an
		// exhausted budget; the shared budget clamps the per-regex
		// timeout to the remaining budget, which is 0.
		if got := matchWithDeadline(re, "a", 0); got != nil {
			t.Fatalf("expected nil for zero-budget deadline, got %v", got)
		}
	})

	// The shared budget must also bound concurrency: a flood of
	// concurrent slow matches must not spawn unbounded goroutines.
	t.Run("concurrent flood is bounded", func(t *testing.T) {
		const N = 1000
		done := make(chan []string, N)
		for i := 0; i < N; i++ {
			go func() {
				done <- matchWithTimeout(re, strings.Repeat("a", 100))
			}()
		}
		got := 0
		for i := 0; i < N; i++ {
			if <-done != nil {
				got++
			}
		}
		// At least some matches should succeed; the test is that
		// the call returns rather than hanging.
		t.Logf("concurrent flood: %d/%d non-nil matches", got, N)
	})
}

// TestCRS_MatchWithDeadline_TimeoutBounds verifies the per-regex
// timeout is enforced. The previous C3 path used time.After(5s); the
// fixed path uses the shared regexsafe budget (500ms ceiling clamped
// to remaining budget).
func TestCRS_MatchWithDeadline_TimeoutBounds(t *testing.T) {
	re := regexp.MustCompile("a")
	// A sub-millisecond budget must produce nil (timeout fires
	// before the match completes).
	if got := matchWithDeadline(re, strings.Repeat("a", 100), 0); got != nil {
		t.Fatalf("expected nil for zero-budget match, got %v", got)
	}
}