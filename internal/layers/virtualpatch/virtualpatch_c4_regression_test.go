package virtualpatch

import (
	"regexp"
	"strings"
	"testing"
)

// TestVirtualPatch_C4_Regression verifies the C4 fix:
// regexMatchWithTimeout used to be `return re.MatchString(s)` — no
// timeout, no semaphore, no fail-closed, no per-request budget. An
// attacker could flood the virtualpatch layer with requests containing
// pathological inputs and exhaust CPU.
//
// The fixed path routes through regexsafe.Match, which provides:
//   - process-wide counting semaphore (cap 500)
//   - per-regex 500ms ceiling (clamped to remaining per-request budget)
//   - per-request 2s total budget
//   - fail-closed semantics (returns true on saturation so virtualpatch
//     patches are treated as matching rather than silently bypassed)
func TestVirtualPatch_C4_Regression(t *testing.T) {
	re := regexp.MustCompile("test[0-9]+")

	// Normal fast match returns true. Pass nil deadline — these tests
	// bypass the layer's Process path, so the per-request deadline is
	// not the concern here; the semaphore cap is.
	if !regexMatchWithTimeout(re, "test123", nil) {
		t.Fatal("expected match for 'test123'")
	}

	// Non-matching input returns false.
	if regexMatchWithTimeout(re, "no-match", nil) {
		t.Fatal("expected no match for 'no-match'")
	}

	// Empty input returns false.
	if regexMatchWithTimeout(re, "", nil) {
		t.Fatal("expected no match for empty input")
	}

	// The shared budget must bound concurrency: a flood of concurrent
	// slow matches must not spawn unbounded goroutines and must
	// return (fail-closed to true under saturation).
	t.Run("concurrent flood is bounded", func(t *testing.T) {
		const N = 1000
		done := make(chan bool, N)
		for i := 0; i < N; i++ {
			go func() {
				done <- regexMatchWithTimeout(re, strings.Repeat("test", 25), nil)
			}()
		}
		// Collect results; the test is that the call returns rather
		// than hanging.
		for i := 0; i < N; i++ {
			<-done
		}
	})
}