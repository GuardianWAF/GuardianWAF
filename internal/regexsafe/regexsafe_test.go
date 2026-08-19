package regexsafe

import (
	"regexp"
	"testing"
	"time"
)

// TestDeadline_ExhaustedAndRemaining locks down the Deadline contract
// that CRS (FindSubmatch, fail-open) and VirtualPatch (Match,
// fail-closed) both depend on. A future refactor that changes
// Remaining() / Exhausted() / SetTestDeadline semantics would silently
// re-introduce the per-request-budget-unreachable bug.
func TestDeadline_ExhaustedAndRemaining(t *testing.T) {
	// Fresh deadline: not exhausted, Remaining() close to PerRequest.
	fresh := NewDeadline()
	if fresh.Exhausted() {
		t.Fatal("fresh deadline must not be exhausted")
	}
	if rem := fresh.Remaining(); rem <= 0 || rem > PerRequest {
		t.Fatalf("fresh deadline Remaining() = %v, want (0, %v]", rem, PerRequest)
	}

	// SetTestDeadline(0): exhausted, Remaining() == 0.
	sat := &Deadline{}
	sat.SetTestDeadline(0)
	if !sat.Exhausted() {
		t.Fatal("deadline with 0 remaining must be exhausted")
	}
	if rem := sat.Remaining(); rem != 0 {
		t.Fatalf("saturated deadline Remaining() = %v, want 0", rem)
	}

	// Negative duration: clamped to 0, exhausted.
	neg := &Deadline{}
	neg.SetTestDeadline(-1 * time.Second)
	if !neg.Exhausted() {
		t.Fatal("deadline with negative remaining must be exhausted")
	}
	if rem := neg.Remaining(); rem != 0 {
		t.Fatalf("negative-remaining deadline Remaining() = %v, want 0", rem)
	}
}

// TestDeadline_NilIsNonBudget: a nil deadline is the documented
// "no budget tracking" mode. Both Exhausted and Remaining must
// behave safely (Remaining returns PerRegex so callers don't
// think they have zero budget).
func TestDeadline_NilIsNonBudget(t *testing.T) {
	var d *Deadline
	if d.Exhausted() {
		t.Fatal("nil deadline must not report exhausted")
	}
	if rem := d.Remaining(); rem != PerRegex {
		t.Fatalf("nil deadline Remaining() = %v, want %v", rem, PerRegex)
	}
}

// TestMatch_FailClosedOnExhaustedDeadline locks the VirtualPatch
// contract: Match returns true (rule fires) when the per-request
// budget is exhausted, so CVE-style patches are never silently
// bypassed. A regression that flipped this to false would re-open
// the silent-bypass hole.
func TestMatch_FailClosedOnExhaustedDeadline(t *testing.T) {
	re := regexp.MustCompile("never-matches-this")
	d := &Deadline{}
	d.SetTestDeadline(0)

	// Pattern does not match the input. Under a saturated deadline
	// the call must return true (fail-closed).
	if !Match(re, "no-match-input", d) {
		t.Fatal("Match must return true (fail-closed) when deadline is exhausted, even for a non-matching pattern")
	}
}

// TestFindSubmatch_FailOpenOnExhaustedDeadline locks the CRS
// contract: FindSubmatch returns nil (rule did not fire) when the
// per-request budget is exhausted, because CRS SecRules are explicit
// allow/deny predicates. A regression that flipped this to a
// non-nil submatch would silently start firing rules on inputs
// that were not actually matched.
func TestFindSubmatch_FailOpenOnExhaustedDeadline(t *testing.T) {
	re := regexp.MustCompile("never-matches-this")
	d := &Deadline{}
	d.SetTestDeadline(0)

	// Pattern does not match the input. Under a saturated deadline
	// the call must return nil (fail-open: rule did not fire).
	if got := FindSubmatch(re, "no-match-input", d); got != nil {
		t.Fatalf("FindSubmatch must return nil (fail-open) when deadline is exhausted, got %v", got)
	}
}

// TestMatch_NilDeadlineNormalBehavior: with a nil deadline (the
// "no budget tracking" mode) Match must follow the underlying
// regex's verdict, not the fail-closed default.
func TestMatch_NilDeadlineNormalBehavior(t *testing.T) {
	re := regexp.MustCompile("hello")
	if !Match(re, "hello world", nil) {
		t.Fatal("Match must return true for a real match under nil deadline")
	}
	if Match(re, "goodbye", nil) {
		t.Fatal("Match must return false for a real non-match under nil deadline")
	}
}

// TestFindSubmatch_NilDeadlineNormalBehavior: same contract for
// the fail-open sibling.
func TestFindSubmatch_NilDeadlineNormalBehavior(t *testing.T) {
	re := regexp.MustCompile(`\d+`)
	if got := FindSubmatch(re, "abc 123 xyz", nil); got == nil || got[0] != "123" {
		t.Fatalf("FindSubmatch must return submatches under nil deadline, got %v", got)
	}
	if got := FindSubmatch(re, "no digits", nil); got != nil {
		t.Fatalf("FindSubmatch must return nil for a real non-match under nil deadline, got %v", got)
	}
}

// TestActiveGoroutinesIsObservable: the diagnostics counter must
// not grow unboundedly across calls. A regression that dropped the
// counter (or made it stick) would lose the operational signal.
// We sample before and after a batch of matches; the count should
// return to its prior value once all matches complete.
func TestActiveGoroutinesIsObservable(t *testing.T) {
	re := regexp.MustCompile("x")
	before := ActiveGoroutines()

	for i := 0; i < 10; i++ {
		Match(re, "xxx", nil)
	}

	// Give any in-flight goroutines a moment to release. The
	// per-regex ceiling is 500ms; in practice the matches return
	// in microseconds, so a small sleep is plenty.
	time.Sleep(10 * time.Millisecond)
	after := ActiveGoroutines()
	if after > before {
		t.Fatalf("ActiveGoroutines() did not return to baseline: before=%d after=%d", before, after)
	}
}

// Note: a direct test of the process-wide semaphore cap (MaxConcurrent)
// is intentionally omitted. The cap is enforced inside Match via
// acquireSem, which releases the slot the instant Match returns.
// A test that holds the cap from inside Go would have to keep
// MaxConcurrent goroutines running Match forever, which is a
// deadlock trap. The cap is exercised indirectly by the
// TestVirtualPatch_C4_Regression / TestCRS_C3_Regression
// "concurrent flood is bounded" sub-tests, which observe that
// the flood returns rather than hanging. A future test that
// wants to lock the cap deterministically should do it via a
// private test-only seam in the regexsafe package, not by
// hanging goroutines from outside.
