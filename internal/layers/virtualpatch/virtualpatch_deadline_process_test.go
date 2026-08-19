package virtualpatch

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/regexsafe"
)

// TestVirtualPatch_Process_ExhaustedDeadline_Regression verifies that
// the per-request regexsafe.Deadline is actually enforced on the
// production Process path (not just the helper functions).
//
// Background: the C4 fix replaced the previous "return re.MatchString(s)"
// path with the shared regexsafe budget (2s per-request, 500ms
// per-regex, 500-slot semaphore). But the wiring left every Process
// call passing a nil deadline to matchRegex, so the per-request
// budget was unreachable from the live request path — only the
// semaphore cap ran in production.
//
// Fail-closed semantics matter here: VirtualPatch's regexMatchWithTimeout
// uses regexsafe.Match (boolean), which the regexsafe package doc
// documents as fail-CLOSED — it returns true on budget/semaphore
// exhaustion. For a per-pattern match this means: if the budget
// is exhausted, the pattern is treated as matching. The test
// therefore asserts the *opposite* of the CRS test:
//
//   - Baseline (fresh deadline, matching path): patch fires.
//   - Baseline (fresh deadline, non-matching path): patch does NOT
//     fire (proves the regex path is reached end-to-end and not
//     unconditionally failing closed under a fresh deadline).
//   - Saturated deadline: the thread-through is proven by the
//     fail-closed semantics itself — the patch MUST fire on a
//     non-matching path (because the deadline is exhausted, the
//     boolean Match returns true, the patch fires). A regression
//     that re-introduced a nil-deadline wiring would make the
//     saturated sub-test PASS on the non-matching path (the
//     previous code did plain re.MatchString which would not match
//     a clean path), failing the test.
func TestVirtualPatch_Process_ExhaustedDeadline_Regression(t *testing.T) {
	// Build a layer with a single regex-mode virtual patch that
	// matches any path containing the literal "exploit".
	// BlockSeverity must include "CRITICAL" — the layer's shouldBlock
	// gates which patches Process actually evaluates, and the
	// inline Config{Enabled:true} leaves BlockSeverity nil otherwise.
	layer := NewLayer(&Config{
		Enabled:       true,
		BlockSeverity: []string{"CRITICAL"},
	})
	layer.database = NewDatabase()
	layer.database.AddPatch(&VirtualPatch{
		ID:       "VP-DEADLINE-TEST",
		CVEID:    "CVE-DEADLINE-TEST",
		Name:     "deadline regression patch",
		Patterns: []PatchPattern{{Type: "path", MatchType: "regex", Pattern: "exploit"}},
		Action:   "block",
		Severity: "CRITICAL",
		Enabled:  true,
	})

	makeCtx := func(path string) *engine.RequestContext {
		req := httptest.NewRequest("GET", path, nil)
		return &engine.RequestContext{
			Method:  "GET",
			Path:    path,
			Request: req,
			Headers: map[string][]string{},
		}
	}

	// Baseline 1: fresh deadline, matching path — patch must fire.
	// If this fails, the saturated sub-test is meaningless.
	t.Run("baseline fresh deadline lets matching patch fire", func(t *testing.T) {
		layer.newDeadline = nil // production default: regexsafe.NewDeadline
		result := layer.Process(makeCtx("/safe/exploit/path"))
		if result.Action != engine.ActionBlock {
			t.Fatalf("expected block with fresh deadline on exploit path, got %v (findings=%d, score=%d)",
				result.Action, len(result.Findings), result.Score)
		}
		if len(result.Findings) == 0 {
			t.Fatal("expected at least one finding with fresh deadline on exploit path")
		}
	})

	// Baseline 2: fresh deadline, non-matching path — patch must
	// NOT fire. This proves the regex path is reached end-to-end
	// under a fresh deadline and is not unconditionally failing
	// closed. Without this baseline, a broken wiring that always
	// returned true (e.g. unconditionally fail-closed) would
	// appear to "work" in the saturated sub-test.
	t.Run("baseline fresh deadline leaves non-matching path alone", func(t *testing.T) {
		layer.newDeadline = nil
		result := layer.Process(makeCtx("/safe/clean/path"))
		if result.Action != engine.ActionPass {
			t.Fatalf("expected pass with fresh deadline on clean path, got %v (findings=%d, score=%d)",
				result.Action, len(result.Findings), result.Score)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("expected no findings with fresh deadline on clean path, got %d: %+v",
				len(result.Findings), result.Findings)
		}
	})

	// Saturated deadline: fail-closed semantics mean the regex
	// match returns true (the budget is exhausted, the boolean
	// Match is documented as fail-closed), so the patch fires on
	// a non-matching path. This is the correct, documented
	// behavior — and it is the proof that the deadline is being
	// threaded into the production Process path. A regression
	// that re-introduced a nil-deadline wiring would make the
	// regex path use plain re.MatchString, which would NOT match
	// a clean path, and this sub-test would fail.
	t.Run("exhausted deadline fires patch fail-closed on non-matching path", func(t *testing.T) {
		layer.newDeadline = func() *regexsafe.Deadline {
			d := &regexsafe.Deadline{}
			d.SetTestDeadline(0)
			return d
		}
		result := layer.Process(makeCtx("/safe/clean/path"))
		if result.Action != engine.ActionBlock {
			t.Fatalf("expected block with exhausted deadline on clean path (fail-closed), got %v (findings=%d, score=%d)",
				result.Action, len(result.Findings), result.Score)
		}
		if len(result.Findings) == 0 {
			t.Fatal("expected at least one finding with exhausted deadline on clean path (fail-closed)")
		}
	})
}
