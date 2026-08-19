package crs

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/regexsafe"
)

// TestCRS_Process_ExhaustedDeadline_Regression verifies that the
// per-request regexsafe.Deadline is actually enforced on the
// production Process path (not just the helper functions).
//
// Background: the C3 fix replaced the previous 5s ceiling with the
// shared regexsafe budget (2s per-request, 500ms per-regex, 500-slot
// semaphore). But the wiring left every Process call passing a
// nil deadline to OperatorEvaluator, so the per-request budget was
// unreachable from the live request path — only the semaphore cap
// ran in production.
//
// This test drives the actual Process method with a deadline whose
// Remaining() is 0 and asserts the rule does not fire. The
// baseline sub-test drives the same rule with a fresh deadline
// and asserts the rule DOES fire, proving the suppression in the
// first sub-test is caused by the saturated deadline and not by
// the rule itself.
func TestCRS_Process_ExhaustedDeadline_Regression(t *testing.T) {
	// Single @rx rule that matches the literal "GET" against the
	// REQUEST_METHOD variable. CRITICAL severity + Action: "deny"
	// means Process must return ActionBlock when the rule fires.
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999deadline",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@rx", Argument: "^GET$"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "denied by deadline-regression rule"},
		},
	}
	layer.buildRuleMaps()

	makeCtx := func() *engine.RequestContext {
		return &engine.RequestContext{
			Method:  "GET",
			Path:    "/test",
			Headers: map[string][]string{},
		}
	}

	// Baseline: a fresh per-request deadline must let the rule
	// fire. If this sub-test fails the saturated sub-test is
	// meaningless (the rule never fires regardless of budget).
	t.Run("baseline fresh deadline lets rule fire", func(t *testing.T) {
		layer.newDeadline = nil // production default: regexsafe.NewDeadline
		result := layer.Process(makeCtx())
		if result.Action != engine.ActionBlock {
			t.Fatalf("expected block with fresh deadline, got %v (findings=%d)",
				result.Action, len(result.Findings))
		}
	})

	// Saturated deadline: factory returns a deadline with
	// Remaining() == 0. regexsafe.FindSubmatch sees the budget is
	// exhausted and returns nil, so evaluateRx reports "no match"
	// and the rule does not fire. The request is therefore
	// passed, not blocked — this is the documented CRS
	// "no-match => rule did not fire" behavior.
	t.Run("exhausted deadline suppresses rule", func(t *testing.T) {
		layer.newDeadline = func() *regexsafe.Deadline {
			d := &regexsafe.Deadline{}
			d.SetTestDeadline(0)
			return d
		}
		result := layer.Process(makeCtx())
		if result.Action == engine.ActionBlock {
			t.Fatalf("expected pass with exhausted deadline, got %v (findings=%d, score=%d)",
				result.Action, len(result.Findings), result.Score)
		}
		if len(result.Findings) != 0 {
			t.Fatalf("expected no findings with exhausted deadline, got %d: %+v",
				len(result.Findings), result.Findings)
		}
	})
}
