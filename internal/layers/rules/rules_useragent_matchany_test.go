package rules

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests (round 87): the rules layer's user_agent field accessor
// returned ua[0] (the first transmitted value), so a UA-keyed deny rule was
// evadable: benign-first + trigger-last passed the rule while a last-wins
// backend (PHP/Python-style parsers) read the trigger value. user_agent
// conditions now match if ANY transmitted value satisfies the op — the same
// match-any treatment as cookie (round 85) and header (round 86) conditions.
// An absent User-Agent resolves against "" exactly as before multi-value
// support (pinned by TestRuleEmptyUserAgent and re-pinned below).

func newUserAgentRuleLayer(action string) *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r87", Name: "ua rule", Enabled: true,
			Conditions: []Condition{{Field: "user_agent", Op: "contains", Value: "sqlmap"}},
			Action:     action, Score: 100,
		}},
	}, nil)
}

func TestRuleUserAgentTriggerLastStillBlocked(t *testing.T) {
	layer := newUserAgentRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64)", "sqlmap/1.7.12#stable"}})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-last User-Agent value not blocked, got %s", result.Action)
	}
}

func TestRuleUserAgentOrderSwapStillBlocked(t *testing.T) {
	layer := newUserAgentRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"User-Agent": {"sqlmap/1.7.12#stable", "Mozilla/5.0 (X11; Linux x86_64)"}})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-first User-Agent value not blocked, got %s", result.Action)
	}
}

func TestRuleUserAgentSingleNonMatchClean(t *testing.T) {
	layer := newUserAgentRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"User-Agent": {"Mozilla/5.0 (X11; Linux x86_64)"}})
	if result := layer.Process(ctx); result.Action == engine.ActionBlock {
		t.Fatal("FAIL: non-matching User-Agent value was blocked")
	}
}

func TestRuleUserAgentAbsentEqualsEmptyFires(t *testing.T) {
	// Absent User-Agent: the condition resolves against "" exactly as before
	// multi-value support (mirrors the pre-existing TestRuleEmptyUserAgent).
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "a87", Name: "missing UA", Enabled: true,
			Conditions: []Condition{{Field: "user_agent", Op: "equals", Value: ""}},
			Action:     "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.Headers = map[string][]string{} // ensure no User-Agent
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Fatalf("FAIL: equals \"\" should fire on an absent User-Agent (empty-value resolution), got %s", result.Action)
	}
}
