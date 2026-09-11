package rules

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests (round 86): the rules layer's header: field accessor
// returned vals[0] (the first transmitted value), so a deny rule keyed to a
// header value was evadable: safe-first + trigger-last passed the rule while
// a last-wins backend (PHP/Python-style parsers) read the trigger value.
// Header conditions now match if ANY transmitted value satisfies the op —
// the same match-any treatment as cookie conditions (round 85). Header name
// canonicalization (RFC 9110 §5.1) is preserved: a rule author's lowercase
// spelling still matches the canonical transport form. An absent header
// resolves against "" exactly as before multi-value support.

func newHeaderRuleLayer(action string) *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r86", Name: "header role rule", Enabled: true,
			Conditions: []Condition{{Field: "header:X-Role", Op: "equals", Value: "admin"}},
			Action:     action, Score: 100,
		}},
	}, nil)
}

func TestRuleHeaderTriggerLastStillBlocked(t *testing.T) {
	layer := newHeaderRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"X-Role": {"guest", "admin"}})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-last header value not blocked, got %s", result.Action)
	}
}

func TestRuleHeaderOrderSwapStillBlocked(t *testing.T) {
	layer := newHeaderRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"X-Role": {"admin", "guest"}})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-first header value not blocked, got %s", result.Action)
	}
}

func TestRuleHeaderSingleNonMatchClean(t *testing.T) {
	layer := newHeaderRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"X-Role": {"guest"}})
	if result := layer.Process(ctx); result.Action == engine.ActionBlock {
		t.Fatal("FAIL: non-matching header value was blocked")
	}
}

func TestRuleHeaderAbsentEqualsEmptyFires(t *testing.T) {
	// Absent header: the condition resolves against "" exactly as before
	// multi-value support (mirrors the cookie TestRuleMissingCookie pin).
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "a86", Name: "missing api key", Enabled: true,
			Conditions: []Condition{{Field: "header:X-Api-Key", Op: "equals", Value: ""}},
			Action:     "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Fatalf("FAIL: equals \"\" should fire on an absent header (empty-value resolution), got %s", result.Action)
	}
}

func TestRuleHeaderCanonicalizationPreservedMultiValue(t *testing.T) {
	// The rule author's lowercase spelling must still match the canonical
	// transport form when the header carries multiple values (pinned
	// single-value by rules_header_case_test.go; combined here).
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "c86", Name: "lowercase author form", Enabled: true,
			Conditions: []Condition{{Field: "header:x-role", Op: "equals", Value: "admin"}},
			Action:     "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/admin", "1.2.3.4", map[string][]string{"X-Role": {"guest", "admin"}})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: canonicalized lookup + match-any combined not blocked, got %s", result.Action)
	}
}
