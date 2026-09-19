package crs

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-18): rules without a phase action parsed with
// Phase 0. buildRuleMaps registers rules by Phase and Process evaluates only
// phases 1 and 2, so every phase-less SecRule/SecAction was filed under
// rulesByPhase[0] and never evaluated. SecLang contract: a rule without a
// phase action runs in the default phase — phase 2, the request phase
// (ModSecurity Reference Manual v2.x, Processing Phases / SecDefaultAction
// "default phase:2"). Explicit phase actions must keep overriding.

func TestParsePhaselessRulesDefaultToPhase2(t *testing.T) {
	content := `SecRule ARGS:probe "@streq hit" "id:910001,deny"
SecAction "id:910002,deny"
SecRule ARGS:probe "@streq hit" "id:910003,phase:1,deny"
SecAction "id:910004,phase:5,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("ParseFile returned %d rules, want 4", len(rules))
	}
	if rules[0].Phase != 2 {
		t.Fatalf("phase-less SecRule parsed with Phase=%d, want 2 (SecLang default) — it is filed under rulesByPhase[0] and never evaluated", rules[0].Phase)
	}
	if rules[1].Phase != 2 {
		t.Fatalf("phase-less SecAction parsed with Phase=%d, want 2 (SecLang default)", rules[1].Phase)
	}
	if rules[2].Phase != 1 {
		t.Fatalf("explicit phase:1 SecRule parsed with Phase=%d — parser broke explicit phases", rules[2].Phase)
	}
	if rules[3].Phase != 5 {
		t.Fatalf("explicit phase:5 SecAction parsed with Phase=%d — parser broke explicit phases", rules[3].Phase)
	}
}

// A phase-less deny SecRule must execute in the default phase: a matching
// request must block through the full Process path.
func TestProcessPhaselessDenyRuleBlocks(t *testing.T) {
	content := `SecRule ARGS:probe "@streq hit" "id:910001,deny"
SecRule ARGS:probe "@streq hit" "id:910003,phase:1,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	l.rules = rules
	l.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/?probe=hit",
		Request: httptest.NewRequest("GET", "/?probe=hit", nil),
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}
	if res := l.Process(ctx); res.Action != engine.ActionBlock {
		t.Fatalf("phase-less deny SecRule did not block (Action=%v) — rule never executed", res.Action)
	}
}

// A phase-less deny SecAction must execute in the default phase.
func TestProcessPhaselessDenySecActionBlocks(t *testing.T) {
	content := `SecAction "id:910002,deny"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	l.rules = rules
	l.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}
	if res := l.Process(ctx); res.Action != engine.ActionBlock {
		t.Fatalf("phase-less deny SecAction did not block (Action=%v) — rule never executed", res.Action)
	}
}
