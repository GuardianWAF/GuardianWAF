package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestLayer_RuntimeDisableRuleStopsEvaluation pins the runtime toggle
// contract: DisableRule must stop a LOADED rule from evaluating without a
// reload. disabledRules was previously consulted only in loadRuleFile
// (config DisabledRules), so the runtime API — wired to the dashboard's
// rule-disable action — flipped IsRuleEnabled while the rule kept firing.
func TestLayer_RuntimeDisableRuleStopsEvaluation(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.conf")
	rules := `SecRule ARGS "@contains evil" "id:100,phase:2,deny,msg:'p2 rule'"
SecRule REQUEST_HEADERS:User-Agent "@contains evilbot" "id:101,phase:1,deny,msg:'p1 rule'"
`
	if err := os.WriteFile(rulePath, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	layer := NewLayer(&Config{
		Enabled:          true,
		RulePath:         rulePath,
		AnomalyThreshold: 5,
		ParanoiaLevel:    1,
	})

	newCtx := func(query, ua string) *engine.RequestContext {
		req := httptest.NewRequest("POST", "/login?"+query, nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		return &engine.RequestContext{
			Method:  req.Method,
			Request: req,
			Headers: req.Header,
		}
	}

	// Baseline: both rules fire.
	if res := layer.Process(newCtx("q=evil", "evilbot/1.0")); res.Action != engine.ActionBlock {
		t.Fatalf("baseline: expected block, got %v (score=%d)", res.Action, res.Score)
	}

	// Disable the phase-2 rule: its trigger alone must no longer block.
	layer.DisableRule("100")
	if layer.IsRuleEnabled("100") {
		t.Fatal("IsRuleEnabled reports enabled after DisableRule")
	}
	if res := layer.Process(newCtx("q=evil", "")); res.Action != engine.ActionPass {
		t.Fatalf("disabled phase-2 rule still fired: action=%v score=%d", res.Action, res.Score)
	}

	// Disable the phase-1 rule: its trigger alone must no longer block
	// (covers the phase-1 loop, not just phase 2).
	layer.DisableRule("101")
	if res := layer.Process(newCtx("", "evilbot/1.0")); res.Action != engine.ActionPass {
		t.Fatalf("disabled phase-1 rule still fired: action=%v score=%d", res.Action, res.Score)
	}

	// Re-enabling restores evaluation for loaded rules.
	layer.EnableRule("100")
	if !layer.IsRuleEnabled("100") {
		t.Fatal("IsRuleEnabled reports disabled after EnableRule")
	}
	if res := layer.Process(newCtx("q=evil", "")); res.Action != engine.ActionBlock {
		t.Fatalf("re-enabled rule did not fire: action=%v", res.Action)
	}
}
