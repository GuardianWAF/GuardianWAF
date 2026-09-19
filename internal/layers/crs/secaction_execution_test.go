package crs

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-18): SecAction directives were parsed and
// registered into the phase maps, but evaluateRule could only set
// matched=true inside the variable-match loop — SecAction rules carry no
// variables by design — so every parsed SecAction early-returned
// false, 0, nil and its action list (setvar, deny, ...) never ran. Per the
// ModSecurity Reference Manual, SecAction "unconditionally processes the
// action list it receives as the first and only parameter" — the CRS
// setup/initialization idiom (SecAction setvar:tx.*) silently did nothing.
//
// The fix marks parsed SecAction rules Unconditional; evaluateRule executes
// their action list with matched=true, score 0 and no finding (a SecAction
// is not a detection — a default-severity point per setup SecAction would
// push every request over the block threshold), while Process still honors
// explicit deny/block via shouldBlock.

func TestParseSecActionUnconditionalFlag(t *testing.T) {
	content := `SecAction "id:900001,phase:1,pass,nolog,setvar:tx.probe=1"
SecRule ARGS:probe "@streq hit" "id:900002,phase:1,pass,nolog,setvar:tx.probe2=1"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("ParseFile returned %d rules, want 2", len(rules))
	}
	if !rules[0].Unconditional {
		t.Fatalf("SecAction parsed with Unconditional=false — SecAction rules would be dead at evaluation")
	}
	// Kind discrimination: only parseSecAction sets the flag. A SecRule —
	// even a degenerate one — must never inherit unconditional semantics.
	if rules[1].Unconditional {
		t.Fatalf("SecRule parsed with Unconditional=true — a rule with targets must require a match")
	}
}

func TestEvaluateRuleSecActionExecutesActions(t *testing.T) {
	content := `SecAction "id:900001,phase:1,pass,nolog,setvar:tx.gw_probe=1,setvar:tx.gw_counter+=2"
SecRule ARGS:probe "@streq hit" "id:900002,phase:1,pass,nolog,setvar:tx.gw_secrule=1"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	l := NewLayer(DefaultConfig())
	tx := NewTransaction()
	tx.RequestArgs["probe"] = []string{"hit"}
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	// Control: a matching SecRule keeps matching and executing setvar.
	matched, _, _ := l.evaluateRule(rules[1], tx)
	if !matched {
		t.Fatalf("control: matching SecRule did not match")
	}
	if tx.GetVar("gw_secrule") != "1" {
		t.Fatalf("control: matching SecRule setvar not applied (tx.gw_secrule=%q)", tx.GetVar("gw_secrule"))
	}

	// SecAction: unconditional execution, no detection reporting.
	matchedSA, scoreSA, findingSA := l.evaluateRule(rules[0], tx)
	if !matchedSA {
		t.Fatalf("SecAction did not execute (matched=false)")
	}
	if tx.GetVar("gw_probe") != "1" {
		t.Fatalf("SecAction setvar not applied (tx.gw_probe=%q)", tx.GetVar("gw_probe"))
	}
	if tx.GetVar("gw_counter") != "2" {
		t.Fatalf("SecAction += arithmetic not applied (tx.gw_counter=%q, want \"2\")", tx.GetVar("gw_counter"))
	}
	if scoreSA != 0 {
		t.Fatalf("SecAction contributed anomaly score %d — SecActions must not inflate the anomaly score", scoreSA)
	}
	if findingSA != nil {
		t.Fatalf("SecAction produced a finding — it is not a detection")
	}
}

func TestProcessSecActionNoScoreInflation(t *testing.T) {
	// Six severity-less setup SecActions (the crs-setup.conf idiom): before
	// the fix they no-oped; a naive "unconditional = matched" fix would have
	// added six default-severity points and blocked every benign request at
	// the default threshold of 5. Actions must run; the score must stay 0.
	content := `SecAction "id:900101,phase:1,pass,nolog,setvar:tx.init1=1"
SecAction "id:900102,phase:1,pass,nolog,setvar:tx.init2=1"
SecAction "id:900103,phase:1,pass,nolog,setvar:tx.init3=1"
SecAction "id:900104,phase:1,pass,nolog,setvar:tx.init4=1"
SecAction "id:900105,phase:1,pass,nolog,setvar:tx.init5=1"
SecAction "id:900106,phase:1,pass,nolog,setvar:tx.init6=1"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.rules = rules
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}
	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Fatalf("benign request blocked by setup SecActions — anomaly score inflated (score=%d)", result.Score)
	}
	if result.Score != 0 {
		t.Fatalf("Process score = %d, want 0 — SecActions must not contribute anomaly score", result.Score)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("Process produced %d findings for SecActions — SecActions are not detections", len(result.Findings))
	}
}

func TestProcessSecActionExplicitDenyBlocks(t *testing.T) {
	// An unconditional SecAction with an explicit disruptive action must
	// block — the matched=true return feeds shouldBlock like any rule.
	content := `SecAction "id:900201,phase:1,deny,status:403"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.rules = rules
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatalf("SecAction deny did not block (Action=%v) — unconditional disruptive actions must be honored", result.Action)
	}
}
