package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: CRS setvar "+=" / "-=" must apply varAction.Value as an
// arithmetic add/subtract on the target TX variable. Two defects previously
// broke this: parseVarAction split canonical "score+=3" at the first "="
// (yielding Variable "score+", Operation "=" — a junk assignment) so the
// arithmetic branch was dead code for real CRS rules, and the evaluator's
// "+=" case ignored varAction.Value/Variable entirely, calling
// tx.AddAnomalyScore(severityScore) instead.

func TestParseVarActionOperations(t *testing.T) {
	p := NewParser()

	cases := []struct {
		in                          string
		collection, variable, value string
		op                          string
	}{
		{"tx.score+=3", "tx", "score", "3", "+="}, // canonical increment
		{"tx.score-=2", "tx", "score", "2", "-="}, // canonical decrement
		{"tx.block=1", "tx", "block", "1", "="},   // plain assignment
		{"tx.score=+3", "tx", "score", "3", "+="}, // legacy =+ spelling
		{"tx.score=-2", "tx", "score", "2", "-="}, // legacy =- spelling
		{"tx.flag=abc", "tx", "flag", "abc", "="}, // non-numeric assignment
	}
	for _, tc := range cases {
		va := p.parseVarAction(tc.in)
		if va.Collection != tc.collection || va.Variable != tc.variable ||
			va.Operation != tc.op || va.Value != tc.value {
			t.Fatalf("FAIL: parseVarAction(%q) = %+v, want {%s %s %s %s}",
				tc.in, va, tc.collection, tc.variable, tc.op, tc.value)
		}
	}
}

// evaluateRule must accumulate the authored delta on the TX variable across
// repeated matches, subtract on "-=", and treat empty values as 0.
func TestSetVarArithmeticAccumulates(t *testing.T) {
	l := NewLayer(DefaultConfig())
	tx := NewTransaction()
	tx.RequestArgs["q"] = []string{"go"}
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	rule := &Rule{
		ID:        "3001",
		Variables: []RuleVariable{{Name: "ARGS"}},
		Operator:  RuleOperator{Type: "@contains", Argument: "go"},
		Actions: RuleActions{
			SetVar: []VarAction{{Collection: "tx", Variable: "score", Operation: "+=", Value: "3"}},
		},
	}

	// Two matches accumulate: 0+3 then 3+3.
	for i, want := range []string{"3", "6"} {
		if matched, _, _ := l.evaluateRule(rule, tx); !matched {
			t.Fatalf("FAIL: match %d did not fire", i+1)
		}
		if got := tx.GetVar("score"); got != want {
			t.Fatalf("FAIL: after %d matches TX:score = %q, want %q", i+1, got, want)
		}
	}

	// "-=" subtracts the authored value.
	rule.Actions.SetVar = []VarAction{{Collection: "tx", Variable: "score", Operation: "-=", Value: "4"}}
	if matched, _, _ := l.evaluateRule(rule, tx); !matched {
		t.Fatal("FAIL: decrement rule did not fire")
	}
	if got := tx.GetVar("score"); got != "2" {
		t.Fatalf("FAIL: after -=4 TX:score = %q, want 2", got)
	}

	// Empty value acts as 0 (variable preserved, no phantom increment).
	rule.Actions.SetVar = []VarAction{{Collection: "tx", Variable: "score", Operation: "+=", Value: ""}}
	if matched, _, _ := l.evaluateRule(rule, tx); !matched {
		t.Fatal("FAIL: empty-increment rule did not fire")
	}
	if got := tx.GetVar("score"); got != "2" {
		t.Fatalf("FAIL: empty += changed TX:score to %q, want 2", got)
	}

	// The severity score is not involved: a CRITICAL rule (score 10) with
	// +=1 yields exactly +1, not +10.
	critical := &Rule{
		ID:        "3009",
		Variables: []RuleVariable{{Name: "ARGS"}},
		Operator:  RuleOperator{Type: "@contains", Argument: "go"},
		Actions: RuleActions{
			Severity: "CRITICAL",
			SetVar:   []VarAction{{Collection: "tx", Variable: "s2", Operation: "+=", Value: "1"}},
		},
	}
	if matched, _, _ := l.evaluateRule(critical, tx); !matched {
		t.Fatal("FAIL: critical rule did not fire")
	}
	if got := tx.GetVar("s2"); got != "1" {
		t.Fatalf("FAIL: CRITICAL severity leaked into += (TX:s2 = %q, want 1)", got)
	}
}

// Integration through the real pipeline: a setvar increment gates a follow-up
// rule that reads the TX variable.
func TestSetVarGateIntegration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	rules := `SecRule ARGS:trigger "@contains go" "id:3001,phase:1,setvar:tx.score+=3,severity:'CRITICAL'"
SecRule TX:score "@ge 3" "id:3002,phase:1,deny,status:403,msg:'score gate',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(rules+"\n"), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 100})
	if err := layer.LoadRules(path); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if layer.GetRule("3001") == nil || layer.GetRule("3002") == nil {
		t.Fatal("rules did not parse")
	}

	run := func(target string) engine.Action {
		req := httptest.NewRequest("GET", target, nil)
		ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
		return layer.Process(ctx).Action
	}

	// The authored increment must make TX:score reach 3 so the gate denies.
	if a := run("/login?trigger=go"); a != engine.ActionBlock {
		t.Fatalf("FAIL: setvar tx.score+=3 did not arm the follow-up gate (action %v)", a)
	}
	// Control: the gate stays closed without the trigger.
	if a := run("/login?x=hello"); a != engine.ActionPass {
		t.Fatalf("FAIL: control — benign request blocked (action %v)", a)
	}
}
