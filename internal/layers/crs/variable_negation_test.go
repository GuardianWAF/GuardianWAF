package crs

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: CRS variable prefixes "!X" (negation) and "&X" (count)
// must be recognized. parseVariables used to check HasPrefix(part, "!+") and
// HasPrefix(part, "&+") — neither canonical form matches, so "!ARGS:password"
// parsed as Collection "!ARGS" (a bogus collection resolving to nothing,
// Exclude left false) and "&ARGS" as Collection "&ARGS". Net effect: negation
// targets were false-positive machines (the excluded field's value still
// matched via the included sibling) and count rules never fired.

func TestParseVariablesNegationAndCountFlags(t *testing.T) {
	p := NewParser()

	vars, err := p.parseVariables(`ARGS|!ARGS:password`)
	if err != nil {
		t.Fatalf("parseVariables: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("got %d variables, want 2", len(vars))
	}
	// Plain form (no colon) populates Name; keyed form populates Collection+Key.
	varName := func(rv RuleVariable) string {
		if rv.Name != "" {
			return rv.Name
		}
		return rv.Collection
	}
	if varName(vars[0]) != "ARGS" || vars[0].Exclude || vars[0].Count {
		t.Fatalf("included target parsed wrong: %+v", vars[0])
	}
	if !vars[1].Exclude || varName(vars[1]) != "ARGS" || vars[1].Key != "password" {
		t.Fatalf("FAIL: negation target parsed wrong: %+v", vars[1])
	}

	count, err := p.parseVariables(`&ARGS`)
	if err != nil {
		t.Fatalf("parseVariables(&ARGS): %v", err)
	}
	if len(count) != 1 || !count[0].Count || varName(count[0]) != "ARGS" {
		t.Fatalf("FAIL: count target parsed wrong: %+v", count)
	}

	combined, err := p.parseVariables(`&!ARGS:password`)
	if err != nil {
		t.Fatalf("parseVariables(&!ARGS:password): %v", err)
	}
	if len(combined) != 1 || !combined[0].Count || !combined[0].Exclude ||
		varName(combined[0]) != "ARGS" || combined[0].Key != "password" {
		t.Fatalf("FAIL: combined count+negation target parsed wrong: %+v", combined)
	}
}

func TestEvaluateRuleExclusionSuppressesMatch(t *testing.T) {
	l := NewLayer(DefaultConfig())
	tx := NewTransaction()
	tx.RequestArgs["password"] = []string{"attack"}
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	rule := &Rule{
		ID: "2001",
		Variables: []RuleVariable{
			{Name: "ARGS"},
			{Collection: "ARGS", Key: "password", Exclude: true},
		},
		Operator: RuleOperator{Type: "@contains", Argument: "attack"},
	}

	if matched, _, _ := l.evaluateRule(rule, tx); matched {
		t.Fatal("FAIL: rule fired on the explicitly excluded field's value")
	}

	// Control: a non-excluded arg whose value contains the pattern still
	// fires. (Value-level exclusion removes exactly the excluded value; a
	// different field carrying the byte-identical value would also be
	// excluded — a documented limitation of the flat resolver model.)
	tx.RequestArgs["comment"] = []string{"xattack"}
	if matched, _, _ := l.evaluateRule(rule, tx); !matched {
		t.Fatal("FAIL: control — non-excluded arg did not match")
	}
}

// A rule with only exclusion targets means the collection minus the excluded
// entries (ModSecurity lone-negation semantics).
func TestLoneNegationRuleMeansCollectionMinusKey(t *testing.T) {
	l := NewLayer(DefaultConfig())
	rule := &Rule{
		ID:        "2003",
		Variables: []RuleVariable{{Collection: "ARGS", Key: "password", Exclude: true}},
		Operator:  RuleOperator{Type: "@contains", Argument: "attack"},
	}

	tx := NewTransaction()
	tx.RequestArgs["password"] = []string{"attack"}
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	if matched, _, _ := l.evaluateRule(rule, tx); matched {
		t.Fatal("FAIL: lone negation matched the excluded field's value")
	}

	tx.RequestArgs["comment"] = []string{"xattack"}
	if matched, _, _ := l.evaluateRule(rule, tx); !matched {
		t.Fatal("FAIL: lone negation did not match the non-excluded field")
	}
}

func TestCountVariableResolvesAfterPrefixFix(t *testing.T) {
	l := NewLayer(DefaultConfig())
	rule := &Rule{
		ID:        "2002",
		Variables: []RuleVariable{{Name: "ARGS", Count: true}},
		Operator:  RuleOperator{Type: "@ge", Argument: "3"},
	}

	newTx := func(n int) *Transaction {
		tx := NewTransaction()
		tx.resolver = NewVariableResolver(tx)
		tx.evaluator = NewOperatorEvaluator()
		for i := 0; i < n; i++ {
			tx.RequestArgs[fmtKey(i)] = []string{"v"}
		}
		return tx
	}

	if matched, _, _ := l.evaluateRule(rule, newTx(3)); !matched {
		t.Fatal("FAIL: 3 args did not satisfy &ARGS @ge 3")
	}
	if matched, _, _ := l.evaluateRule(rule, newTx(2)); matched {
		t.Fatal("FAIL: 2 args satisfied &ARGS @ge 3")
	}
}

func fmtKey(i int) string {
	return "k" + string(rune('a'+i))
}

// Integration: negation and count rules loaded from a CRS file behave as
// authored through the real Process path.
func TestNegationAndCountRulesViaLoadRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	rules := `SecRule ARGS|!ARGS:password "@contains attack" "id:2001,phase:1,deny,status:403,msg:'exclusion test',severity:'CRITICAL'"
SecRule &ARGS "@ge 3" "id:2002,phase:1,deny,status:403,msg:'too many args',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(rules+"\n"), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(path); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if layer.GetRule("2001") == nil || layer.GetRule("2002") == nil {
		t.Fatal("rules did not parse")
	}

	run := func(target string) engine.Action {
		req := httptest.NewRequest("GET", target, nil)
		ctx := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
		return layer.Process(ctx).Action
	}

	// Negation: the excluded field's value must not trigger.
	if a := run("/login?password=attack"); a != engine.ActionPass {
		t.Fatalf("FAIL: negation target did not exclude the field (action %v)", a)
	}
	// Control: non-excluded value fires.
	if a := run("/login?x=attack"); a != engine.ActionBlock {
		t.Fatalf("FAIL: control — non-excluded arg did not fire (action %v)", a)
	}
	// Count: 3 args trip @ge 3.
	if a := run("/login?a=1&b=2&c=3"); a != engine.ActionBlock {
		t.Fatalf("FAIL: count target did not fire on 3 args (action %v)", a)
	}
	// Boundary: below the threshold passes.
	if a := run("/login?a=1&b=2"); a != engine.ActionPass {
		t.Fatalf("FAIL: 2 args triggered the @ge 3 count rule (action %v)", a)
	}
}
