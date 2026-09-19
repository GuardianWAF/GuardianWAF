package crs

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-09-18): ParseFile's SecAction branch appended every
// SecAction standalone and never participated in pendingChainRule. SecLang
// allows SecAction in rule chains ("The following directives can be used in
// rule chains: SecAction, SecRule, SecRuleScript" — Coraza SecLang
// reference), so a chained SecAction starter was parsed as an unconditional
// top-level rule — its deny fired on EVERY request (the chain's AND-gate was
// lost) and its continuation was demoted to a standalone top-level rule.

func TestParseSecActionChainStarterLinksContinuation(t *testing.T) {
	content := `SecAction "id:920001,phase:1,deny,chain"
SecRule ARGS:gate "@streq open" "id:920002,phase:1,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("chained SecAction ruleset parsed as %d standalone rules, want 1 chain", len(rules))
	}
	if !rules[0].Actions.Chain || rules[0].Chain == nil {
		t.Fatalf("chain starter not linked (Actions.Chain=%v, Chain=%v)", rules[0].Actions.Chain, rules[0].Chain)
	}
	if rules[0].Chain.ID != "920002" || rules[0].Chain.Unconditional {
		t.Fatalf("continuation linked wrong: ID=%q Unconditional=%v", rules[0].Chain.ID, rules[0].Chain.Unconditional)
	}
}

func TestParseSecRuleChainLinksSecActionContinuation(t *testing.T) {
	content := `SecRule ARGS:gate "@streq open" "id:920003,phase:1,deny,chain"
SecAction "id:920004,setvar:tx.gw_mid=1"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("mixed chain parsed as %d standalone rules, want 1 chain", len(rules))
	}
	if rules[0].Chain == nil || !rules[0].Chain.Unconditional {
		t.Fatalf("SecAction continuation not linked as chain child (Chain=%v)", rules[0].Chain)
	}
}

func TestParseSecActionMidChainThreeLinks(t *testing.T) {
	content := `SecRule ARGS:gate "@streq open" "id:920005,phase:1,deny,chain"
SecAction "id:920006,setvar:tx.gw_mid=1,chain"
SecRule ARGS:second "@streq yes" "id:920007,phase:1,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("3-link chain parsed as %d standalone rules, want 1", len(rules))
	}
	c1 := rules[0].Chain
	if c1 == nil || !c1.Unconditional || c1.Chain == nil || c1.Chain.ID != "920007" {
		t.Fatalf("3-link chain not linked through the SecAction mid-node: starter.Chain=%+v", c1)
	}
}

// The SecAction mid-chain node must gate its own deeper continuation — the
// unconditional fast path previously bypassed evaluateRule's chain AND-check,
// which would have let the starter's deny fire without the deepest condition.
func TestEvaluateMidChainSecActionGatesDeeperLink(t *testing.T) {
	content := `SecRule ARGS:gate "@streq open" "id:920005,phase:1,deny,chain"
SecAction "id:920006,setvar:tx.gw_mid=1,chain"
SecRule ARGS:second "@streq yes" "id:920007,phase:1,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := NewLayer(DefaultConfig())

	newTx := func(gate, second string) *Transaction {
		tx := NewTransaction()
		tx.RequestArgs["gate"] = []string{gate}
		tx.RequestArgs["second"] = []string{second}
		tx.resolver = NewVariableResolver(tx)
		tx.evaluator = NewOperatorEvaluator()
		return tx
	}

	// Both links match: starter matched, mid-node setvar applied.
	full := newTx("open", "yes")
	if matched, _, _ := l.evaluateRule(rules[0], full); !matched {
		t.Fatalf("fully matching 3-link chain reported unmatched")
	}
	if full.GetVar("gw_mid") != "1" {
		t.Fatalf("mid-node setvar not applied on a matching chain (tx.gw_mid=%q)", full.GetVar("gw_mid"))
	}

	// Deepest link fails: the whole chain is unmatched and the mid-node's
	// actions must not have run (gating precedes side effects).
	short := newTx("open", "no")
	if matched, _, _ := l.evaluateRule(rules[0], short); matched {
		t.Fatalf("3-link chain matched with a failing deepest link")
	}
	if short.GetVar("gw_mid") != "" {
		t.Fatalf("mid-node setvar ran despite the failing deeper link (tx.gw_mid=%q)", short.GetVar("gw_mid"))
	}
}

func TestProcessChainedSecActionDenyIsGated(t *testing.T) {
	content := `SecAction "id:920001,phase:1,deny,chain"
SecRule ARGS:gate "@streq open" "id:920002,phase:1,pass"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	l.rules = rules
	l.buildRuleMaps()

	newCtx := func(target string) *engine.RequestContext {
		return &engine.RequestContext{
			Method:  "GET",
			Path:    target,
			Request: httptest.NewRequest("GET", target, nil),
			Headers: map[string][]string{"Host": {"example.com"}},
		}
	}
	if res := l.Process(newCtx("/")); res.Action == engine.ActionBlock {
		t.Fatalf("benign request blocked — chained SecAction deny fired without its continuation condition")
	}
	if res := l.Process(newCtx("/?gate=open")); res.Action != engine.ActionBlock {
		t.Fatalf("gated request not blocked (Action=%v) — chain starter deny did not fire on a matching chain", res.Action)
	}
}

// A SecAction continuation's actions run only when the starter matched — the
// chain child is never evaluated when an earlier link fails.
func TestEvaluateSecActionContinuationGatedByStarter(t *testing.T) {
	content := `SecRule ARGS:gate "@streq open" "id:920003,phase:1,deny,chain"
SecAction "id:920004,setvar:tx.gw_mid=1"`
	rules, err := NewParser().ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	l := NewLayer(DefaultConfig())

	newTx := func(gate string) *Transaction {
		tx := NewTransaction()
		tx.RequestArgs["gate"] = []string{gate}
		tx.resolver = NewVariableResolver(tx)
		tx.evaluator = NewOperatorEvaluator()
		return tx
	}

	matching := newTx("open")
	matched, _, _ := l.evaluateRule(rules[0], matching)
	if !matched || matching.GetVar("gw_mid") != "1" {
		t.Fatalf("matched chain: matched=%v tx.gw_mid=%q, want matched with setvar applied", matched, matching.GetVar("gw_mid"))
	}

	failing := newTx("closed")
	if matchedF, _, _ := l.evaluateRule(rules[0], failing); matchedF {
		t.Fatalf("failing chain: starter reported matched")
	}
	if failing.GetVar("gw_mid") != "" {
		t.Fatalf("failing chain: SecAction continuation's setvar ran anyway (tx.gw_mid=%q)", failing.GetVar("gw_mid"))
	}
}
