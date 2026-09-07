package crs

import (
	"testing"
)

// parseChainFixture parses the canonical depth-3 CRS chain used by the tests
// below: the chain must fire only when ALL three conditions hold.
func parseChainFixture(t *testing.T) []*Rule {
	t.Helper()
	p := NewParser()
	content := `SecRule REQUEST_METHOD "@streq POST" "id:300,phase:1,chain"
SecRule ARGS:action "@streq login" "phase:1,chain"
SecRule ARGS:user "@rx ^admin$" "deny"
`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	return rules
}

// TestParser_Depth3ChainParsesAsSingleRule pins the parsed model: a depth-3
// chain is ONE top-level rule with a three-level Chain linkage. The linker
// previously nil'ed pendingChainRule after one link, so the tail rule leaked
// as a standalone top-level rule — evaluated both outside the chain's
// AND-condition and with the chain firing without the tail condition.
func TestParser_Depth3ChainParsesAsSingleRule(t *testing.T) {
	rules := parseChainFixture(t)
	if len(rules) != 1 {
		t.Fatalf("expected 1 top-level rule, got %d", len(rules))
	}
	top := rules[0]
	if top.Chain == nil || top.Chain.Chain == nil {
		t.Fatalf("expected a 3-level chain, got depth %d", chainDepth(top))
	}
	if tail := top.Chain.Chain; tail.Operator.Argument != "^admin$" {
		t.Errorf("tail operator argument = %q; want %q", tail.Operator.Argument, "^admin$")
	}
}

// TestParser_ChainedRuleEvaluatedWithFullANDLogic verifies the behavioral
// consequence through the evaluator: the chain matches only when every level
// matches. Pre-fix, the chain fired without the tail condition.
func TestParser_ChainedRuleEvaluatedWithFullANDLogic(t *testing.T) {
	layer := NewLayer(nil)
	rules := parseChainFixture(t)
	if len(rules) != 1 {
		t.Fatalf("expected 1 top-level rule, got %d", len(rules))
	}

	newTx := func(method string, args map[string][]string) *Transaction {
		tx := NewTransaction()
		tx.Method = method
		tx.RequestArgs = args
		// evaluateRule consumes the cached resolver/evaluator that Process's
		// transaction builder normally installs; install them explicitly here.
		// A nil evaluator deadline is the supported no-budget test mode.
		tx.resolver = NewVariableResolver(tx)
		tx.evaluator = NewOperatorEvaluator()
		return tx
	}

	// All three conditions match -> chain fires.
	txAll := newTx("POST", map[string][]string{"action": {"login"}, "user": {"admin"}})
	if matched, _, _ := layer.evaluateRule(rules[0], txAll); !matched {
		t.Error("chain did not fire when all three conditions match")
	}

	// Tail condition fails -> chain must NOT fire.
	txTailFails := newTx("POST", map[string][]string{"action": {"login"}, "user": {"guest"}})
	if matched, _, _ := layer.evaluateRule(rules[0], txTailFails); matched {
		t.Error("chain fired even though the tail condition (ARGS:user ^admin$) failed")
	}

	// Middle condition fails -> chain must NOT fire.
	txMidFails := newTx("POST", map[string][]string{"action": {"logout"}, "user": {"admin"}})
	if matched, _, _ := layer.evaluateRule(rules[0], txMidFails); matched {
		t.Error("chain fired even though the middle condition (ARGS:action streq login) failed")
	}
}

// TestParser_Depth2ChainUnchanged guards the fix against over-correction: a
// depth-2 chain still parses to one rule with exactly one chain link.
func TestParser_Depth2ChainUnchanged(t *testing.T) {
	p := NewParser()
	content := `SecRule REQUEST_METHOD "@streq POST" "id:400,phase:1,chain"
SecRule REQUEST_URI "@rx ^/admin" "deny"
`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 || rules[0].Chain == nil || rules[0].Chain.Chain != nil {
		t.Fatalf("depth-2 model changed: %d rules, chainDepth %d", len(rules), chainDepth(rules[0]))
	}
}

// chainDepth measures how many Chain links hang off a rule.
func chainDepth(r *Rule) int {
	depth := 1
	for node := r.Chain; node != nil; node = node.Chain {
		depth++
	}
	return depth
}
