package crs

import (
	"net/http"
	"strings"
	"testing"
)

// Regression (hunt round 12/25): /regex/ variable key selectors were parsed
// (KeyRegex=true, "Key is a regex" per the model contract) but the resolvers
// matched keys with matchWildcard — so a selector like ARGS:/^id_\d+$/ was
// compared as a literal/wildcard string against argument names and could
// never match. Every regex-keyed rule target in an operator's ruleset was
// silently inert.

func TestRegexKeySelectorMatchesArgNames(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs["id_1"] = []string{"attack-payload"}
	tx.RequestArgs["other"] = []string{"benign"}

	vr := NewVariableResolver(tx)
	vals, err := vr.Resolve(RuleVariable{Collection: "ARGS", Key: `^id_\d+$`, KeyRegex: true})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	found := false
	for _, v := range vals {
		if v == "attack-payload" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: ARGS:/^id_\\d+$/ resolved no values for arg id_1 — regex key selectors are inert (got %v)", vals)
	}
}

func TestRegexKeySelectorMatchesHeaderNames(t *testing.T) {
	tx := NewTransaction()
	tx.RequestHeaders = map[string][]string{
		http.CanonicalHeaderKey("X-Custom-Trace"): {"val"},
	}

	vr := NewVariableResolver(tx)
	vals, err := vr.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: `^X-Custom-`, KeyRegex: true})
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(vals) == 0 {
		t.Fatalf("FAIL: REQUEST_HEADERS:/^X-Custom-/ resolved no values — regex key selectors are inert")
	}
}

// End-to-end: a parsed SecRule with a regex key selector must actually fire.
func TestRegexKeySelectorRuleFires(t *testing.T) {
	line := `SecRule ARGS:/^id_\d+$/ "@contains attack" "id:100,phase:1,deny,severity:CRITICAL,msg:'regex-key rule'"`
	rules, err := NewParser().ParseFile(line)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	tx := NewTransaction()
	tx.RequestArgs["id_1"] = []string{"attack-payload"}
	// Mirror createTransaction: NewTransaction leaves resolver/evaluator nil;
	// only the production Process path wires them.
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	matched, _, _ := (&Layer{}).evaluateRule(rules[0], tx)
	if !matched {
		t.Fatalf("FAIL: rule with ARGS:/^id_\\d+$/ never matched id_1=attack-payload — regex key targets are inert")
	}
}

// Controls: exact-key selectors keep working, and the regex must stay
// anchored (no substring drift).
func TestExactKeySelectorStillWorks(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs["id_1"] = []string{"attack-payload"}

	vr := NewVariableResolver(tx)
	vals, _ := vr.Resolve(RuleVariable{Collection: "ARGS", Key: "id_1"})
	if len(vals) != 1 {
		t.Fatalf("exact key selector broke: got %v", vals)
	}
}

func TestRegexKeySelectorStaysAnchored(t *testing.T) {
	tx := NewTransaction()
	tx.RequestArgs["xid_1"] = []string{"payload"}

	vr := NewVariableResolver(tx)
	vals, _ := vr.Resolve(RuleVariable{Collection: "ARGS", Key: `^id_\d+$`, KeyRegex: true})
	for _, v := range vals {
		if strings.Contains(v, "payload") {
			t.Fatalf("FAIL: ^id_\\d+$ matched xid_1 — regex anchoring lost")
		}
	}
}
