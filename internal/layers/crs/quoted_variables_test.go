package crs

import (
	"testing"
)

// Regression (the round-98 recorded observation): splitQuoted keeps each
// quoted section's surrounding quotes, and parseVariables never stripped
// them — a quoted variables section arrived as "\"ARGS:attack\"", so the
// collection carried a leading quote and the key a trailing one, matching
// no known collection: the rule parsed, loaded, and silently never fired.
// parseVariables now unquotes its input, mirroring the documented
// operator-unquote fix in parseOperator.
func TestQuotedVariablesSectionParses(t *testing.T) {
	rule, err := NewParser().parseSecRule(`SecRule "ARGS:attack" "@contains evil" "id:1001,phase:2,deny"`)
	if err != nil {
		t.Fatalf("parseSecRule: %v", err)
	}
	if len(rule.Variables) != 1 {
		t.Fatalf("FAIL: got %d variables, want 1", len(rule.Variables))
	}
	if rule.Variables[0].Collection != "ARGS" {
		t.Fatalf("FAIL: collection is %q, want ARGS — the leading quote survived parsing", rule.Variables[0].Collection)
	}
	if rule.Variables[0].Key != "attack" {
		t.Fatalf("FAIL: key is %q, want attack — the trailing quote survived parsing", rule.Variables[0].Key)
	}
}

// A whole-section quote wrapping a pipe-separated list must unquote BEFORE
// the pipe split, so every name inside the list is clean.
func TestQuotedPlainAndMixedVariables(t *testing.T) {
	rule, err := NewParser().parseSecRule(`SecRule "ARGS|REQUEST_HEADERS:User-Agent" "@rx x" "id:1002,phase:2,deny"`)
	if err != nil {
		t.Fatalf("parseSecRule: %v", err)
	}
	if len(rule.Variables) != 2 {
		t.Fatalf("FAIL: got %d variables, want 2", len(rule.Variables))
	}
	if rule.Variables[0].Name != "ARGS" {
		t.Fatalf("FAIL: plain variable name is %q, want ARGS", rule.Variables[0].Name)
	}
	if rule.Variables[1].Collection != "REQUEST_HEADERS" || rule.Variables[1].Key != "User-Agent" {
		t.Fatalf("FAIL: selector variable is %q:%q, want REQUEST_HEADERS:User-Agent", rule.Variables[1].Collection, rule.Variables[1].Key)
	}
}

func TestQuotedChainVariablesParse(t *testing.T) {
	rule, err := NewParser().parseSecRule(`SecRule "ARGS:session" "@streq abc" "id:1003,phase:2,chain" "REQUEST_HEADERS:Referer" "@contains evil" "t:none"`)
	if err != nil {
		t.Fatalf("parseSecRule: %v", err)
	}
	if rule.Chain == nil {
		t.Fatal("FAIL: expected a chained rule")
	}
	if len(rule.Chain.Variables) != 1 || rule.Chain.Variables[0].Collection != "REQUEST_HEADERS" {
		t.Fatalf("FAIL: chain variables are %#v, want [REQUEST_HEADERS:Referer]", rule.Chain.Variables)
	}
}

// End-to-end: the quoted-variables rule must actually FIRE against matching
// traffic, not merely parse into fields.
func TestQuotedVariablesRuleFires(t *testing.T) {
	line := `SecRule "ARGS:attack" "@contains evil" "id:1004,phase:1,deny,severity:CRITICAL,msg:'quoted-vars rule'"`
	rules, err := NewParser().ParseFile(line)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	tx := NewTransaction()
	tx.RequestArgs["attack"] = []string{"evil-payload"}
	// Mirror createTransaction: NewTransaction leaves resolver/evaluator nil;
	// only the production Process path wires them.
	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()

	matched, _, _ := (&Layer{}).evaluateRule(rules[0], tx)
	if !matched {
		t.Fatalf("FAIL: quoted-variables rule never matched attack=evil-payload — quoted variable names are inert")
	}
}
