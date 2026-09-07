package crs

import (
	"strings"
	"testing"
)

// TestParser_UnsupportedDirectivesDoNotAbortFile pins the directive-dispatch
// behavior of ParseFile. Dispatch used strings.HasPrefix(line, "SecRule"), so
// standard ModSecurity directives that merely share the prefix
// (SecRuleUpdateTargetById, SecRuleUpdateActionById, SecRuleRemoveById,
// SecRuleEngine, SecRuleScript, ...) entered parseSecRule, failed with
// "invalid SecRule format", and aborted the whole file — LoadRules then
// dropped the entire ruleset (one such line in one CRS exclusion file left
// the layer with zero rules).
func TestParser_UnsupportedDirectivesDoNotAbortFile(t *testing.T) {
	p := NewParser()
	content := `# -- rule file --
SecRule ARGS "@contains evil" "id:100,phase:2,deny,msg:'block evil'"
SecRuleUpdateTargetById 100 "ARGS:q"
SecRuleEngine On
SecRuleRemoveById 200
SecRuleUpdateActionById 100 "t:none,log"
`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile aborted on unsupported directives: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "100" {
		t.Errorf("rule ID = %q; want %q", rules[0].ID, "100")
	}
}

// TestParser_TabSeparatedDirectiveDispatch covers the tab boundary in the
// first-token split: a directive separated from its argument by a tab must
// also be recognized (and skipped) as a non-SecRule directive.
func TestParser_TabSeparatedDirectiveDispatch(t *testing.T) {
	p := NewParser()
	content := "SecRule ARGS \"@rx x\" \"id:7,phase:2,deny\"\nSecRuleScript\t/tmp/x.lua\n"
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile aborted on tab-separated directive: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "7" {
		t.Fatalf("expected only the SecRule to load, got %v", rules)
	}
}

// TestParser_SecActionStillDispatched ensures the exact-token dispatch kept
// the SecAction branch working.
func TestParser_SecActionStillDispatched(t *testing.T) {
	p := NewParser()
	content := "SecAction \"id:1,phase:1,pass,setvar:tx.flag=1\"\n"
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 SecAction rule, got %d", len(rules))
	}
}

// TestParser_MalformedSecRuleStillFails ensures the dispatch fix did not
// weaken fail-fast behavior for genuinely malformed SecRule directives.
func TestParser_MalformedSecRuleStillFails(t *testing.T) {
	p := NewParser()
	_, err := p.ParseFile("SecRule REQUEST_METHOD \"@rx ^GET$\"\n") // missing actions
	if err == nil {
		t.Fatal("expected error for malformed SecRule, got nil")
	}
	if !strings.Contains(err.Error(), "invalid SecRule format") {
		t.Fatalf("unexpected error: %v", err)
	}
}
