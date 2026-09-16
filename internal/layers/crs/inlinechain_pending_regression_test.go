package crs

import (
	"testing"
)

// Regression (round 2026-09-16): ParseFile set pendingChainRule from
// rule.Actions.Chain alone. For a single-line chained rule (the supported
// 6-part form: SecRule V "@op" "id:1,...,chain" V2 "@op2" "actions2"),
// parseSecRule already links the complete inline chain into rule.Chain — but
// ParseFile still marked the rule as awaiting a continuation, so the NEXT
// unrelated SecRule line was linked via pendingChainRule.Chain = rule: the
// inline chain condition was overwritten (lost) and the following top-level
// rule was demoted into the chain, never evaluated independently again.
// pendingChainRule is now set only when the chain truly continues: the rule
// has no linked chain yet (multi-line form) or its inline tail itself
// declares chain.

func TestParseFile_InlineChainDoesNotSwallowFollowingRule(t *testing.T) {
	src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny,chain\" ARGS \"@rx b\" \"phase:2,deny\"\n" +
		"SecRule REQUEST_METHOD \"@streq POST\" \"id:2002,phase:2,deny\"\n"
	rules, err := NewParser().ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d top-level rules, want 2 — the rule following a complete single-line chain was swallowed into the chain", len(rules))
	}
	c := rules[0].Chain
	if c == nil || len(c.Variables) != 1 || c.Variables[0].Name != "ARGS" || c.Operator.Argument != "b" {
		t.Fatalf("inline chain condition lost or corrupted: %+v", c)
	}
	if rules[1].ID != "2002" {
		t.Fatalf("second rule demoted: ID = %q, want 2002", rules[1].ID)
	}
}

func TestParseFile_MultiLineDepth3ChainIntact(t *testing.T) {
	src := "SecRule ARGS \"@rx a\" \"id:1,phase:2,deny,chain\"\n" +
		"SecRule REQUEST_HEADERS:Referer \"@contains evil\" \"id:2,phase:2,deny,chain\"\n" +
		"SecRule REQUEST_METHOD \"@streq POST\" \"id:3,phase:2,deny\"\n"
	rules, err := NewParser().ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d top-level rules, want 1 for a depth-3 chain", len(rules))
	}
	if rules[0].Chain == nil || rules[0].Chain.Chain == nil {
		t.Fatalf("depth-3 chain not linked: %+v", rules[0].Chain)
	}
	if rules[0].Chain.ID != "2" || rules[0].Chain.Chain.ID != "3" {
		t.Fatalf("chain order corrupted: %q -> %q", rules[0].Chain.ID, rules[0].Chain.Chain.ID)
	}
}

// Characterization: an inline chain whose TAIL declares chain continues on
// the next line (the Rule struct links one chain member, so the tail is
// superseded by the linked continuation — documented linking semantics the
// guard must preserve).
func TestParseFile_InlineChainWithTailChainContinues(t *testing.T) {
	src := "SecRule ARGS \"@rx a\" \"id:3001,phase:2,deny,chain\" ARGS \"@rx b\" \"phase:2,deny,chain\"\n" +
		"SecRule REQUEST_METHOD \"@streq POST\" \"id:3003,phase:2,deny\"\n"
	rules, err := NewParser().ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d top-level rules, want 1 for a continuing chain", len(rules))
	}
	if rules[0].Chain == nil || rules[0].Chain.ID != "3003" {
		t.Fatalf("continuation not linked: %+v", rules[0].Chain)
	}
}
