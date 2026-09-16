package crs

import (
	"testing"
)

// Regression (round 2026-09-16): splitQuoted and splitActions toggled quote
// state on any raw quote rune, ignoring backslash escapes. An escaped quote
// (\") inside a quoted operator argument prematurely closed the section, and
// the next unquoted space split the rule mid-token: the operator argument was
// truncated and the real actions section shifted into the unused chain
// position — the rule loaded without error but was inert (detection gap).
// parseOperator unescapes \" after the split, so the escape must survive it
// verbatim; splitEscaped already honored escapes for the | separator.

func TestParseFile_EscapedQuoteOperatorRuleIntact(t *testing.T) {
	// File line: SecRule ARGS "@rx val\"ue more" "id:1001,phase:2,deny,msg:'test'"
	src := "SecRule ARGS \"@rx val\\\"ue more\" \"id:1001,phase:2,deny,msg:'test'\"\n"
	rules, err := NewParser().ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if got := r.Operator.Argument; got != `val"ue more` {
		t.Fatalf("operator argument = %q, want %q — the escaped quote split the section and corrupted the operator", got, `val"ue more`)
	}
	if r.Actions.ID != "1001" {
		t.Fatalf("actions shifted out by the mis-split: ID = %q, want 1001", r.Actions.ID)
	}
	if r.Actions.Action != "deny" {
		t.Fatalf("actions shifted out by the mis-split: Action = %q, want deny", r.Actions.Action)
	}
	if r.Actions.Msg != "test" {
		t.Fatalf("Msg = %q, want test", r.Actions.Msg)
	}
}

func TestParseFile_EscapedQuoteMsgIntact(t *testing.T) {
	// File line: SecRule ARGS "@rx x" "id:2002,phase:2,deny,msg:'blocked \"admin\" access'"
	src := "SecRule ARGS \"@rx x\" \"id:2002,phase:2,deny,msg:'blocked \\\"admin\\\" access'\"\n"
	rules, err := NewParser().ParseFile(src)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Actions.ID != "2002" {
		t.Fatalf("ID = %q, want 2002", r.Actions.ID)
	}
	if r.Actions.Action != "deny" {
		t.Fatalf("Action = %q, want deny", r.Actions.Action)
	}
	// parseActions strips the single-quote pair; the \" escapes pass through
	// verbatim (this parser only unescapes operator arguments).
	if r.Actions.Msg != `blocked \"admin\" access` {
		t.Fatalf("Msg = %q, want %q — the premature section close truncated the msg value", r.Actions.Msg, `blocked \"admin\" access`)
	}
}

func TestSplitQuotedEscapedQuoteStaysInSection(t *testing.T) {
	p := NewParser()
	parts := p.splitQuoted(`A "B\"C D" E`)
	if len(parts) != 3 {
		t.Fatalf("splitQuoted = %d parts (%v), want 3", len(parts), parts)
	}
	if parts[1] != `"B\"C D"` {
		t.Fatalf("splitQuoted part = %q, want %q — the escaped quote must not close the section", parts[1], `"B\"C D"`)
	}
}

func TestSplitActionsEscapedQuoteKeepsValue(t *testing.T) {
	parts := splitActions(`msg:'don\'t,x'`)
	if len(parts) != 1 {
		t.Fatalf("splitActions = %d parts (%v), want 1", len(parts), parts)
	}
	if parts[0] != `msg:'don\'t,x'` {
		t.Fatalf("splitActions part = %q, want %q — the escaped quote must not close the value", parts[0], `msg:'don\'t,x'`)
	}
}

// Controls: inputs without escapes must parse exactly as before, and regex
// metacharacter backslashes (not quote escapes) must pass through verbatim.
func TestParser_EscapeHandlingControls(t *testing.T) {
	p := NewParser()
	rule, err := p.parseSecRule(`SecRule ARGS "@rx ^GET$" "id:3001,phase:1,deny"`)
	if err != nil {
		t.Fatalf("control parse: %v", err)
	}
	if rule.Operator.Argument != "^GET$" || rule.Actions.ID != "3001" || rule.Actions.Action != "deny" {
		t.Fatalf("control plain rule corrupted: arg=%q id=%q action=%q", rule.Operator.Argument, rule.Actions.ID, rule.Actions.Action)
	}

	rule, err = p.parseSecRule(`SecRule ARGS:/^id_\d+$/ "@rx x" "id:3002,phase:1,deny"`)
	if err != nil {
		t.Fatalf("control parse (regex key): %v", err)
	}
	if len(rule.Variables) != 1 || !rule.Variables[0].KeyRegex || rule.Variables[0].Key != `^id_\d+$` {
		t.Fatalf("control regex-key variable corrupted: %+v", rule.Variables)
	}
}
