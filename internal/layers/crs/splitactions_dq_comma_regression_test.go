package crs

// Regression (round 2026-09-24-r2-crs-splitactions-dq-comma): splitActions
// tracked only single-quote state, so a comma inside a SecLang
// escaped-double-quote value span (msg:\"a, b\") split the action list
// mid-value — the value truncated at the comma and the tail became a stray,
// silently-dropped token. SecLang grammar: the actions section is one
// double-quoted string, so a literal double quote inside it is escaped as
// \", and a value containing a comma may be spelled msg:\"a, b\". The \"
// pairs must toggle an escaped-double-quote span whose commas are protected;
// bare double quotes (invalid SecLang) stay plain characters, preserving the
// documented a,b,"c,d",e 5-part split; \" pairs inside single-quoted values
// stay verbatim and inert; backslash escape pairs are never separators.

import (
	"testing"
)

func TestSplitActions_EscapedDoubleQuoteSpanProtectsCommas(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"escaped-dq value with comma", `msg:\"a, b\",deny`, 2},
		{"single-quoted value with comma", `msg:'a, b',deny`, 2},
		{"bare dq commas still split (invalid SecLang, documented)", `a,b,"c,d",e`, 5},
		{"escaped backslash is not a comma escape", `a\\,deny`, 2},
		{"escaped comma does not split", `a\,b`, 1},
		{"escaped quote inside single-quoted value (round-4 shape)", `msg:'don\'t,x'`, 1},
		{"dq pair inside single-quoted value stays inert", `msg:'say \"x\", ok',log`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := splitActions(tc.input)
			if len(parts) != tc.want {
				t.Fatalf("splitActions(%q) = %d parts (%q), want %d", tc.input, len(parts), parts, tc.want)
			}
		})
	}
}

// TestParse_EscapedDoubleQuotedMsgSurvives pins the parse-level contract
// through the full production chain (ParseFile -> parseSecRule ->
// splitQuoted -> parseActions -> splitActions): the value survives as one
// token with its full text (the \" pairs stay verbatim — the pinned
// value-text convention), and actions after the value still parse.
func TestParse_EscapedDoubleQuotedMsgSurvives(t *testing.T) {
	p := NewParser()
	line := `SecRule ARGS "@streq attack" "id:1001,phase:2,deny,msg:\"blocked: x, see docs\",status:403"`
	rules, err := p.ParseFile(line + "\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	r := rules[0]
	if want := `\"blocked: x, see docs\"`; r.Actions.Msg != want {
		t.Fatalf("Msg = %q, want %q — escaped-double-quoted value split at the embedded comma", r.Actions.Msg, want)
	}
	if r.Actions.Status != 403 {
		t.Fatalf("Status = %d, want 403 — action after the value was lost to a stray token", r.Actions.Status)
	}
	if r.Actions.Action != "deny" {
		t.Fatalf("Action = %q, want deny", r.Actions.Action)
	}
}
