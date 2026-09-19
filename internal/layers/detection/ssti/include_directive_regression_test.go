package ssti

// Regression (bug-hunt round 2026-09-18-r17, extending the asymmetry-sweep
// family from the round-9/25 sweep note): templateDirectives covered BOTH
// spellings of the Jinja2 import tag ("{% import" and "{%import") but only
// the spaced form of include ("{% include") — the no-space twin "{%include"
// was absent. Jinja2/Twig treat whitespace between "{%" and the tag keyword
// as optional, so {%include "/etc/passwd"%} is valid, executing template
// syntax that produced ZERO findings while its spaced twin scored 70 (High,
// above the default block threshold) — a blocking-path evasion of a declared
// detection, and the same paired-spelling miss as the round-11 UNION
// DISTINCT interlude.

import (
	"strings"
	"testing"
)

func TestDetect_NoSpaceIncludeDirectiveDetected(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		keyword string
	}{
		{"no-space include", `{%include "/etc/passwd"%}`, "include"},
		{"no-space include no-quotes", `{%include "/etc/passwd" %}`, "include"},
	}
	for _, tc := range cases {
		findings := Detect(tc.input, "query")
		found := false
		for _, f := range findings {
			if strings.Contains(f.Description, "directive") && strings.Contains(f.MatchedValue, tc.keyword) {
				found = true
			}
		}
		if !found {
			t.Fatalf("FAIL: %s (%q) produced %d findings, none a directive classification — the no-space include spelling must match like the spaced form (%+v)", tc.name, tc.input, len(findings), findings)
		}
	}
}

// Control: the spaced include keeps firing — the fix must not lose it.
func TestDetect_SpaceIncludeStillDetected(t *testing.T) {
	findings := Detect(`{% include "/etc/passwd"%}`, "query")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "directive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — the spaced include must keep its directive finding, got %+v", findings)
	}
}

// Control: benign template prose with no dangerous directive stays clean —
// plain {{ username }} is neither a gadget, nor a context-object access, nor
// an arithmetic probe.
func TestDetect_BenignTemplateProseClean(t *testing.T) {
	if got := Detect("Hello {{ username }}, welcome back", "query"); len(got) != 0 {
		t.Fatalf("FAIL: benign prose produced findings: %+v", got)
	}
}
