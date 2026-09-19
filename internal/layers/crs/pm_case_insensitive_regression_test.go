package crs

import (
	"testing"
)

// Regression (round 2026-09-16): evaluatePm and evaluatePmFromFile matched
// phrases with case-sensitive strings.Contains. The ModSecurity Reference
// Manual (v2.x Operators) defines @pm as performing "a case-insensitive match
// of the provided phrases against the desired input value" (Aho-Corasick),
// and @pmFromFile matches the same way with phrases read from a file. With
// case-sensitive matching, a mixed-case payload ("SeLeCt UNION") evaded a
// rule like SecRule ARGS "@pm select union" — a silent detection gap on the
// phrase-list rules CRS relies on. @streq remains SecLang string equality
// (case-sensitive).

func TestEvaluatePmCaseInsensitive(t *testing.T) {
	eval := NewOperatorEvaluator()

	got, err := eval.Evaluate(RuleOperator{Type: "@pm", Argument: "select union insert"}, "SeLeCt UNION")
	if err != nil {
		t.Fatalf("Evaluate(@pm): %v", err)
	}
	if !got {
		t.Fatalf("@pm \"select union insert\" did not match \"SeLeCt UNION\" — phrase matching is case-sensitive")
	}
}

func TestEvaluatePmfFallbackCaseInsensitive(t *testing.T) {
	eval := NewOperatorEvaluator()

	// @pmf with an unreadable path falls back to treating the argument as an
	// inline phrase list (the documented fallback, pinned by crs_gap_test).
	got, err := eval.Evaluate(RuleOperator{Type: "@pmf", Argument: "/nonexistent/gw-zzz select union"}, "SeLeCt UNION")
	if err != nil {
		t.Fatalf("Evaluate(@pmf): %v", err)
	}
	if !got {
		t.Fatalf("@pmf inline fallback did not match \"SeLeCt UNION\" — the fallback phrase match is case-sensitive")
	}
}

func TestEvaluatePmControls(t *testing.T) {
	eval := NewOperatorEvaluator()

	// @streq is SecLang string equality — stays case-sensitive.
	got, err := eval.Evaluate(RuleOperator{Type: "@streq", Argument: "select"}, "SeLeCt")
	if err != nil {
		t.Fatalf("Evaluate(@streq): %v", err)
	}
	if got {
		t.Fatalf("@streq became case-insensitive")
	}

	// An absent phrase must stay non-matching.
	got, err = eval.Evaluate(RuleOperator{Type: "@pm", Argument: "insert"}, "SeLeCt UNION")
	if err != nil {
		t.Fatalf("Evaluate(@pm absent): %v", err)
	}
	if got {
		t.Fatalf("@pm matched a phrase that is absent from the value")
	}

	// Lowercase payloads keep matching.
	got, err = eval.Evaluate(RuleOperator{Type: "@pm", Argument: "select union"}, "select union")
	if err != nil {
		t.Fatalf("Evaluate(@pm lowercase): %v", err)
	}
	if !got {
		t.Fatalf("lowercase payload stopped matching")
	}
}
