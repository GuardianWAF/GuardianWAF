package crs

import (
	"testing"
)

// Regression (round 24/25, 2026-09-25): ARGS_COMBINED_SIZE summed only
// argument VALUES, omitting parameter names. SecLang contract (ModSecurity
// v3 transaction.cc addArgs): m_ARGScombinedSizeDouble += key.length() +
// value.length() — per occurrence, so a repeated parameter counts its name
// each time. The values-only sum undercounted every rule threshold evaluated
// against this variable.

func TestArgsCombinedSizeIncludesNames(t *testing.T) {
	tx := &Transaction{
		RequestArgs: map[string][]string{
			"password": {"x"},    // 8 + 1 = 9
			"a":        {"2222"}, // 1 + 4 = 5
		},
	}
	vr := NewVariableResolver(tx)
	vals, err := vr.Resolve(RuleVariable{Name: "ARGS_COMBINED_SIZE"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "14" {
		t.Fatalf("ARGS_COMBINED_SIZE = %v, want \"14\" (names + values)", vals)
	}
}

// ModSecurity accumulates per addArgs call: a repeated parameter counts its
// name once per occurrence (password=a&password=bc -> (8+1)+(8+2) = 19).
func TestArgsCombinedSizeCountsNamePerOccurrence(t *testing.T) {
	tx := &Transaction{
		RequestArgs: map[string][]string{
			"password": {"a", "bc"},
		},
	}
	vr := NewVariableResolver(tx)
	vals, err := vr.Resolve(RuleVariable{Name: "ARGS_COMBINED_SIZE"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "19" {
		t.Fatalf("ARGS_COMBINED_SIZE = %v, want \"19\" (name counted per occurrence)", vals)
	}
}

func TestArgsCombinedSizeEmpty(t *testing.T) {
	tx := &Transaction{RequestArgs: map[string][]string{}}
	vr := NewVariableResolver(tx)
	vals, err := vr.Resolve(RuleVariable{Name: "ARGS_COMBINED_SIZE"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "0" {
		t.Fatalf("empty args: got %v, want [0]", vals)
	}
}
