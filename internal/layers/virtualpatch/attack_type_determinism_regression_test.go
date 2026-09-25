package virtualpatch

// Regression (round 2026-09-24-s3r1-attacktype-nondet): detectAttackType
// selected the attack type by iterating a MAP — map iteration order is random
// per run, so a CVE description matching several attack types (SQLi->RCE
// chains are common in CVE text) produced a different enforcement pattern set
// on every feed refresh. The selection is now a fixed priority slice
// (first-match-wins in the documented order).

import (
	"reflect"
	"testing"
)

func TestAttackTypeSelectionDeterministic(t *testing.T) {
	g := NewGenerator()

	// A description matching TWO attack types — the extremely common
	// SQLi->RCE chain shape in real CVE descriptions.
	cve := &CVEEntry{
		CVEID:       "CVE-2024-9999",
		Description: "SQL injection vulnerability in the admin console allowing remote code execution",
		CWEs:        []string{"CWE-89"},
		CVSSScore:   9.8,
		Severity:    "CRITICAL",
	}

	patch := g.Generate(cve)
	if patch == nil {
		t.Fatal("FAIL: Generate returned nil for a qualifying CVE")
	}
	if patch.Patterns == nil {
		t.Fatal("FAIL: generated patch has no patterns")
	}

	// The priority order must make the selection deterministic: the sqli
	// entry precedes rce, so a description matching both resolves to sqli.
	want := []PatchPattern{
		{Type: "query", Pattern: "(union|select|insert|update|delete|drop|create|alter|exec|execute)", MatchType: "regex"},
		{Type: "body", Pattern: "(union|select|insert|update|delete|drop|create|alter|exec|execute)", MatchType: "regex"},
	}
	if !reflect.DeepEqual(patch.Patterns, want) {
		t.Fatalf("FAIL: attack-type selection is not deterministic (want the sqli pattern set, got %v)", patch.Patterns)
	}

	// Repeated generation must be stable (the feed-refresh invariant).
	for i := 0; i < 20; i++ {
		again := g.Generate(cve)
		if again == nil || !reflect.DeepEqual(patch.Patterns, again.Patterns) {
			t.Fatalf("FAIL: generation %d diverged from the first — attack-type selection is nondeterministic", i)
		}
	}
}
