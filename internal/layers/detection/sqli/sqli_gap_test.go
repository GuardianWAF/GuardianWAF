package sqli

import "testing"

func TestCoverageGaps(t *testing.T) {
	if got := NewDetector(true, 1).Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
	if isSQLishPattern("plain cookie") {
		t.Fatal("plain cookie must not be SQL-ish")
	}

	tokens := Tokenize("/* unterminated")
	if len(tokens) == 0 {
		t.Fatalf("unterminated comment produced no tokens")
	}
	tokens = Tokenize("/*")
	if len(tokens) == 0 {
		t.Fatalf("bare open comment produced no tokens")
	}
	if !containsSQLContent("safe 1=1") {
		t.Fatal("expected tautology to count as SQL content")
	}
	if !containsMultiWordPattern("value OR 1") {
		t.Fatal("expected multi-word SQL pattern")
	}
	if !containsMultiWordPattern("value 1=1") {
		t.Fatal("expected tautology pattern")
	}
}
