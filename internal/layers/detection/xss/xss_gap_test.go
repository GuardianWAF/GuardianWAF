package xss

import "testing"

func TestCoverageGaps(t *testing.T) {
	if got := NewDetector(true, 1).Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
	for _, input := range []string{"1*2", "1 *2", "1* '2", `1* "2`} {
		if !hasTemplateArithmeticProbe(input) {
			t.Errorf("hasTemplateArithmeticProbe(%q) = false", input)
		}
	}
	if hasTemplateArithmeticProbe("x*2") {
		t.Fatal("non-numeric left operand must not match")
	}
	if hasTemplateArithmeticProbe("*1") {
		t.Fatal("missing left operand must not match")
	}
	if got := codePointRune(0); got != '\uFFFD' {
		t.Fatalf("codePointRune(0) = %U", got)
	}
	if !containsEventHandler("xx onclick=") {
		t.Fatal("expected handler after boundary")
	}
}
