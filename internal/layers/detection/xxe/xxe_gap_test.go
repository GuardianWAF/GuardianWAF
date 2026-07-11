package xxe

import "testing"

func TestDetectorOrder(t *testing.T) {
	if got := NewDetector(true, 1).Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
}
