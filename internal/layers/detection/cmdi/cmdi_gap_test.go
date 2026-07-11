package cmdi

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestCoverageGaps(t *testing.T) {
	d := NewDetector(true, 1)
	if d.Order() != 0 {
		t.Fatalf("Order() = %d, want 0", d.Order())
	}
	result := d.Process(&engine.RequestContext{
		NormalizedHeaders: map[string][]string{"Referer": {"safe", ";id"}},
	})
	if result.Action != engine.ActionLog {
		t.Fatalf("normalized Referer action = %v, want log", result.Action)
	}
}
