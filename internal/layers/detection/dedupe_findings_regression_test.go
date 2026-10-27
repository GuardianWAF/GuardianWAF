package detection

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: the same rule matching an input's raw and normalized views was
// summed, so a 30-point "possible" finding on "O'Connor" scored 60 and blocked.
func TestDedupeFindingsKeepsOnePerRuleAndLocation(t *testing.T) {
	in := []engine.Finding{
		{DetectorName: "sqli", Description: "possible", Location: "body", Score: 30},
		{DetectorName: "sqli", Description: "possible", Location: "body", Score: 35},
		{DetectorName: "sqli", Description: "possible", Location: "query", Score: 30},
		{DetectorName: "sqli", Description: "other", Location: "body", Score: 10},
		{DetectorName: "xss", Description: "possible", Location: "body", Score: 20},
	}
	out := dedupeFindings(in)
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(out), out)
	}
	if out[0].Score != 35 {
		t.Fatalf("duplicate kept score %d, want the higher 35", out[0].Score)
	}
}
