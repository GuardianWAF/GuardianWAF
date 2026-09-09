package dashboard

// Regression: dlpAdapter.TestPattern used strings.Contains on the pattern source —
//
// Defect: dlpAdapter.TestPattern implemented the "test your pattern"
// endpoint as strings.Contains(testData, pattern) — literal containment of
// the pattern SOURCE. A real regex like \d{16} can therefore never match
// unless the sample data contains the backslash-d text itself, so the
// endpoint always reports no-match and operators deploy broken patterns
// believing they were validated.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

func TestDLPTestPatternEvaluatesRegex(t *testing.T) {
	layer := dlp.NewLayer(&dlp.Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn", "iban", "email", "phone", "api_key", "private_key", "passport", "tax_id"},
	})
	adapter := &dlpAdapter{layer: layer}

	// A real regex evaluated against data that MATCHES the regex but does
	// NOT contain the pattern source as a literal substring.
	result := adapter.TestPattern(`\d{16}`, "card 4111111111111111 on file")

	if !result.Matched {
		t.Fatalf("FAIL: TestPattern reported no match for a regex that matches the sample data — the test endpoint uses strings.Contains on the pattern source (literal containment), not regex evaluation, so it can never validate a real pattern")
	}
	if len(result.Matches) == 0 || result.Matches[0] != "4111111111111111" {
		t.Fatalf("FAIL: matches = %v — expected the extracted 16-digit run", result.Matches)
	}
}
