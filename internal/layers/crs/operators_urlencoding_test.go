package crs

import "testing"

// TestEvaluateUrlEncoding pins the validateUrlEncoding contract: the operator
// returns TRUE only for well-formed URL encoding, FALSE for any violation
// (incomplete escapes, non-hex digits, signed digits). Regression: signed
// hex pairs like %-1/%+5 were accepted because strconv.ParseInt with base 16
// still honours a leading sign, so invalid escapes passed as valid and
// CRS rules relying on the operator never fired.
func TestEvaluateUrlEncoding(t *testing.T) {
	oe := &OperatorEvaluator{}
	cases := []struct {
		name  string
		value string
		valid bool // true = well-formed encoding (no match); false = violation (match)
	}{
		{"plain text", "plain text", true},
		{"valid uppercase hex", "a=1%2Bb", true},
		{"valid lowercase hex", "%c4%8d", true},
		{"incomplete trailing percent", "100%", false},
		{"non-hex digits", "%%zz", false},
		{"non-hex word", "abc%qux", false},
		{"signed hex digit dash", "%-1", false},
		{"signed hex digit plus", "%+5", false},
	}
	for _, tc := range cases {
		got, err := oe.evaluateUrlEncoding(tc.value)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.valid {
			t.Errorf("%s: evaluateUrlEncoding(%q) = %v, want %v", tc.name, tc.value, got, tc.valid)
		}
	}
}
