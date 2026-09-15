package crs

import "testing"

// TestEvaluateUrlEncoding pins the validateUrlEncoding SecLang contract: the
// operator MATCHES when the value contains invalid URL encoding (incomplete
// escapes, non-hex digits, signed digits) and does NOT match well-formed or
// escape-free values — the polarity the CRS layer's matched->block chain
// requires. Regression: signed hex pairs like %-1/%+5 were accepted because
// strconv.ParseInt with base 16 still honours a leading sign, so those
// invalid escapes slipped past the violation scan.
func TestEvaluateUrlEncoding(t *testing.T) {
	oe := &OperatorEvaluator{}
	cases := []struct {
		name    string
		value   string
		violate bool // true = invalid encoding present (operator matches)
	}{
		{"plain text", "plain text", false},
		{"valid uppercase hex", "a=1%2Bb", false},
		{"valid lowercase hex", "%c4%8d", false},
		{"incomplete trailing percent", "100%", true},
		{"non-hex digits", "%%zz", true},
		{"non-hex word", "abc%qux", true},
		{"signed hex digit dash", "%-1", true},
		{"signed hex digit plus", "%+5", true},
	}
	for _, tc := range cases {
		got, err := oe.evaluateUrlEncoding(tc.value)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if got != tc.violate {
			t.Errorf("%s: evaluateUrlEncoding(%q) = %v, want %v", tc.name, tc.value, got, tc.violate)
		}
	}
}
