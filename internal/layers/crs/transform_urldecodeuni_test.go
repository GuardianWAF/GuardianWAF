package crs

import "testing"

// Regression: Transform had no case for t:urlDecodeUni — a standard
// ModSecurity transform (URL decode including the legacy %uXXXX UTF-16
// percent-encoding) used throughout the OWASP Core Rule Set. Unknown names
// fell through the dispatch switch as a silent no-op, so CRS rules using
// t:urlDecodeUni never decoded "%u003Cscript"-style payloads and the
// operator missed. The transform now decodes %XX plus %uXXXX (surrogate
// pairs combine into astral code points); invalid sequences stay literal.
func TestTransformUrlDecodeUni(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"%uXXXX form of a detection payload", "%u003Cscript%u003E", "<script>"},
		{"UTF-16 surrogate pair combines", "%ud83d%ude00", "\U0001F600"},
		{"mixed %uXXXX and %XX forms", "%u0041%42", "AB"},
		{"unpaired surrogate decodes to replacement", "%ud83d", "\uFFFD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:urlDecodeUni"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Controls: adjacent behavior must be preserved — plain urlDecode, malformed
// sequences, the uppercase %U form (the IE legacy form is lowercase u), and
// genuinely unknown transform passthrough.
func TestTransformUrlDecodeUniControlsUnchanged(t *testing.T) {
	cases := []struct {
		name         string
		transform    string
		in           string
		want         string
	}{
		{"plain urlDecode unaffected", "t:urlDecode", "%20", " "},
		{"malformed %uZZZZ stays literal", "t:urlDecodeUni", "%uZZZZ", "%uZZZZ"},
		{"truncated %u00 stays literal", "t:urlDecodeUni", "%u00", "%u00"},
		{"uppercase %U stays literal", "t:urlDecodeUni", "%U0041", "%U0041"},
		{"unknown transform passthrough", "unknownTransform", "hi", "hi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{tc.transform}); got != tc.want {
				t.Fatalf("Transform(%q, %q) = %q, want %q", tc.in, tc.transform, got, tc.want)
			}
		})
	}
}
