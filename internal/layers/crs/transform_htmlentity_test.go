package crs

import "testing"

// Regression: Transform's t:htmlEntityDecode routed to a 5-replacement stub
// (&lt; &gt; &amp; &quot; &#x27;) that missed numeric character references and
// whitespace entities. CRS rules using the transform therefore never fired on
// payloads like "&#x3C;script&#x3E;" or "jav&Tab;ascript:..." — the transform
// left them literal and the operator missed. The stub now delegates to the
// sanitizer's canonical decoder (sanitizer.DecodeHTMLEntities), whose
// coverage includes &#xNN;/&#NNN; numeric references and the &Tab;/&NewLine;
// whitespace entities.

func TestTransformHtmlEntityDecodeNumericAndWhitespaceEntities(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hex numeric reference", "&#x3C;script&#x3E;", "<script>"},
		{"decimal numeric reference", "&#60;script", "<script"},
		{"whitespace named entity", "jav&Tab;ascript:alert(1)", "jav\tascript:alert(1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:htmlEntityDecode"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Controls: previously-working decodes must be preserved by the delegation.
func TestTransformHtmlEntityDecodeControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"named entities", "a &amp; b &lt; c", "a & b < c"},
		{"hex apostrophe", "&#x27;single&#x27;", "'single'"},
		{"plain value passthrough", "no entities", "no entities"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:htmlEntityDecode"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
