package crs

import "testing"

// Regression: removeWhitespace stripped only space, tab, LF and CR — leaving
// vertical tab (0x0B) and form feed (0x0C) in place. ModSecurity's
// t:removeWhitespace strips the full C-locale whitespace set, so CRS rules
// relying on whitespace removal never saw VT/FF-obfuscated payloads like
// "drop\x0btable" collapse to "droptable".
func TestTransformRemoveWhitespaceCSet(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"vertical tab stripped", "drop\x0btable", "droptable"},
		{"form feed stripped (multiple)", "delete\x0cfrom\x0cusers", "deletefromusers"},
		{"mixed VT/FF run", "union\x0bselect\x0c*\x0bfrom", "unionselect*from"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:removeWhitespace"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Controls: the original set still strips, plain values pass through, NBSP
// is preserved (C-locale set, not unicode.IsSpace), and multibyte content is
// intact apart from the stripped space.
func TestTransformRemoveWhitespaceControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"original set", "a b\tc\nd\re", "abcde"},
		{"plain unchanged", "plain", "plain"},
		{"NBSP preserved", "a\u00a0b", "a\u00a0b"},
		{"multibyte with space stripped", "héllo wörld", "héllowörld"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:removeWhitespace"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
