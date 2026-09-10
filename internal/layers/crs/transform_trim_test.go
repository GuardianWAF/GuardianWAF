package crs

import "testing"

// Regression: Transform's t:trim case used strings.TrimSpace, which trims the
// FULL Unicode whitespace set — NBSP (U+00A0), NEL (U+0085), en/em spaces
// (U+2000-U+200A), and more — while ModSecurity's t:trim removes only the
// C-locale whitespace set (space, \t, \n, \v, \f, \r) from the ends. Values
// with Unicode whitespace at the edges were silently corrupted across a
// transform cycle ("\u00a0secret\u00a0" collapsed to "secret"). t:trim now
// trims exactly the C-locale set, matching removeWhitespace (round 9).
func TestTransformTrimCLocaleSet(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"leading/trailing NBSP preserved", "\u00a0secret\u00a0", "\u00a0secret\u00a0"},
		{"C-locale space trimmed, NBSP edges kept", " \u00a0x\u00a0", "\u00a0x\u00a0"},
		{"em space (U+2003) preserved", "\u2003wide\u2003", "\u2003wide\u2003"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:trim"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Controls: C-locale whitespace is still trimmed at the ends (including the
// \v and \f members added to the engine's whitespace definition in round 9),
// plain values pass through, and mid-string Unicode whitespace is untouched.
func TestTransformTrimControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"C-locale spaces trimmed", "  hi  ", "hi"},
		{"full C-locale set trimmed at ends", "\t hi \n\v\f\r", "hi"},
		{"plain value unchanged", "plain", "plain"},
		{"mid-string NBSP untouched", "a\u00a0b", "a\u00a0b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:trim"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
