package crs

import "testing"

// Regression: urlEncode was implemented as strings.ReplaceAll(s, " ",
// "%20") — every other byte passed through raw. ModSecurity's t:urlEncode
// percent-encodes ALL bytes outside the RFC 3986 unreserved set
// (alphanumerics, '-', '.', '_', '~') using uppercase hex, so reserved
// characters ('/', '"', '%', '<', '!') and non-ASCII bytes now encode.
func TestTransformUrlEncodeReservedAndNonASCII(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"reserved '!' encoded", "hello world!", "hello%20world%21"},
		{"slash and percent encoded", "a/b%20c", "a%2Fb%2520c"},
		{"non-ASCII per UTF-8 byte", "café", "caf%C3%A9"},
		{"quotes and angle brackets", `say "hi" <x>`, `say%20%22hi%22%20%3Cx%3E`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:urlEncode"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Controls: unreserved characters stay raw (RFC 3986 set), plain spaces keep
// the existing %20 form, and empty values stay empty.
func TestTransformUrlEncodeControlsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"space still encodes to %20", "a b", "a%20b"},
		{"RFC 3986 unreserved set stays raw", "safe-._~9x", "safe-._~9x"},
		{"empty value stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Transform(tc.in, []string{"t:urlEncode"}); got != tc.want {
				t.Fatalf("Transform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
