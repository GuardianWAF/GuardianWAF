package sanitizer

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression for F165: block_null_bytes missed %u0000, the IIS-style escape
// decodeURLOnce itself decodes to NUL, so the one spelling the normalizer
// treated as a null byte bypassed the validator's null-byte block.
func TestContainsNullByte_UnicodeEscape(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"/f%u0000.jpg", true},
		{"/f%U0000.jpg", true},
		{"/%u0000", true},
		{"/%u000", false},
		{"/%u0001", false},
		{"/plain", false},
	} {
		if got := containsNullByte(tc.in); got != tc.want {
			t.Errorf("containsNullByte(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	ctx := &engine.RequestContext{Method: "GET", URI: "/d?f=../../etc/passwd%u0000.jpg", Headers: map[string][]string{}}
	if len(ValidateRequest(ctx, Config{BlockNullBytes: true})) == 0 {
		t.Fatal("%u0000 in the URI must produce a null-byte finding")
	}
}

// Regression for F166: only digits, letters and U+FF01-FF0F of the fullwidth
// ASCII block were mapped, so fullwidth < > ; = [ ] { } etc. survived and
// "\uFF1Cscript\uFF1E" never reached the detectors as "<script>".
func TestNormalizeUnicode_FullFullwidthBlock(t *testing.T) {
	var in, want []rune
	for r := rune(0xFF01); r <= 0xFF5E; r++ {
		in = append(in, r)
		want = append(want, r-0xFF01+'!')
	}
	if got := NormalizeUnicode(string(in)); got != string(want) {
		t.Fatalf("NormalizeUnicode(U+FF01..FF5E) = %q, want %q", got, string(want))
	}
	if got := NormalizeUnicode("\uFF00\uFF5F"); got != "\uFF00\uFF5F" {
		t.Fatalf("runes outside the block must be unchanged, got %q", got)
	}
	if got := NormalizeAll("\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E"); got != "<script>alert(1)</script>" {
		t.Fatalf("NormalizeAll(fullwidth <script>) = %q", got)
	}
}
