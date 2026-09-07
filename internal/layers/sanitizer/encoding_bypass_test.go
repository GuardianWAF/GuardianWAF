package sanitizer

import (
	"strings"
	"testing"
)

// TestNormalizeAll_LayeredEncodingReachesFixedPoint pins the fix for an
// encoding-order bypass.
//
// The chain decoded in a fixed order — URL first, HTML entities fifth — so any
// encoding that *produces* an earlier layer's syntax survived. "&#37;" is a
// literal '%', but it was only decoded after URL decoding had finished, so
// "&#37;3Cscript&#37;3E" normalized to "%3Cscript%3E" and stopped. Every
// detector that scans the normalized value therefore never saw "<script>".
func TestNormalizeAll_LayeredEncodingReachesFixedPoint(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"entity-encoded percent then URL", "&#37;3Cscript&#37;3E", "<script>"},
		{"double URL encoded", "%253Cscript%253E", "<script>"},
		{"entity-encoded percent traversal", "&#37;2e&#37;2e&#37;2fetc/passwd", "etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeAll(tt.in); got != tt.want {
				t.Fatalf("NormalizeAll(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDecodeHTMLEntities_RealHTML5Names pins the entity-table fix. The table
// previously contained "tab" and "newl" — neither is an HTML entity — while the
// real "&Tab;" and "&NewLine;", which are exactly what break up "javascript:"
// in an href, were missing and passed through untouched.
func TestDecodeHTMLEntities_RealHTML5Names(t *testing.T) {
	tests := []struct {
		name, in, wantContains string
	}{
		{"Tab splits javascript scheme", "jav&Tab;ascript:alert(1)", "jav ascript:"},
		{"NewLine splits javascript scheme", "jav&NewLine;ascript:alert(1)", "jav ascript:"},
		{"uppercase TAB", "jav&TAB;ascript:alert(1)", "jav ascript:"},
		{"sol is a slash", "..&sol;..&sol;etc", "etc"},
		{"lpar rpar", "alert&lpar;1&rpar;", "alert(1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeAll(tt.in)
			if !strings.Contains(got, tt.wantContains) {
				t.Fatalf("NormalizeAll(%q) = %q, want it to contain %q", tt.in, got, tt.wantContains)
			}
		})
	}
}

// TestNormalizeAll_IsIdempotent guards the fixed-point loop: a second pass over
// already-normalized output must not keep changing it, or the loop would burn
// its full iteration budget on every request.
func TestNormalizeAll_IsIdempotent(t *testing.T) {
	for _, in := range []string{
		"/api/v1/users?id=42",
		"<script>alert(1)</script>",
		"etc/passwd",
		"plain text with spaces",
		"100% sure",
	} {
		t.Run(in, func(t *testing.T) {
			once := NormalizeAll(in)
			twice := NormalizeAll(once)
			if once != twice {
				t.Fatalf("not idempotent: NormalizeAll(%q) = %q, then %q", in, once, twice)
			}
		})
	}
}
