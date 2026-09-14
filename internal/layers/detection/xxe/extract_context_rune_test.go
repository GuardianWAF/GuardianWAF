package xxe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression: extractContext truncated with raw byte slicing, which can cut
// a multi-byte UTF-8 rune in half and emit invalid UTF-8 in Finding
// MatchedValue (serialized into JSON event streams and SIEM exports).
// Mirrors LFI's safeTruncate: truncation backs off to a rune boundary, and
// the context-window edges are aligned onto rune starts.
func TestExtractContext_MultibyteFallbackRuneSafe(t *testing.T) {
	in := strings.Repeat("日", 40) // 120 bytes; a 100-byte cut lands mid-rune
	got := extractContext(in, "absent-pattern")
	if !utf8.ValidString(got) {
		t.Fatalf("FAIL: fallback context is invalid UTF-8: %q", got)
	}
	if len(got) != 99 { // 33 complete 3-byte runes
		t.Fatalf("FAIL: len = %d, want 99 (33 complete runes)", len(got))
	}
}

func TestExtractContext_MultibyteWindowStartRuneSafe(t *testing.T) {
	in := strings.Repeat("日", 34) + "needle" + strings.Repeat("x", 10)
	got := extractContext(in, "needle") // idx-20 lands mid-rune
	if !utf8.ValidString(got) {
		t.Fatalf("FAIL: window context is invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "needle") {
		t.Fatalf("FAIL: window lost the pattern: %q", got)
	}
	if len(got) != 34 { // aligned start drops the partial leading rune
		t.Fatalf("FAIL: len = %d, want 34", len(got))
	}
}

func TestExtractContext_MultibyteTruncationRuneSafe(t *testing.T) {
	pattern := "<!entit" + strings.Repeat("日", 70) // 7 + 210 = 218 bytes
	in := "abc" + pattern + strings.Repeat("日", 50)
	got := extractContext(in, pattern) // result > 200 bytes -> truncate at 197
	if !utf8.ValidString(got) {
		t.Fatalf("FAIL: truncated context is invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("FAIL: missing ellipsis: %q", got)
	}
	if len(got) != 199 { // 196 bytes (backed off to a rune boundary) + "..."
		t.Fatalf("FAIL: len = %d, want 199", len(got))
	}
}
