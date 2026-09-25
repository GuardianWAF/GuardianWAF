package ssrf

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression (round 21/25, 2026-09-25): extractContext byte-sliced both
// truncation points AND the window edges, so multi-byte runes crossing any
// of them stored invalid UTF-8 in MatchedValue (serialized into JSON event
// streams and SIEM exports). Mirrors the xxe fix landed as commit 10201ce —
// this is the sibling that memory flagged as still unfixed. Both truncation
// points and both window edges are now rune-safe via safeTruncate and the
// edge-alignment loops; every MatchedValue stays valid UTF-8.

// Path A: pattern not found, the 100-byte cut lands inside a 4-byte rune
// spanning bytes 98-105.
func TestExtractContextNoMatchCutValidUTF8(t *testing.T) {
	in := strings.Repeat("a", 98) + "\U0001F389\U0001F389" + strings.Repeat("b", 60)
	got := extractContext(in, "notfound")
	if !utf8.ValidString(got) {
		t.Fatalf("no-match cut produced invalid UTF-8: %q", got)
	}
	if len(got) > 100 {
		t.Fatalf("no-match cut exceeded 100 bytes: %d", len(got))
	}
}

// Path B: pattern found, the window start (idx-20) lands inside a rune
// spanning bytes 17-20 (idx=38, start=18).
func TestExtractContextWindowEdgeValidUTF8(t *testing.T) {
	in := strings.Repeat("a", 17) + "\U0001F389" + strings.Repeat("a", 17) + "P" + strings.Repeat("x", 200)
	got := extractContext(in, "P")
	if !utf8.ValidString(got) {
		t.Fatalf("window edge produced invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "P") {
		t.Fatal("window lost the matched pattern")
	}
}

// The pinned ASCII shapes are preserved byte-for-byte.
func TestExtractContextASCIIShapesUnchanged(t *testing.T) {
	if got := extractContext("hello world", "notfound"); got != "hello world" {
		t.Fatalf("short no-match changed: %q", got)
	}
	long := strings.Repeat("a", 150)
	if got := extractContext(long, "notfound"); len(got) != 100 {
		t.Fatalf("long no-match length changed: %d", len(got))
	}
	in := strings.Repeat("a", 50) + strings.Repeat("b", 200) + strings.Repeat("c", 50)
	got := extractContext(in, strings.Repeat("b", 200))
	if len(got) != 200 || !strings.HasSuffix(got, "...") {
		t.Fatalf("long-window shape changed: len=%d suffixOK=%v", len(got), strings.HasSuffix(got, "..."))
	}
}
