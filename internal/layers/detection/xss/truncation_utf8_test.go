package xss

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// The XSS detector builds Finding.MatchedValue from attacker-controlled input.
// It previously truncated with a raw byte slice (`s[:197] + "..."`), which
// split any multi-byte rune straddling the cut and stored an invalid UTF-8
// sequence in the evidence that flows into events, the dashboard, and traces.
//
// The engine's canonical TruncateEvidence is rune-safe and is applied in
// ScoreAccumulator.Add — but it returns early once the string is <= 200 bytes,
// and the byte-slice truncation lands at exactly 200 (197 + "..."), so the
// engine re-truncation was a no-op and the corruption survived.
//
// Sibling detectors were already fixed for this exact defect: engine/finding.go,
// xxe.go, ai/analyzer.go, LFI (safeTruncate), ssrf (extractContext), and
// sanitizer/validate.go. The XSS detector was missed.

// evi builds a string whose 3-byte '€' (U+20AC) rune straddles the 197-byte
// cut, so a naive `s[:197]` keeps a 2-byte fragment and drops the last byte.
func evi(prefix, suffix string) string {
	var b strings.Builder
	b.WriteString(strings.Repeat(prefix, 195)) // bytes [0..194]
	b.WriteRune('€')                           // bytes 195,196,197
	b.WriteString(strings.Repeat(suffix, 10))
	return b.String()
}

func TestTruncateMatch_KeepsValidUTF8(t *testing.T) {
	// Control: ASCII over the limit still truncates to the same shape.
	const ascii = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	got := truncateMatch(ascii)
	if !utf8.ValidString(got) {
		t.Fatalf("CONTROL BROKEN: ASCII truncation produced invalid UTF-8")
	}
	if got != ascii[:197]+"..." {
		t.Fatalf("CONTROL BROKEN: ASCII truncation shape changed: %q", got)
	}

	if g := truncateMatch(evi("a", "b")); !utf8.ValidString(g) {
		t.Errorf("FAIL: truncateMatch split the rune on the cut boundary (ends %x)", g[len(g)-6:])
	}
}

func TestMakeFinding_MatchedValueStaysValidUTF8(t *testing.T) {
	// Control: short ASCII evidence is untouched.
	if f := makeFinding(50, engine.SeverityHigh, "d", "aaa", "query", 1.0); f.MatchedValue != "aaa" {
		t.Fatalf("CONTROL BROKEN: short ASCII evidence was altered: %q", f.MatchedValue)
	}

	f := makeFinding(50, engine.SeverityHigh, "d", evi("x", "y"), "query", 1.0)
	if !utf8.ValidString(f.MatchedValue) {
		t.Errorf("FAIL: makeFinding stored invalid UTF-8 in MatchedValue (ends %x)",
			f.MatchedValue[len(f.MatchedValue)-6:])
	}
}

// Detect is the real production entry point: a genuine XSS payload whose
// evidence crosses the 200-byte cut with a multi-byte rune on the boundary.
func TestDetect_FindingMatchedValueIsValidUTF8(t *testing.T) {
	var b strings.Builder
	b.WriteString("<script>alert(1)</script>")
	b.WriteString(strings.Repeat("a", 170))
	b.WriteRune('€')
	b.WriteString(strings.Repeat("b", 20))

	fs := Detect(b.String(), "query")
	if len(fs) == 0 {
		t.Fatalf("CONTROL BROKEN: the XSS payload produced no findings")
	}
	for _, f := range fs {
		if !utf8.ValidString(f.MatchedValue) {
			t.Errorf("FAIL: finding %q carried invalid UTF-8 in MatchedValue (ends %x)",
				f.Description, f.MatchedValue[len(f.MatchedValue)-6:])
		}
	}
}

// Boundary: the rune must survive when it sits exactly at each end of the cut,
// and truncation must never exceed 200 bytes.
func TestTruncateMatch_RuneAtCutBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		// rune begins one byte before the cut (split by [:197])
		{"split at cut", strings.Repeat("a", 195) + "€" + "b"},
		// rune begins exactly at the cut
		{"starts at cut", strings.Repeat("a", 197) + "€" + "b"},
		// rune ends exactly at the cut
		{"ends at cut", strings.Repeat("a", 194) + "€" + "b"},
	} {
		got := truncateMatch(tc.in)
		if !utf8.ValidString(got) {
			t.Errorf("FAIL (%s): result is invalid UTF-8 (ends %x)", tc.name, got[len(got)-6:])
		}
		if len(got) > 200 {
			t.Errorf("FAIL (%s): result is %d bytes, over the 200-byte cap", tc.name, len(got))
		}
	}
}

// Precision control: an over-limit ASCII string must still be truncated to
// 200 bytes (the fix must not stop truncating entirely).
func TestTruncateMatch_StillTruncatesOverLimit(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := truncateMatch(long)
	if len(got) > 200 {
		t.Fatalf("FAIL: 500-byte input was not truncated (got %d bytes)", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("FAIL: truncated result lost its %q marker: %q", "...", got[len(got)-10:])
	}
}
