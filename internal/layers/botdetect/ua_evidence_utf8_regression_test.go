package botdetect

// Regression: User-Agent finding evidence must never be stored as invalid UTF-8.
//
// truncateUA previously built Finding.MatchedValue with a raw byte slice
// (`ua[:maxLen-3] + "..."`). analyzeUA feeds it a fully attacker-controlled,
// unbounded User-Agent header, so a multi-byte rune straddling the cut was
// stored split. The engine's canonical re-truncation in ScoreAccumulator.Add
// could not repair it: TruncateEvidence returns early once len(s) <= maxLen,
// and maxLen-3 + len("...") == maxLen, so the repair was a no-op and the
// corruption propagated into events, the dashboard, and traces.
//
// This is the same defect fixed in the sibling detectors by commits 8636fbd
// (xss) and f2ee65f (sqli); the invariant is stated at engine/finding.go:52.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// multibyteRuneWidths covers every UTF-8 rune length, so a regression at any
// alignment relative to the cut is caught, not just the 2-byte case.
var multibyteRuneWidths = map[string]string{
	"2-byte (é)":       "é",
	"3-byte (€)":       "€",
	"4-byte (𝄞)":       "𝄞",
	"2-byte (界 CJK)":   "界",
	"3-byte (→ arrow)": "→",
}

// TestTruncateUANeverSplitsRunes is the exact trigger from the proof.
func TestTruncateUANeverSplitsRunes(t *testing.T) {
	// A high-scoring scanner UA padded so the cut lands inside a rune.
	ua := "sqlmap/1.7" + strings.Repeat("é", 200)

	got := truncateUA(ua, 200)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateUA returned invalid UTF-8 for a %d-byte User-Agent "+
			"(len=%d): %q", len(ua), len(got), got)
	}
	if len(got) > 200 {
		t.Errorf("truncateUA returned %d bytes, exceeds the 200-byte limit", len(got))
	}
}

// TestTruncateUAMultibyteWidths sweeps rune widths and cut alignments.
func TestTruncateUAMultibyteWidths(t *testing.T) {
	for name, r := range multibyteRuneWidths {
		t.Run(name, func(t *testing.T) {
			// Vary the offset so the cut lands at every phase of the rune.
			for _, pad := range []int{94, 95, 96, 97, 98, 99, 100, 101} {
				ua := "sqlmap/1.7" + strings.Repeat(r, pad)
				got := truncateUA(ua, 200)
				if !utf8.ValidString(got) {
					t.Fatalf("pad=%d (%s, ua len %d): invalid UTF-8, len=%d: %q",
						pad, name, len(ua), len(got), got)
				}
			}
		})
	}
}

// TestTruncateUAThroughAccumulator pins the end-to-end contract: whatever
// ScoreAccumulator.Add publishes must be valid UTF-8. This is the site that
// made the defect durable — the canonical re-truncation is a no-op at exactly
// maxLen bytes, so a detector-side split is never repaired downstream.
func TestTruncateUAThroughAccumulator(t *testing.T) {
	for name, r := range multibyteRuneWidths {
		t.Run(name, func(t *testing.T) {
			ua := "sqlmap/1.7" + strings.Repeat(r, 200)

			f := engine.Finding{
				DetectorName: "botdetect-ua",
				Category:     "bot",
				Severity:     engine.SeverityHigh,
				Score:        85,
				MatchedValue: truncateUA(ua, 200),
			}
			acc := &engine.ScoreAccumulator{}
			acc.Add(&f)

			if !utf8.ValidString(f.MatchedValue) {
				t.Fatalf("Finding.MatchedValue is invalid UTF-8 after "+
					"ScoreAccumulator.Add (%s, len=%d)", name, len(f.MatchedValue))
			}
		})
	}
}

// TestTruncateUAShortUnchanged is the control: inputs at or under the limit
// pass through byte-for-byte, so the rune-safe walk changes nothing for the
// overwhelmingly common ASCII case.
func TestTruncateUAShortUnchanged(t *testing.T) {
	for _, ua := range []string{
		"",
		"sqlmap/1.7",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		strings.Repeat("a", 200),      // exactly at the limit
		strings.Repeat("a", 199),      // one under
		strings.Repeat("é", 99) + "x", // exactly 199 bytes, multibyte but under
	} {
		if got := truncateUA(ua, 200); got != ua {
			t.Errorf("truncateUA(%q) = %q, want it unchanged", ua, got)
		}
	}
}

// TestTruncateUADegenerateLimits covers the small-limit branches the old
// hand-rolled version handled separately (maxLen <= 3).
func TestTruncateUADegenerateLimits(t *testing.T) {
	for _, maxLen := range []int{0, 1, 2, 3, 4} {
		got := truncateUA(strings.Repeat("𝄞", 50), maxLen)
		if !utf8.ValidString(got) {
			t.Errorf("truncateUA(4-byte runes, maxLen=%d) = %q: invalid UTF-8", maxLen, got)
		}
		if len(got) > maxLen {
			t.Errorf("truncateUA(maxLen=%d) returned %d bytes: %q", maxLen, len(got), got)
		}
	}
}
