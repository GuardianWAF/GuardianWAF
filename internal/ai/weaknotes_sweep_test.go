package ai

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Regression (the catalog-closure weak note, mirroring the engine's round-76
// truncateEvidence fix): truncate byte-sliced s[:maxLen] without checking
// rune boundaries — a multi-byte rune straddling the cut put an invalid
// UTF-8 sequence into the AI prompt.
func TestTruncateKeepsValidUTF8(t *testing.T) {
	// U+1F389 is 4 bytes starting at index 2: a cut at 4 slices it mid-rune.
	s := "ab🎉cd"
	got := truncate(s, 4)
	if !utf8.ValidString(got) {
		t.Fatalf("FAIL: truncate produced invalid UTF-8 (%q) — the cut split a multi-byte rune", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("FAIL: truncated result %q lost the ellipsis", got)
	}

	// Validity sweep across rune widths and cut points (the round-76
	// TestTruncateEvidenceValidUTF8 pattern).
	for _, payload := range []string{"ab🎉cd", "héllo wörld", "日本語のテスト", "a🎉b€c😀d"} {
		for _, maxLen := range []int{1, 2, 3, 4, 5, 7, 10, 16} {
			if got := truncate(payload, maxLen); !utf8.ValidString(got) {
				t.Fatalf("FAIL: truncate(%q, %d) produced invalid UTF-8 (%q)", payload, maxLen, got)
			}
		}
	}
}

// The usage day is the UTC day: DailyResetAt must be the next UTC midnight
// regardless of the server's local zone, so quotas roll identically across
// deployments. TrackUsage's roll-over now states that explicitly.
func TestUsageDayResetAtIsUTCMidnight(t *testing.T) {
	s := NewStore(t.TempDir() + "/usage-test.json")

	s.TrackUsage(5)
	now := time.Now()
	want := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)

	usage := s.GetUsage()
	if !usage.DayResetAt.Equal(want) {
		t.Fatalf("FAIL: DayResetAt = %v, want the next UTC midnight %v — the usage day must be the UTC day", usage.DayResetAt, want)
	}
}
