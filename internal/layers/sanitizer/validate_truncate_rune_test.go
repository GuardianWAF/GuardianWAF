package sanitizer

import (
	"net"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 20/25, 2026-09-25): the sanitizer's local truncate
// byte-sliced MatchedValue at the 200-byte cut without checking rune
// boundaries — the same contract violation engine/finding.go's round-76
// truncateEvidence fix eliminated in the engine's copy. Multi-byte content
// crossing the cut stored an invalid final rune in evidence that flows into
// events, the dashboard, and traces (ScoreAccumulator.Add's re-truncation is
// a no-op for <=200-byte strings, so the corruption survived). The local
// helper now delegates to the canonical engine.TruncateEvidence; these tests
// pin valid UTF-8 on every MatchedValue path ValidateRequest can produce.

// multiByteOverCut returns s prefixed to 196 ASCII bytes so a 4-byte emoji
// spans bytes 197-200 — the cut lands inside the rune.
func multiByteOverCut(pad string) string {
	return strings.Repeat(pad, 196) + "\U0001F389" + strings.Repeat("x", 60)
}

func assertFindingsValidUTF8(t *testing.T, findings []engine.Finding) {
	t.Helper()
	for _, f := range findings {
		if f.MatchedValue != "" && !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("MatchedValue contains invalid UTF-8 (truncation split a multi-byte rune): %q", f.MatchedValue)
		}
	}
}

func TestValidateURIFindingTruncateValidUTF8(t *testing.T) {
	cfg := Config{MaxURLLength: 100}
	ctx := &engine.RequestContext{
		Method: "GET",
		URI:    multiByteOverCut("a"),
		Path:   "/x",
	}
	findings := ValidateRequest(ctx, cfg)
	if len(findings) == 0 {
		t.Fatal("expected the URL-length finding to fire")
	}
	assertFindingsValidUTF8(t, findings)
}

func TestValidateCookieFindingTruncateValidUTF8(t *testing.T) {
	cfg := Config{MaxCookieSize: 10}
	ctx := &engine.RequestContext{
		Method:   "GET",
		Cookies:  map[string][]string{"session": {multiByteOverCut("c")}},
		ClientIP: net.ParseIP("192.0.2.7"),
	}
	findings := ValidateRequest(ctx, cfg)
	if len(findings) == 0 {
		t.Fatal("expected the cookie-size finding to fire")
	}
	assertFindingsValidUTF8(t, findings)
}

func TestValidateNullByteFindingsTruncateValidUTF8(t *testing.T) {
	cfg := Config{BlockNullBytes: true}
	// Triggers: containsNullByte covers literal NUL and %00 (the '\0'
	// backslash-zero spelling is deliberately not checked here — the
	// round-14 divergence note). Each MatchedValue still carries the
	// multi-byte emoji spanning the 200-byte cut.
	ctx := &engine.RequestContext{
		Method:     "GET",
		URI:        multiByteOverCut("a") + "\x00",
		BodyString: multiByteOverCut("d") + "%00",
		Headers: map[string][]string{
			"User-Agent": {multiByteOverCut("u") + "%00"},
		},
	}
	findings := ValidateRequest(ctx, cfg)
	if len(findings) < 3 {
		t.Fatalf("expected URI/header/body null-byte findings, got %d", len(findings))
	}
	assertFindingsValidUTF8(t, findings)

	// The full evidence path: the accumulator's re-truncation must stay a
	// no-op for <=200-byte MatchedValues, not repair or worsen them.
	acc := engine.NewScoreAccumulator(2)
	for i := range findings {
		acc.Add(&findings[i])
	}
	assertFindingsValidUTF8(t, acc.Findings())
}

// The ASCII pre-fix shape is preserved byte-for-byte.
func TestTruncateASCIIShapeUnchanged(t *testing.T) {
	long := strings.Repeat("a", 250)
	if got := truncate(long, 200); got != strings.Repeat("a", 197)+"..." {
		t.Fatalf("ASCII truncate shape changed: got %d bytes", len(got))
	}
	if got := truncate("short", 200); got != "short" {
		t.Fatalf("short input changed: %q", got)
	}
}
