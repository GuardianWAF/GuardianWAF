package openredirect

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression (round 2026-10-21): the open-redirect detector built
// Finding.MatchedValue — the redirect target straight from the request,
// attacker-controlled and stored verbatim in events, the dashboard and SIEM
// exports — with a raw byte slice.
//
// The engine states the contract for this field (engine/finding.go):
// "The cut point never splits a multi-byte UTF-8 rune: MatchedValue carries
// attacker-controlled request content that is frequently multi-byte, and a
// byte-slice at an arbitrary offset would store an invalid final rune in the
// evidence that flows into events, the dashboard, and traces."
//
// The sibling detectors honour it (xxe/extract_context_rune_test.go,
// ssrf/extract_context_rune_test.go, sqli/truncation_utf8_test.go,
// xss/truncation_utf8_test.go, cmdi/extract_context_rune_test.go,
// lfi/extract_context_rune_test.go) and the engine exports TruncateEvidence
// for it.
//
// The open-redirect detector did not: its local truncate helper cut with
// s[:maxLen-3] + "...", so a multi-byte character straddling that offset was
// cut in half. The truncated value is the redirect parameter itself, so the
// split rune reached the event stream, where encoding/json silently rewrote
// it to U+FFFD — corrupted evidence in the stored event.
//
// The cut is now rune-safe via the shared engine.TruncateEvidence; the pinned
// ASCII shapes are unchanged.

// euro is a 3-byte rune (E2 82 AC) used to straddle the byte-offset cut.
const euro = "€"

// redirectTarget is a protocol-relative redirect target long enough to be
// truncated, with the euro placed so that byte 197 of the value falls inside
// it: "//evil.com/" is 11 bytes, 184 filler bytes follow, and the euro
// occupies bytes 195-197.
func redirectTarget() string {
	return "//evil.com/" + strings.Repeat("a", 184) + euro + strings.Repeat("b", 20)
}

// The production path — a redirect parameter on the request.
func TestMatchedValueStaysValidUTF8(t *testing.T) {
	val := redirectTarget()
	ctx := makeCtx("example.com", "redirect="+url.QueryEscape(val), nil)

	result := NewDetector(true, 1.0).Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("pre-condition: open-redirect produced no finding for a protocol-relative target")
	}
	for i, f := range result.Findings {
		if !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("finding[%d].MatchedValue is invalid UTF-8 (the 197-byte cut split a rune): %q", i, f.MatchedValue)
		}
	}
}

// The same defect observed in the serialized evidence — encoding/json replaces
// invalid UTF-8 with U+FFFD, so the stored evidence is corrupted.
func TestEvidenceSurvivesJSONRoundTrip(t *testing.T) {
	val := redirectTarget()
	ctx := makeCtx("example.com", "redirect="+url.QueryEscape(val), nil)

	result := NewDetector(true, 1.0).Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("pre-condition: open-redirect produced no finding for a protocol-relative target")
	}
	for i, f := range result.Findings {
		if !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("finding[%d].MatchedValue is invalid UTF-8: %q", i, f.MatchedValue)
		}
		blob, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshalling finding: %v", err)
		}
		// engine.Severity marshals to a string but has no UnmarshalJSON, so the
		// round-trip is checked on the generic shape: the stored matched_value
		// must equal the value the detector produced.
		var round map[string]any
		if err := json.Unmarshal(blob, &round); err != nil {
			t.Fatalf("unmarshalling finding: %v", err)
		}
		stored, _ := round["matched_value"].(string)
		if stored != f.MatchedValue {
			t.Fatalf("evidence corrupted by serialization: stored %q, original %q", stored, f.MatchedValue)
		}
	}
}

// The helper itself — the cut lands inside a multi-byte rune. The euro
// occupies bytes 195-197, so the cut at 197 keeps its first two bytes and
// drops the third.
func TestTruncateKeepsValidUTF8(t *testing.T) {
	in := strings.Repeat("a", 195) + euro + strings.Repeat("b", 20)
	got := truncate(in, 200)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if len(got) > 200 {
		t.Fatalf("truncate exceeded 200 bytes: %d", len(got))
	}
}

// The pinned ASCII shapes are preserved byte-for-byte.
func TestTruncateASCIIShapesUnchanged(t *testing.T) {
	// A short value is stored whole.
	ctx := makeCtx("example.com", "redirect="+url.QueryEscape("//evil.com/x"), nil)
	result := NewDetector(true, 1.0).Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("pre-condition: open-redirect produced no finding")
	}
	if got := result.Findings[0].MatchedValue; got != "//evil.com/x" {
		t.Fatalf("ASCII matched value changed: %q", got)
	}

	// A long ASCII value keeps the "..." suffix and the 200-byte cap.
	long := "//evil.com/" + strings.Repeat("a", 300)
	ctx2 := makeCtx("example.com", "redirect="+url.QueryEscape(long), nil)
	result2 := NewDetector(true, 1.0).Process(ctx2)
	if len(result2.Findings) == 0 {
		t.Fatal("pre-condition: open-redirect produced no finding for the long value")
	}
	got := result2.Findings[0].MatchedValue
	if len(got) != 200 || !strings.HasSuffix(got, "...") {
		t.Fatalf("ASCII long matched value shape changed: len=%d suffix=%v", len(got), strings.HasSuffix(got, "..."))
	}
}
