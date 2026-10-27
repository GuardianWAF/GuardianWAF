package cmdi

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-10-21): the CMDi detector built Finding.MatchedValue
// — attacker-controlled request content that is stored verbatim in events, the
// dashboard and SIEM exports — by byte-slicing the request input.
//
// The engine states the contract for this field (engine/finding.go):
// "The cut point never splits a multi-byte UTF-8 rune: MatchedValue carries
// attacker-controlled request content that is frequently multi-byte, and a
// byte-slice at an arbitrary offset would store an invalid final rune in the
// evidence that flows into events, the dashboard, and traces."
//
// The sibling detectors honour it (xxe/extract_context_rune_test.go,
// ssrf/extract_context_rune_test.go, sqli/truncation_utf8_test.go,
// xss/truncation_utf8_test.go) and the engine exports TruncateEvidence for it.
// CMDi did not: extractContext cut the 100-byte no-match window and the
// context window edges at raw byte offsets, extractContextAt cut the 197-byte
// limit the same way, and makeFinding cut the matched evidence at
// matched[:197]. A request whose multi-byte character straddled one of those
// offsets produced a finding whose MatchedValue was invalid UTF-8, which
// encoding/json then silently rewrote to U+FFFD — corrupted evidence in the
// stored event.
//
// Both truncation points and both window edges are now rune-safe; the pinned
// ASCII shapes are unchanged.

// euro is a 3-byte rune (E2 82 AC) used to straddle byte-offset cuts.
const euro = "€"

// The production path: a command injection whose separator is preceded by
// multi-byte characters. The window start (idx-20) lands inside the 4th euro
// (10 x euro = 30 bytes, the ";" sits at byte 30, so start = 10 is the 2nd
// byte of a rune).
func TestDetectMatchedValueStaysValidUTF8(t *testing.T) {
	in := strings.Repeat(euro, 10) + ";id"

	findings := Detect(in, "body")
	if len(findings) == 0 {
		t.Fatalf("pre-condition: CMDi produced no finding for %q", in)
	}
	for i, f := range findings {
		if !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("finding[%d].MatchedValue is invalid UTF-8 (window start edge split a rune): %q", i, f.MatchedValue)
		}
	}
}

// The same defect through the detector's Process path — the production entry
// point used by the detection layer — observed in the serialized evidence.
func TestDetectorProcessEvidenceSurvivesJSONRoundTrip(t *testing.T) {
	in := strings.Repeat(euro, 10) + ";id"

	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:     "POST",
		Path:       "/upload",
		BodyString: in,
	}
	result := det.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("pre-condition: CMDi produced no finding for %q", in)
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

// The no-match cut at 100 bytes landed inside a 4-byte rune spanning bytes
// 98-105.
func TestExtractContextNoMatchCutKeepsValidUTF8(t *testing.T) {
	in := strings.Repeat("a", 98) + "\U0001F389\U0001F389" + strings.Repeat("b", 60)
	got := extractContext(in, "notfound")
	if !utf8.ValidString(got) {
		t.Fatalf("no-match cut produced invalid UTF-8: %q", got)
	}
	if len(got) > 100 {
		t.Fatalf("no-match cut exceeded 100 bytes: %d", len(got))
	}
}

// The window end edge (idx+len(pattern)+30) landed inside a rune: "P" sits at
// byte 0, so end = 31 — the 2nd byte of the euro at bytes 30-32.
func TestExtractContextWindowEndEdgeKeepsValidUTF8(t *testing.T) {
	in := "P" + strings.Repeat("a", 29) + euro + strings.Repeat("x", 50)
	got := extractContext(in, "P")
	if !utf8.ValidString(got) {
		t.Fatalf("window end edge produced invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "P") {
		t.Fatal("window lost the matched pattern")
	}
}

// The >200-byte cut of the context window landed inside a rune: the pattern is
// 197 bytes long, so the window spans 197+50 bytes and the 197-byte cut
// falls inside the euro at absolute bytes 195-197.
func TestExtractContextLongWindowCutKeepsValidUTF8(t *testing.T) {
	pattern := strings.Repeat("b", 194) + euro
	in := "P" + pattern + strings.Repeat("c", 50)
	got := extractContext(in, pattern)
	if !utf8.ValidString(got) {
		t.Fatalf("200-byte window cut produced invalid UTF-8: %q", got)
	}
	if len(got) > 200 {
		t.Fatalf("window cut exceeded 200 bytes: %d", len(got))
	}
}

// The pinned ASCII shapes are preserved byte-for-byte.
func TestExtractContextASCIIShapesUnchanged(t *testing.T) {
	findings := Detect(";id", "query")
	if len(findings) == 0 {
		t.Fatal("pre-condition: CMDi produced no finding for \";id\"")
	}
	if findings[0].MatchedValue != ";id" {
		t.Fatalf("ASCII matched value changed: %q", findings[0].MatchedValue)
	}
	if findings[0].Score == 0 {
		t.Fatal("ASCII finding lost its score")
	}

	if got := extractContext("hello world", "notfound"); got != "hello world" {
		t.Fatalf("ASCII no-match shape changed: %q", got)
	}
	long := strings.Repeat("a", 150)
	if got := extractContext(long, "notfound"); len(got) != 100 {
		t.Fatalf("ASCII long no-match length changed: %d", len(got))
	}
}
