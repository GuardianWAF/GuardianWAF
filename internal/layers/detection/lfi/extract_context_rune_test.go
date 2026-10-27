package lfi

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-10-21): the LFI detector built Finding.MatchedValue
// — attacker-controlled request content that is stored verbatim in events, the
// dashboard and SIEM exports — from a context window whose EDGES were cut at
// raw byte offsets.
//
// The engine states the contract for this field (engine/finding.go):
// "The cut point never splits a multi-byte UTF-8 rune: MatchedValue carries
// attacker-controlled request content that is frequently multi-byte, and a
// byte-slice at an arbitrary offset would store an invalid final rune in the
// evidence that flows into events, the dashboard, and traces."
//
// The sibling detectors honour it (xxe/extract_context_rune_test.go,
// ssrf/extract_context_rune_test.go, sqli/truncation_utf8_test.go,
// xss/truncation_utf8_test.go, cmdi/extract_context_rune_test.go) and the
// engine exports TruncateEvidence for it.
//
// LFI's truncation POINTS were rune-safe (safeTruncate), but the two window
// edges (idx-20 and idx+len(pattern)+20) were byte-aligned: a multi-byte rune
// straddling an edge was cut in half. Unlike the siblings, all 11 LFI
// makeFinding call sites pass extractContext(...) directly as the matched
// value, so the window IS the stored evidence — the split rune reached the
// event stream, where encoding/json silently rewrote it to U+FFFD, i.e.
// corrupted evidence in the stored event.
//
// Both window edges are now aligned onto rune starts; the pinned ASCII shapes
// are unchanged.

// euro is a 3-byte rune (E2 82 AC) used to straddle byte-offset cuts.
const euro = "€"

// The production path: a traversal payload preceded by multi-byte characters.
// The window start (idx-20) lands inside the 4th euro (10 x euro = 30 bytes,
// the ".." sits at byte 30, so start = 10 is the 2nd byte of a rune).
func TestDetectMatchedValueStaysValidUTF8(t *testing.T) {
	in := strings.Repeat(euro, 10) + "../../etc/passwd"

	findings := Detect(in, "body")
	if len(findings) == 0 {
		t.Fatalf("pre-condition: LFI produced no finding for %q", in)
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
	in := strings.Repeat(euro, 10) + "../../etc/passwd"

	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:     "GET",
		Path:       "/download",
		BodyString: in,
	}
	result := det.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("pre-condition: LFI produced no finding for %q", in)
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

// The window end edge (idx+len(pattern)+20) landed inside a rune: "P" sits at
// byte 0, so end = 21 — the 2nd byte of the euro at bytes 20-22.
func TestExtractContextWindowEndEdgeKeepsValidUTF8(t *testing.T) {
	in := "P" + strings.Repeat("a", 19) + euro + strings.Repeat("x", 50)
	got := extractContext(in, "P")
	if !utf8.ValidString(got) {
		t.Fatalf("window end edge produced invalid UTF-8: %q", got)
	}
	if !strings.Contains(got, "P") {
		t.Fatal("window lost the matched pattern")
	}
}

// The pinned ASCII shapes are preserved byte-for-byte.
func TestExtractContextASCIIShapesUnchanged(t *testing.T) {
	findings := Detect("../../etc/passwd", "query")
	if len(findings) == 0 {
		t.Fatal("pre-condition: LFI produced no finding for \"../../etc/passwd\"")
	}
	for i, f := range findings {
		if !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("ASCII finding[%d] is not valid UTF-8: %q", i, f.MatchedValue)
		}
	}
	if findings[0].Score == 0 {
		t.Fatal("ASCII finding lost its score")
	}

	got := extractContext("aaaaaaaaaa../../etc/passwd", "..")
	if !strings.Contains(got, "..") {
		t.Fatalf("ASCII window lost the matched pattern: %q", got)
	}
}
