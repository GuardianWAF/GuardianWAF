package crs

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 2026-10-21): the CRS layer built Finding.MatchedValue —
// the rule's matched request content, stored verbatim in events, the dashboard
// and SIEM exports — with a raw byte slice.
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
// lfi/extract_context_rune_test.go, openredirect/truncation_utf8_test.go)
// and the engine exports TruncateEvidence for it.
//
// The CRS layer did not: the matched values were joined and cut with
// data[:200], so a multi-byte character straddling that offset was cut in
// half. The matched value is the attacker's own request parameter, so the
// split rune reached the event stream, where encoding/json silently rewrote
// it to U+FFFD — corrupted evidence in the stored event.
//
// The cut is now rune-safe via the shared engine.TruncateEvidence.

// euro is a 3-byte rune (E2 82 AC) used to straddle the byte-offset cut.
const euro = "€"

// crsLayerWithRule builds a CRS layer from a rule file through the same
// config-driven path the serve binary uses.
func crsLayerWithRule(t *testing.T, ruleText string) *Layer {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(path, []byte(ruleText), 0o600); err != nil {
		t.Fatalf("writing rule file: %v", err)
	}
	l := NewLayer(&Config{
		Enabled:          true,
		RulePath:         path,
		ParanoiaLevel:    4,
		AnomalyThreshold: 100,
	})
	if err := l.LoadError(); err != nil {
		t.Fatalf("pre-condition: CRS layer failed to load its rules: %v", err)
	}
	return l
}

// longArgValue is an ARGS value long enough to be truncated, with the euro
// placed so that byte 200 of the value falls inside it: 198 filler bytes
// precede it, so it occupies bytes 198-200 and the cut at 200 keeps its
// first two bytes and drops the third.
func longArgValue() string {
	return strings.Repeat("a", 198) + euro + "evil" + strings.Repeat("b", 20)
}

// crsArgRequest builds a request whose "q" parameter carries value.
func crsArgRequest(value string) *engine.RequestContext {
	req := httptest.NewRequest("GET", "/?"+url.QueryEscape("q")+"="+url.QueryEscape(value), nil)
	return &engine.RequestContext{
		Method:  "GET",
		Path:    "/",
		Request: req,
		Headers: map[string][]string{},
	}
}

// The production path — a CRS rule matching an attacker's parameter.
func TestMatchedValueStaysValidUTF8(t *testing.T) {
	l := crsLayerWithRule(t, `SecRule ARGS "@contains evil" "id:1001,phase:2,deny,msg:'matched',severity:'CRITICAL'"`)

	result := l.Process(crsArgRequest(longArgValue()))
	if len(result.Findings) == 0 {
		t.Fatal("pre-condition: CRS produced no finding for a matched ARGS value")
	}
	for i, f := range result.Findings {
		if !utf8.ValidString(f.MatchedValue) {
			t.Fatalf("finding[%d].MatchedValue is invalid UTF-8 (the 200-byte cut split a rune): %q", i, f.MatchedValue)
		}
	}
}

// The same defect observed in the serialized evidence — encoding/json replaces
// invalid UTF-8 with U+FFFD, so the stored evidence is corrupted.
func TestEvidenceSurvivesJSONRoundTrip(t *testing.T) {
	l := crsLayerWithRule(t, `SecRule ARGS "@contains evil" "id:1001,phase:2,deny,msg:'matched',severity:'CRITICAL'"`)

	result := l.Process(crsArgRequest(longArgValue()))
	if len(result.Findings) == 0 {
		t.Fatal("pre-condition: CRS produced no finding for a matched ARGS value")
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
		// must equal the value the layer produced.
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

// The pinned ASCII shapes are preserved: a long ASCII value is still cut to
// the 200-byte cap and stays valid UTF-8.
func TestASCIIMatchedValueShapeUnchanged(t *testing.T) {
	l := crsLayerWithRule(t, `SecRule ARGS "@contains evil" "id:1001,phase:2,deny,msg:'matched',severity:'CRITICAL'"`)

	val := strings.Repeat("a", 198) + "evil" + strings.Repeat("b", 20)
	result := l.Process(crsArgRequest(val))
	if len(result.Findings) == 0 {
		t.Fatal("pre-condition: CRS produced no finding for a matched ARGS value")
	}
	got := result.Findings[0].MatchedValue
	if !utf8.ValidString(got) {
		t.Fatalf("ASCII matched value is not valid UTF-8: %q", got)
	}
	if len(got) > 200 {
		t.Fatalf("ASCII matched value exceeded the 200-byte cap: %d", len(got))
	}
}
