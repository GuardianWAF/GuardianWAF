package sqli

// Regression (bug-hunt round 2026-09-18-r7): Detector.Process scanned only
// ONE form per input — NormalizedPath/NormalizedQuery/NormalizedBody
// preferred, raw only as an empty-fallback — the exact shape the round-9/25
// XSS fix identified as a defect class: a payload whose SQL signature the
// sanitizer's normalization alters (NormalizeWhitespace/NormalizeUnicode/
// NormalizeBackslashes collapse or rewrite bytes) was judged solely on its
// mangled sanitized form, while the upstream SQL parser receives the RAW
// bytes. Sibling detectors (cmdi — cmdi.go:74-91 — nosqli, ssti, ssrf) scan
// both forms; this converts the flagship sqli detector to the same
// both-forms-with-dedup convention, mirroring the xss.go scanInputs shape.
//
// All fixtures are deterministic: the divergence is constructed directly in
// the RequestContext (normalized form benign, raw form carrying the
// signature), exactly the production state after a mangling normalization.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const unionAttack = "1' UNION SELECT password FROM users--"

// TestSQLiDetectorScansBothRawAndNormalizedForms is the defect case: the
// sanitizer's view is benign, the raw view carries the injection — the
// detector must judge BOTH forms.
func TestSQLiDetectorScansBothRawAndNormalizedForms(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:         "POST",
		Path:           "/api/search",
		NormalizedPath: "/api/search",
		QueryParams:    map[string][]string{"q": {unionAttack}},
		NormalizedQuery: map[string][]string{
			"q": {"searchterm"}, // sanitizer rewrote the value: signature gone
		},
		BodyString:     "q=" + unionAttack,
		NormalizedBody: "q=searchterm", // sanitizer rewrote the body: signature gone
		Headers:        map[string][]string{},
		Cookies:        map[string][]string{},
	}

	result := d.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: the sqli detector judged only the sanitized forms — the raw query/body values carrying %q produced 0 findings; both forms must be scanned", unionAttack)
	}
}

// Control: identical forms must be detected ONCE — converting to both-forms
// scanning must not double-count findings for an input the sanitizer left
// unchanged (asserted as an exact one-scan count against Detect directly).
func TestSQLiDetectorIdenticalFormsDetectedOnce(t *testing.T) {
	d := NewDetector(true, 1.0)
	bodyInput := "q=" + unionAttack
	ctx := &engine.RequestContext{
		Method:          "POST",
		Path:            "/api/search",
		NormalizedPath:  "/api/search",
		QueryParams:     map[string][]string{},
		NormalizedQuery: map[string][]string{},
		BodyString:      bodyInput,
		NormalizedBody:  bodyInput, // sanitizer left the body unchanged
		Headers:         map[string][]string{},
		Cookies:         map[string][]string{},
	}

	result := d.Process(ctx)
	expected := len(Detect(bodyInput, "body"))
	if expected == 0 {
		t.Fatalf("FAIL: harness sanity — the attack must be detectable by Detect")
	}
	if len(result.Findings) != expected {
		t.Fatalf("FAIL: identical forms scanned more than once — got %d findings, expected exactly %d (one scan of the unchanged form)", len(result.Findings), expected)
	}
}

// Control: a conforming input produces no findings — both-forms scanning
// must not turn ordinary prose into SQLi findings.
func TestSQLiDetectorConformingInputPasses(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Method:         "POST",
		Path:           "/api/search",
		NormalizedPath: "/api/search",
		QueryParams:    map[string][]string{"q": {"searchterm"}},
		NormalizedQuery: map[string][]string{
			"q": {"searchterm"},
		},
		BodyString:     "q=searchterm",
		NormalizedBody: "q=searchterm",
		Headers:        map[string][]string{},
		Cookies:        map[string][]string{},
	}

	result := d.Process(ctx)
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: harness control — a conforming input must produce no findings, got %v", result.Findings)
	}
}
