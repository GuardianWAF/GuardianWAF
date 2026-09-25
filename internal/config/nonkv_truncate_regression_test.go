package config

// Regression (round 2026-09-24-r27-nonkv-truncate): parseMapping treated the
// two malformed-input classes asymmetrically — an over-indented line at a
// mapping's level errored loudly, but a SAME-INDENT line that parseKeyValue
// rejected (e.g. a colon-typo'd key at column 0) silently BROKE the mapping
// loop, truncating the rest of the document: every following section was
// dropped and the WAF booted on partial config + defaults. The branch now
// returns an honest ParseError naming the line, mirroring the over-indent
// error's invariant.

import (
	"errors"
	"testing"
)

func TestNonKVLineReturnsParseError(t *testing.T) {
	data := []byte("waf:\n  mode: block\nthis line has no colon\ntls:\n  enabled: true\n")
	_, err := Parse(data)
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.Line != 3 {
		t.Fatalf("error line = %d, want 3", pe.Line)
	}
}

func TestNestedNonKVLineReturnsParseError(t *testing.T) {
	// A non-KV line at the NESTED mapping's own indent errors with the line
	// attributed to the malformed line (pre-fix this surfaced as the less
	// specific over-indent error from the parent mapping).
	data := []byte("waf:\n  mode: block\n  this has no colon\n  more: x\n")
	_, err := Parse(data)
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.Line != 3 {
		t.Fatalf("error line = %d, want 3", pe.Line)
	}
}

func TestValidDocumentWithSequencesStillParses(t *testing.T) {
	data := []byte("waf:\n  mode: block\ntls:\n  enabled: true\n  ciphers:\n    - a\n    - b\n")
	node, err := Parse(data)
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	ciphers := node.GetPath("tls", "ciphers")
	if ciphers == nil || len(ciphers.Items) != 2 {
		t.Fatalf("valid document lost sections: %+v", node)
	}
	if node.GetPath("waf", "mode").String() != "block" {
		t.Fatalf("waf.mode = %q", node.GetPath("waf", "mode").String())
	}
}
