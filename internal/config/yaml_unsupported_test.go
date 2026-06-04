package config

import (
	"strings"
	"testing"
)

// TestParse_RejectsUnsupportedSyntax locks in the fail-loud behavior for YAML
// constructs this single-document parser cannot honor. Previously a leading
// "---" silently dropped the entire config (the WAF booted on pure defaults
// with no error), and anchors/aliases/tags were ingested as literal strings.
func TestParse_RejectsUnsupportedSyntax(t *testing.T) {
	reject := []struct {
		name string
		yaml string
	}{
		{"leading document marker", "---\nlisten: \":12345\"\n"},
		{"document marker with content", "--- listen: \":1\"\n"},
		{"document end marker", "listen: \":1\"\n...\n"},
		{"anchor", "listen: &x \":1\"\n"},
		{"alias", "a: &x 1\nb: *x\n"},
		{"type tag", "port: !!int 5\n"},
		{"merge key", "base:\n  a: 1\nchild:\n  <<: *base\n"},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err == nil {
				t.Fatalf("expected parse error for %s, got nil", tc.name)
			}
		})
	}

	// These must still parse: bare wildcards and wildcard hostnames are common
	// in this WAF's config (CORS origins, virtual-host patterns) and are NOT
	// YAML aliases.
	accept := []struct {
		name string
		yaml string
	}{
		{"bare wildcard value", "origin: \"*\"\n"},
		{"wildcard hostname", "host: *.example.com\n"},
		{"quoted ampersand value", "secret: \"&p@ss\"\n"},
		{"value containing ampersand", "url: http://h/?a=1&b=2\n"},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err != nil {
				t.Fatalf("expected %s to parse, got error: %v", tc.name, err)
			}
		})
	}
}

// TestParse_NoSilentConfigDrop is the direct regression for the proven
// fail-open: a "---" prefixed file must not load as an empty/default config.
func TestParse_NoSilentConfigDrop(t *testing.T) {
	_, err := Parse([]byte("---\nlisten: \":12345\"\n"))
	if err == nil {
		t.Fatal("leading --- silently accepted; config would load as defaults (fail-open regression)")
	}
	if !strings.Contains(err.Error(), "document marker") {
		t.Fatalf("expected a document-marker error, got: %v", err)
	}
}
