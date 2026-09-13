package dlp

import (
	"strings"
	"testing"
)

// Regression (round 77): dlp.Config.CustomPatterns (yaml: custom_patterns)
// was silently ignored — NewLayer only called configurePatterns(cfg.Patterns),
// which handles the nine builtin names, so operator-configured custom regex
// patterns never reached the pattern registry and scans passed over their
// matches. NewLayer now registers them; invalid regexes are skipped without
// panicking and without breaking sibling patterns.

func TestNewLayerRegistersConfigCustomPatterns(t *testing.T) {
	l := NewLayer(&Config{
		Enabled:        true,
		ScanResponse:   true,
		MaskResponse:   true,
		MaxBodySize:    1024 * 1024,
		Patterns:       []string{}, // disable builtins — isolate the custom pattern
		CustomPatterns: map[string]string{"corp_id": `ACME-[0-9]{5}`},
	})

	res, masked := l.ScanResponse([]byte("id=ACME-54321 ok"), "text/plain")
	if res.Safe {
		t.Fatal("FAIL: ScanResponse reported Safe for content matching the configured custom pattern — the pattern was silently ignored")
	}
	if strings.Contains(string(masked), "ACME-54321") {
		t.Fatalf("FAIL: masked response still contains the unmasked match: %q", string(masked))
	}
}

// Boundary: an invalid custom regex must be skipped at construction (no
// panic) without preventing the remaining custom patterns from registering.
func TestNewLayerSkipsInvalidCustomPatternRegex(t *testing.T) {
	l := NewLayer(&Config{
		Enabled:        true,
		ScanResponse:   true,
		MaskResponse:   true,
		MaxBodySize:    1024 * 1024,
		Patterns:       []string{"credit_card"},
		CustomPatterns: map[string]string{"broken": "([unclosed", "corp_id": `ACME-[0-9]{5}`},
	})

	res, masked := l.ScanResponse([]byte("id=ACME-54321 ok"), "text/plain")
	if res.Safe {
		t.Fatal("FAIL: the valid custom pattern was not applied after an invalid sibling was skipped")
	}
	if strings.Contains(string(masked), "ACME-54321") {
		t.Fatalf("FAIL: masked response still contains the unmasked match: %q", string(masked))
	}
}
