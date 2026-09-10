package openredirect

import (
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestDetect_TabObfuscatedRedirectTargets covers ASCII-tab obfuscation of
// redirect targets. The WHATWG URL parser strips ASCII tab (and LF/CR) from
// URL input, so these values are executable/external in a browser; Go's
// url.Parse instead rejects the raw forms ("invalid control character in
// URL"), which made checkValue return "safe" — every other check silently
// skipped — before tab joined the control-char gate. Embedded tabs must hit
// the control-char branch (score 70 → ActionBlock).
func TestDetect_TabObfuscatedRedirectTargets(t *testing.T) {
	d := NewDetector(true, 1.0)

	attackTargets := []string{
		"java\tscript:alert(1)", // tab inside scheme → browser executes javascript:
		"ht\ttps://evil.com",    // tab inside scheme → browser resolves external redirect
		"https://ev\til.com",    // tab inside host → external host evil.com
	}
	for _, target := range attackTargets {
		ctx := makeCtx("example.com", "next="+url.QueryEscape(target), nil)
		result := d.Process(ctx)
		if len(result.Findings) == 0 {
			t.Fatalf("tab-obfuscated target %q: got 0 findings, want a control-char finding", target)
		}
		if result.Action != engine.ActionBlock {
			t.Fatalf("tab-obfuscated target %q: action = %v, want ActionBlock", target, result.Action)
		}
		if result.Findings[0].Score != 70 || !strings.Contains(result.Findings[0].Description, "control characters") {
			t.Fatalf("tab-obfuscated target %q: unexpected finding %+v, want the control-char branch (score 70)", target, result.Findings[0])
		}
	}

	// The same checkValue serves the Location-header path.
	hdrCtx := makeCtx("example.com", "", map[string][]string{"Location": {"java\tscript:alert(1)"}})
	if r := d.Process(hdrCtx); len(r.Findings) == 0 || r.Action != engine.ActionBlock {
		t.Fatalf("tab-obfuscated Location header: findings=%d action=%v, want a blocking control-char finding", len(r.Findings), r.Action)
	}

	// Benign values must stay clean: spaces are NOT stripped by browsers and
	// never form a scheme/host (only tab/LF/CR are), and leading/trailing
	// tabs are incidental whitespace already removed by checkValue's
	// TrimSpace — they must not trigger the control-char branch.
	benignTargets := []string{
		"https://example.com/path",
		"https://example.com/a b",
		"\thttps://example.com\t",
		"/relative/path?x=1",
	}
	for _, target := range benignTargets {
		ctx := makeCtx("example.com", "next="+url.QueryEscape(target), nil)
		if r := d.Process(ctx); len(r.Findings) != 0 {
			t.Fatalf("benign target %q: got %d findings (%q), want clean pass", target, len(r.Findings), r.Findings[0].Description)
		}
	}
}
