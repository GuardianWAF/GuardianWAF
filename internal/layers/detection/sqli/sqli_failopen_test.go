package sqli

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestProcess_RawFallbackWhenSanitizerDisabled guards against the fail-open
// regression where the detector scanned only the Sanitizer-populated
// Normalized* fields. With the sanitizer disabled those fields are empty, so
// the detector must fall back to the raw request fields or it silently passes
// every injection in the path/query/body.
func TestProcess_RawFallbackWhenSanitizerDisabled(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		Method: "GET",
		// No Normalized* fields set (sanitizer disabled) — only raw fields.
		Path: "/search",
		QueryParams: map[string][]string{
			"q": {"' UNION SELECT password FROM users --"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)
	if result.Action == engine.ActionPass || len(result.Findings) == 0 {
		t.Fatalf("expected SQLi to be detected via raw query fallback; got action=%v findings=%d", result.Action, len(result.Findings))
	}

	// Body fallback must work too.
	ctxBody := &engine.RequestContext{
		Method:     "POST",
		BodyString: "id=1 OR 1=1; DROP TABLE users",
		Headers:    map[string][]string{},
		Cookies:    map[string]string{},
	}
	if r := det.Process(ctxBody); r.Action == engine.ActionPass && len(r.Findings) == 0 {
		t.Fatalf("expected SQLi detected via raw body fallback; got action=%v findings=%d", r.Action, len(r.Findings))
	}
}
