package lfi

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestProcess_RawFallbackWhenSanitizerDisabled guards against the fail-open
// regression where the detector scanned only Sanitizer-populated Normalized*
// fields. See the matching test in the sqli package for rationale.
func TestProcess_RawFallbackWhenSanitizerDisabled(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/download",
		QueryParams: map[string][]string{
			"file": {"../../../../etc/passwd"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)
	if result.Action == engine.ActionPass || len(result.Findings) == 0 {
		t.Fatalf("expected LFI to be detected via raw query fallback; got action=%v findings=%d", result.Action, len(result.Findings))
	}
}
