package apivalidation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests (round 81): validateHeaders validated ONLY the first
// value of a repeated header (values[0]), while the query-parameter path
// validated each value. An attacker sent X-Api-Version: <valid> plus
// X-Api-Version: <violating> and the declared header contract was never
// enforced against the second value — zero findings, bypass. Header
// parameters must validate EVERY transmitted value (mirrors the query
// loop), without over-blocking headers whose values are all valid.

const mvhSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "mvh", "version": "1.0.0"},
  "paths": {
    "/orders": {
      "get": {
        "parameters": [
          {
            "name": "X-Api-Version",
            "in": "header",
            "required": true,
            "schema": {"type": "string", "enum": ["v1", "v2"]}
          }
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func newMVHLayer(t *testing.T) *Layer {
	t.Helper()

	layer := NewLayer(&Config{Enabled: true, ValidateRequest: true})
	path := filepath.Join("mvh_spec_", "spec.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(mvhSpec), 0o600); err != nil {
		t.Fatalf("writing spec: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path)) })
	if err := layer.LoadSchema(SchemaSource{Type: "openapi", Path: path}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

func runMVH(t *testing.T, versions []string) engine.LayerResult {
	t.Helper()

	layer := newMVHLayer(t)
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/orders",
		Headers: map[string][]string{
			"X-Api-Version": versions,
		},
	}
	return layer.Process(ctx)
}

func TestMultiValueHeaderViolatingSecondValueDetected(t *testing.T) {
	result := runMVH(t, []string{"v1", "v3"})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: X-Api-Version: v1 + X-Api-Version: v3 produced no findings — a schema-violating second header value bypasses the declared contract")
	}
	if !strings.Contains(strings.Join(findingDescriptions(result), "; "), "X-Api-Version") {
		t.Fatalf("FAIL: findings do not reference the header parameter: %v", findingDescriptions(result))
	}
}

func TestMultiValueHeaderViolatingFirstValueDetected(t *testing.T) {
	// Order swap: the violating value must be caught regardless of position
	// (pre-fix this was found only when it happened to be values[0]).
	result := runMVH(t, []string{"v3", "v1"})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: X-Api-Version: v3 + X-Api-Version: v1 produced no findings")
	}
}

func TestMultiValueHeaderAllViolatingDetected(t *testing.T) {
	result := runMVH(t, []string{"v3", "v4"})
	if len(result.Findings) != 2 {
		t.Fatalf("FAIL: two violating values produced %d findings, want 2: %v", len(result.Findings), findingDescriptions(result))
	}
}

func TestMultiValueHeaderAllValidNotFlagged(t *testing.T) {
	// No over-blocking: repeated headers whose values are all valid must
	// stay clean.
	result := runMVH(t, []string{"v1", "v2"})
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: all-valid multi-value header produced findings: %v", findingDescriptions(result))
	}
}

func TestSingleValueHeaderStillValidated(t *testing.T) {
	// Preserved behavior: the single-value path (previously the only
	// validated case) must keep detecting.
	result := runMVH(t, []string{"v3"})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: single violating header value produced no findings")
	}
}

func TestMultiValueHeaderRequiredMissingStillFlagged(t *testing.T) {
	// Secondary branch: the required-missing branch must be intact.
	layer := newMVHLayer(t)
	ctx := &engine.RequestContext{Method: "GET", Path: "/orders"}
	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: missing required header produced no findings")
	}
	if !strings.Contains(result.Findings[0].Description, "missing") {
		t.Fatalf("FAIL: expected required-missing finding, got: %v", findingDescriptions(result))
	}
}

func TestMultiValueHeaderMatchedValueIsOffendingValue(t *testing.T) {
	// The finding must attribute the offending VALUE, not the first one.
	result := runMVH(t, []string{"v1", "v3"})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: expected findings")
	}
	if got := result.Findings[0].MatchedValue; got != "v3" {
		t.Fatalf("FAIL: MatchedValue = %v, want the offending value v3", got)
	}
}

func findingDescriptions(r engine.LayerResult) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Description)
	}
	return out
}
