package apivalidation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: request-body schemas referenced via $ref must be
// validated. The validator used to treat ANY $ref schema as unconditionally
// valid ("For now, skip reference resolution"), and the compile path stored
// $ref schemas verbatim — so for any OpenAPI spec using components (the
// standard authoring style), body validation silently enforced nothing while
// BlockOnViolation defaulted to true.

// Single-line compact JSON: IsYAML keys off ": " substrings, so a
// pretty-printed JSON spec would be misdetected as YAML and mangled by the
// naive parser before ever reaching the $ref code under test.
const refBypassSpec = `{"openapi":"3.0.0","info":{"title":"pets","version":"1.0.0"},"paths":{"/pets":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Pet"}}}}}},"/dogs":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":3}}}}}}}}},"components":{"schemas":{"Pet":{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":3}}}}}}`

func newRefBypassLayer(t *testing.T) *Layer {
	t.Helper()

	// readFile confines spec paths to the working directory; the test binary
	// runs with CWD = this package dir, so the spec must live under it.
	dir, err := os.MkdirTemp(".", "refbypass-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(refBypassSpec), 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}

	layer := NewLayer(&Config{
		Enabled:          true,
		ValidateRequest:  true,
		ValidateResponse: false,
		StrictMode:       true,
		BlockOnViolation: true,
		ViolationScore:   40,
		CacheSize:        100,
	})
	if err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

func postJSON(t *testing.T, layer *Layer, path, body string) engine.LayerResult {
	t.Helper()
	ctx := &engine.RequestContext{
		Method:  "POST",
		Path:    path,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(body),
	}
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	return result
}

func TestRefSchemaViolationsMustBeDetected(t *testing.T) {
	layer := newRefBypassLayer(t)

	// Case A: violates the $ref'd schema (name exceeds maxLength 3).
	result := postJSON(t, layer, "/pets", `{"name":"way-too-long"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: payload violating the $ref'd component schema produced zero findings — $ref request-body validation is silently bypassed")
	}

	// Case B: violates the $ref'd schema (required field missing).
	result = postJSON(t, layer, "/pets", `{}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: payload missing the $ref'd schema's required field produced zero findings")
	}

	// Case D: valid payload must stay clean (no false positives after the fix).
	result = postJSON(t, layer, "/pets", `{"name":"abc"}`)
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: valid payload against $ref'd schema flagged: %v", result.Findings)
	}
}

// Control: the identical schema inlined (no $ref) must already detect the
// violation both before and after the fix — isolating $ref handling as the
// defect, not the validation machinery.
func TestInlineSchemaControlDetectsViolation(t *testing.T) {
	layer := newRefBypassLayer(t)

	result := postJSON(t, layer, "/dogs", `{"name":"way-too-long"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: inline-schema control did not detect the violation — test setup broken")
	}
	if !strings.Contains(result.Findings[0].Description, "maxLength") &&
		!strings.Contains(result.Findings[0].Description, "length") {
		t.Fatalf("FAIL: unexpected control finding: %+v", result.Findings[0])
	}
}
