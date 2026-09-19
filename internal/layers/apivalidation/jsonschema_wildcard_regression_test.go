package apivalidation

// Regression (bug-hunt round 2026-09-18-r5): loadJSONSchema wraps a raw JSON
// Schema in a synthetic OpenAPI spec whose single path is the literal "/*" —
// documented in the function as a "wildcard path". compilePathPattern ran
// regexp.QuoteMeta over that path, escaping the star: the compiled pattern
// became ^/\*$, which matches ONLY a request path literally equal to "/*".
// Process routes every request through router.Match, so a jsonschema-type
// schema — a supported SchemaSource type — never matched any real request:
//
//   - non-strict mode: every request passed with ZERO validation (the
//     operator's schema contract was silently inert while the dashboard
//     reported the schema loaded), and
//   - strict mode (the DefaultConfig): every request was blocked with
//     "No OpenAPI schema defined for this endpoint in strict mode".
//
// The fix teaches compilePathPattern that the synthetic "/*" path is a
// catch-all (^/.*$), and deprioritizes that wildcard route inside
// PathRouter.Match so a spec loaded alongside an OpenAPI spec keeps the
// specific route deterministic (the wildcard is the last-resort fallback).
//
// The OpenAPI concrete-path control below passes before AND after the fix:
// it proves the harness, the validator, and the config are sound, isolating
// the defect to the wildcard path.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func writeSchemaFile(t *testing.T, content string) string {
	t.Helper()
	// The layer's readFile confines schema paths to the process working
	// directory (symlink-resolved), so the fixture must live under CWD —
	// t.TempDir() (/tmp) is rejected by design. Same pattern as
	// ref_bypass_test.go / json_detection_test.go.
	dir, err := os.MkdirTemp(".", "jsonwildcard-*")
	if err != nil {
		t.Fatalf("setup: MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "schema.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("setup: write schema file: %v", err)
	}
	return path
}

func violatingWidgetRequest() *engine.RequestContext {
	return &engine.RequestContext{
		Method:      "POST",
		Path:        "/api/widgets",
		Body:        []byte(`{"name":"no id here"}`),
		BodyString:  `{"name":"no id here"}`,
		ContentType: "application/json",
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
	}
}

// TestJSONSchemaWildcardPathValidatesAllRequests is the defect case: a
// jsonschema-type schema must enforce its contract on every path, not sit
// inert behind an escaped literal "/*" pattern.
func TestJSONSchemaWildcardPathValidatesAllRequests(t *testing.T) {
	schemaPath := writeSchemaFile(t, `{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}`)
	cfg := &Config{Enabled: true, ValidateRequest: true, StrictMode: false, BlockOnViolation: true, ViolationScore: 40}
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{Type: "jsonschema", Path: schemaPath}); err != nil {
		t.Fatalf("setup: LoadSchema: %v", err)
	}

	result := layer.Process(violatingWidgetRequest())

	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: a jsonschema-type schema validated nothing — POST /api/widgets with a body violating the required 'id' constraint produced %d findings because the synthetic /* wildcard path compiled to a literal-only pattern; the schema contract must apply to every path", len(result.Findings))
	}
	if result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: expected ActionBlock for a schema violation with BlockOnViolation, got %s", result.Action.String())
	}
}

// TestJSONSchemaWildcardStrictModeNoFalseNoSchema pins strict mode: with a
// jsonschema schema loaded, a request must be judged against the schema —
// the "no schema defined" refusal must not fire for matched paths.
func TestJSONSchemaWildcardStrictModeNoFalseNoSchema(t *testing.T) {
	schemaPath := writeSchemaFile(t, `{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}`)
	cfg := &Config{Enabled: true, ValidateRequest: true, StrictMode: true, BlockOnViolation: true, ViolationScore: 40}
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{Type: "jsonschema", Path: schemaPath}); err != nil {
		t.Fatalf("setup: LoadSchema: %v", err)
	}

	result := layer.Process(violatingWidgetRequest())

	for _, f := range result.Findings {
		if f.Description == "No OpenAPI schema defined for this endpoint in strict mode" {
			t.Fatalf("FAIL: strict mode refused the request with %q — the jsonschema wildcard route must match real paths so the actual schema is evaluated", f.Description)
		}
	}
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: strict-mode jsonschema request produced no findings at all; the violating body must be flagged by the schema")
	}
}

// Control: an OpenAPI spec with a concrete path validates the same violating
// body — passes before AND after the fix, proving the harness is sound.
func TestOpenAPISpecConcretePathStillValidates(t *testing.T) {
	spec := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/api/widgets":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}}}}}}}}`
	specPath := writeSchemaFile(t, spec)
	cfg := &Config{Enabled: true, ValidateRequest: true, StrictMode: false, BlockOnViolation: true, ViolationScore: 40}
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{Type: "openapi", Path: specPath}); err != nil {
		t.Fatalf("setup: LoadSchema: %v", err)
	}

	result := layer.Process(violatingWidgetRequest())

	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: harness control — an OpenAPI concrete path must flag the violating body")
	}
}

// Control: a conforming body must pass the jsonschema wildcard without
// false positives (pins the post-fix contract; vacuously true pre-fix).
func TestJSONSchemaWildcardConformingBodyPasses(t *testing.T) {
	schemaPath := writeSchemaFile(t, `{"type":"object","required":["id"],"properties":{"id":{"type":"integer"}}}`)
	cfg := &Config{Enabled: true, ValidateRequest: true, StrictMode: false, BlockOnViolation: true, ViolationScore: 40}
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{Type: "jsonschema", Path: schemaPath}); err != nil {
		t.Fatalf("setup: LoadSchema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:      "POST",
		Path:        "/api/widgets",
		Body:        []byte(`{"id":42}`),
		BodyString:  `{"id":42}`,
		ContentType: "application/json",
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
	}
	result := layer.Process(ctx)

	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: harness control — a conforming body must produce no findings, got %v", result.Findings)
	}
	if result.Action != engine.ActionPass {
		t.Fatalf("FAIL: harness control — a conforming body must pass, got %s", result.Action.String())
	}
}
