package apivalidation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests: JSON Schema allows omitting "type" — the applicable
// keywords (required, properties, additionalProperties, minLength, items,
// combinators) must still apply to instances of the matching shape. The
// validator used to dispatch type-specific checks on schema.Type alone, so
// schemas without "type" silently validated NOTHING (required fields,
// property constraints, and strict-mode unknown-field detection were all
// skipped).

// Implicit-object schema: no "type", but required/properties/constraints
// that must apply to object payloads.
const implicitTypeSpec = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/things":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"required":["name"],"properties":{"name":{"type":"string","maxLength":3}},"additionalProperties":false}}}}}},"/dogs":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","maxLength":3}},"additionalProperties":false}}}}}}}}`

func newImplicitTypeLayer(t *testing.T) *Layer {
	t.Helper()

	dir, err := os.MkdirTemp(".", "implicittype-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(implicitTypeSpec), 0o600); err != nil {
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

func TestImplicitObjectSchemaStillValidates(t *testing.T) {
	layer := newImplicitTypeLayer(t)

	// Missing required "name" AND unknown field "wrong" (strict mode).
	result := postJSON(t, layer, "/things", `{"wrong":"x"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: schema without \"type\" skipped required/unknown-field validation — payload with missing required field passed")
	}

	// Property constraint: maxLength 3 on name.
	result = postJSON(t, layer, "/things", `{"name":"way-too-long"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: schema without \"type\" skipped property maxLength validation")
	}

	// Boundary: valid payload stays clean.
	result = postJSON(t, layer, "/things", `{"name":"abc"}`)
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: valid payload flagged after fix: %+v", result.Findings)
	}
}

// Control: the identical schema WITH "type":"object" must detect the same
// violation both before and after the fix — isolating omitted-"type"
// dispatch as the defect, not the validation machinery.
func TestExplicitObjectSchemaControlDetectsViolation(t *testing.T) {
	layer := newImplicitTypeLayer(t)

	result := postJSON(t, layer, "/dogs", `{"wrong":"x"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: explicit-type control did not detect the violation — test setup broken")
	}
	if !strings.Contains(result.Findings[0].Description, "required") &&
		!strings.Contains(result.Findings[0].Description, "additional property") {
		t.Fatalf("FAIL: unexpected control finding: %+v", result.Findings[0])
	}
}

// String constraints must also apply when "type" is omitted.
func TestImplicitStringSchemaConstraintsApply(t *testing.T) {
	v := NewSchemaValidator(true)

	minLen := 5
	schema := &Schema{MinLength: &minLen}

	if result := v.Validate("abc", schema, "f"); result.Valid {
		t.Fatal("FAIL: minLength ignored for a string schema without \"type\"")
	}
	if result := v.Validate("abcde", schema, "f"); !result.Valid {
		t.Fatalf("FAIL: string meeting minLength flagged: %+v", result.Errors)
	}
}
