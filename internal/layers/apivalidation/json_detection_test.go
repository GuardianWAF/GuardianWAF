package apivalidation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests: pretty-printed JSON OpenAPI specs must be detected as
// JSON, not YAML. IsYAML keyed off ": " substrings, which every pretty JSON
// document contains, so realistic JSON specs were routed to the naive YAML
// parser and silently mangled into an empty spec (no paths). With
// BlockOnViolation/StrictMode defaults that means strict mode then blocked
// every request with "No OpenAPI schema defined", and non-strict mode
// silently validated nothing.

const prettyJSONSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "pets", "version": "1.0.0"},
  "paths": {
    "/pets": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "maxLength": 3}}}}}}}}
  }
}`

func TestIsYAMLPrettyJSONIsNotYAML(t *testing.T) {
	if IsYAML([]byte(prettyJSONSpec)) {
		t.Fatal("FAIL: pretty-printed JSON detected as YAML — it would be mangled by the naive YAML parser into an empty spec")
	}
}

func TestLoadSchemaPrettyJSONSpecEnforcesSchema(t *testing.T) {
	// readFile confines spec paths to the working directory; the test binary
	// runs with CWD = this package dir, so the spec must live under it.
	dir, err := os.MkdirTemp(".", "prettyjson-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(prettyJSONSpec), 0o600); err != nil {
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

	// Violating payload: name exceeds maxLength 3. The layer must report the
	// REAL schema violation — not the strict-mode "No OpenAPI schema defined"
	// fallback that fires when the spec loaded as empty.
	result := postJSON(t, layer, "/pets", `{"name":"way-too-long"}`)
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: violating payload produced zero findings against a loaded pretty-JSON spec")
	}
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "No OpenAPI schema defined") {
			t.Fatalf("FAIL: pretty-JSON spec loaded as empty — strict-mode fallback fired instead of schema validation: %q", f.Description)
		}
	}
	enforced := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "maxLength") || strings.Contains(f.Description, "length") {
			enforced = true
		}
	}
	if !enforced {
		t.Fatalf("FAIL: expected a maxLength violation finding, got: %+v", result.Findings)
	}

	// Boundary: valid payload stays clean.
	result = postJSON(t, layer, "/pets", `{"name":"abc"}`)
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: valid payload flagged after fix: %+v", result.Findings)
	}
}

// Control: genuine YAML documents must still be detected.
func TestIsYAMLStillDetectsYAML(t *testing.T) {
	yamlDoc := "openapi: 3.0.0\ninfo:\n  title: pets\n  version: 1.0.0\npaths:\n  /pets:\n    post:\n      summary: create\n"
	if !IsYAML([]byte(yamlDoc)) {
		t.Fatal("FAIL: plain YAML document no longer detected as YAML")
	}
	if !IsYAML([]byte("---\nfoo: bar\n")) {
		t.Fatal("FAIL: document-separator YAML no longer detected as YAML")
	}
}
