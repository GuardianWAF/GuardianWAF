package apivalidation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: request-body validation must key off the SPEC's declared
// content contract, not the request's self-declared Content-Type. Previously
// validateRequestBody handled only application/json and the two form types;
// any other Content-Type value (e.g. text/plain) skipped body validation
// entirely, so an attacker could send a schema-violating JSON payload with a
// lying Content-Type and bypass the declared schema contract (the backend
// commonly parses the body regardless of the declared type).

const ctBypassSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "ct-bypass", "version": "1.0.0"},
  "paths": {
    "/users": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["username"],
                "properties": {
                  "username": {"type": "string", "minLength": 3}
                },
                "additionalProperties": false
              }
            }
          }
        }
      }
    }
  }
}`

const ctViolatingBody = `{"username":"ab","is_admin":true}`

func newCTBypassLayer(t *testing.T) *Layer {
	t.Helper()

	layer := NewLayer(&Config{Enabled: true, ValidateRequest: true})
	// readFile confines spec loads to the working directory: use a
	// package-relative path so the test's spec file stays inside it.
	if err := layer.LoadSchema(SchemaSource{Type: "openapi", Path: specName(t)}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

// specName materializes the spec inside the package working directory (the
// layer's readFile confinement) and cleans it up with the test.
func specName(t *testing.T) string {
	t.Helper()
	path := filepath.Join("ct_bypass_spec_", "spec.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(ctBypassSpec), 0o600); err != nil {
		t.Fatalf("writing spec: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path)) })
	return path
}

func runCTScenario(t *testing.T, contentType string) (int, int) {
	t.Helper()
	layer := newCTBypassLayer(t)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/users",
		Headers: map[string][]string{
			"Content-Type": {contentType},
		},
		Body:       []byte(ctViolatingBody),
		BodyString: ctViolatingBody,
	}

	result := layer.Process(ctx)
	return result.Score, len(result.Findings)
}

func TestContentTypeConfusionStillValidated(t *testing.T) {
	score, findings := runCTScenario(t, "text/plain")
	if score == 0 || findings == 0 {
		t.Fatalf("FAIL: a schema-violating JSON body with Content-Type text/plain produced no findings (score=%d findings=%d) — content-type confusion bypasses the schema contract", score, findings)
	}
}

func TestDeclaredContentTypeControl(t *testing.T) {
	score, findings := runCTScenario(t, "application/json")
	if score == 0 || findings == 0 {
		t.Fatalf("FAIL: control scenario broke — application/json CT no longer detects violations (score=%d findings=%d)", score, findings)
	}
}

func TestValidBodyWithLyingContentTypeNotBlocked(t *testing.T) {
	// A schema-VALID body must not be flagged merely because the client
	// declared a different content type (no over-blocking).
	layer := newCTBypassLayer(t)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/users",
		Headers: map[string][]string{
			"Content-Type": {"text/plain"},
		},
		Body:       []byte(`{"username":"alice"}`),
		BodyString: `{"username":"alice"}`,
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Fatalf("FAIL: a schema-valid body was blocked when the client declared text/plain (action=%v score=%d)", result.Action, result.Score)
	}
}
