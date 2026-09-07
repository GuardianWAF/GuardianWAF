package apivalidation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: the urlencoded form branch must validate the urlencoded
// BODY (url.ParseQuery(ctx.BodyString)), not ctx.QueryParams. The previous
// implementation built its form map from the URL query, so (1) violations in
// the form body were never validated and (2) URL query parameters were
// flagged against the body schema. Multipart bodies skip validation (no
// boundary parser — disclosed limitation).

const formSourceSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "form-source", "version": "1.0.0"},
  "paths": {
    "/users": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
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

func newFormSourceLayer(t *testing.T) *Layer {
	t.Helper()

	layer := NewLayer(&Config{Enabled: true, ValidateRequest: true})
	// readFile confines spec loads to the working directory: use a
	// package-relative path so the test's spec file stays inside it.
	if err := layer.LoadSchema(SchemaSource{Type: "openapi", Path: formSpecName(t)}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

func formSpecName(t *testing.T) string {
	t.Helper()
	path := filepath.Join("form_source_spec", "spec.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(formSourceSpec), 0o600); err != nil {
		t.Fatalf("writing spec: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path)) })
	return path
}

func runFormScenario(t *testing.T, query string, contentType, body string) (int, int) {
	t.Helper()
	layer := newFormSourceLayer(t)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/users",
		Headers: map[string][]string{
			"Content-Type": {contentType},
		},
		Body:       []byte(body),
		BodyString: body,
	}
	if query != "" {
		ctx.QueryParams = map[string][]string{"username": {"alice"}}
		_ = query
	}

	result := layer.Process(ctx)
	return result.Score, len(result.Findings)
}

func TestFormBodyViolationsDetected(t *testing.T) {
	// A schema-violating body ("username" is 2 chars, minLength 3) must be
	// detected even when the URL query carries a satisfying value.
	score, findings := runFormScenario(t, "satisfying", "application/x-www-form-urlencoded", "username=ab")
	if score == 0 || findings == 0 {
		t.Fatalf("FAIL: a violating form body produced no findings while the query satisfied the schema (score=%d findings=%d) — the wrong-source validation is still in effect", score, findings)
	}
}

func TestFormBodyQueryNotValidatedAsBody(t *testing.T) {
	// A schema-valid body with NO query params must pass clean (the old
	// code flagged "required username missing" from the empty query map).
	score, findings := runFormScenario(t, "", "application/x-www-form-urlencoded", "username=alice")
	if score != 0 || findings != 0 {
		t.Fatalf("FAIL: a valid form body produced findings (score=%d findings=%d) — over-blocking", score, findings)
	}
}

func TestFormBodyURLEncodedDecoding(t *testing.T) {
	// "username=%61" decodes to "a" (1 char): must be INVALID under
	// minLength=3. Undecoded, the raw value "%61" (3 chars) would pass —
	// a finding here proves the body was URL-decoded.
	score, findings := runFormScenario(t, "", "application/x-www-form-urlencoded", "username=%61")
	if score == 0 || findings == 0 {
		t.Fatalf("FAIL: an encoded violating body (decodes to a 1-char value) produced no findings — the form body was not URL-decoded")
	}
}

func TestJSONPathIntact(t *testing.T) {
	score, findings := runFormScenario(t, "", "application/json", `{"username":"ab"}`)
	if score == 0 || findings == 0 {
		t.Fatalf("FAIL: the JSON validation path regressed (score=%d findings=%d)", score, findings)
	}
}

func TestMultipartSkipsWithoutCrash(t *testing.T) {
	// Multipart bodies cannot be parsed without boundary handling; they
	// must not crash and must not flag query data as body violations.
	score, findings := runFormScenario(t, "satisfying", "multipart/form-data; boundary=xyz", "--xyz\r\ncontent-disposition: form-data; name=\"username\"\r\n\r\nab\r\n--xyz--\r\n")
	if findings != 0 {
		t.Fatalf("FAIL: multipart produced unexpected findings (score=%d findings=%d)", score, findings)
	}
}
