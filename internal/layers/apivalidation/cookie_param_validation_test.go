package apivalidation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests (round 82): in:cookie parameters were compiled into
// route.Parameters but skipped by every validator — path/query/header each
// filter on their own In value and no cookie validator existed. A spec
// declaring cookie parameters was silently unenforced: violating cookie
// values and missing required cookies passed with zero findings. Cookie
// parameters are now validated like the other parameter locations (required
// missing → ViolationScore/2; present values → schema validation; optional
// absent → clean).

const cookieSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "cookie-validation", "version": "1.0.0"},
  "paths": {
    "/orders": {
      "get": {
        "parameters": [
          {
            "name": "session_id",
            "in": "cookie",
            "required": true,
            "schema": {"type": "string", "enum": ["alpha", "beta"]}
          },
          {
            "name": "X-Api-Version",
            "in": "header",
            "required": true,
            "schema": {"type": "string", "enum": ["v1", "v2"]}
          }
        ],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/sessions": {
      "get": {
        "parameters": [
          {
            "name": "theme",
            "in": "cookie",
            "required": false,
            "schema": {"type": "string", "enum": ["light", "dark"]}
          }
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func newCookieLayer(t *testing.T) *Layer {
	t.Helper()

	layer := NewLayer(&Config{Enabled: true, ValidateRequest: true})
	path := filepath.Join("cookie_spec_", "spec.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(cookieSpec), 0o600); err != nil {
		t.Fatalf("writing spec: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path)) })
	if err := layer.LoadSchema(SchemaSource{Type: "openapi", Path: path}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

type cookieCall struct {
	path    string
	headers map[string][]string
	cookies map[string][]string
}

func runCookie(t *testing.T, c cookieCall) engine.LayerResult {
	t.Helper()

	if c.path == "" {
		c.path = "/orders"
	}
	if c.headers == nil {
		c.headers = map[string][]string{"X-Api-Version": {"v1"}}
	}
	layer := newCookieLayer(t)
	return layer.Process(&engine.RequestContext{
		Method:  "GET",
		Path:    c.path,
		Headers: c.headers,
		Cookies: c.cookies,
	})
}

func cookieDescriptions(r engine.LayerResult) string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Description)
	}
	return strings.Join(out, "; ")
}

func TestCookieParamViolatingValueDetected(t *testing.T) {
	result := runCookie(t, cookieCall{cookies: map[string][]string{"session_id": {"omega"}}})
	if len(result.Findings) == 0 || !strings.Contains(cookieDescriptions(result), "session_id") {
		t.Fatalf("FAIL: session_id=omega violates the declared enum but produced no session_id finding: %q", cookieDescriptions(result))
	}
}

func TestCookieParamRequiredMissingDetected(t *testing.T) {
	result := runCookie(t, cookieCall{})
	if len(result.Findings) == 0 || !strings.Contains(cookieDescriptions(result), "session_id") {
		t.Fatalf("FAIL: request without the required session_id cookie produced no session_id finding: %q", cookieDescriptions(result))
	}
	if !strings.Contains(cookieDescriptions(result), "missing") {
		t.Fatalf("FAIL: expected required-missing finding, got: %q", cookieDescriptions(result))
	}
}

func TestCookieParamAllValidNotFlagged(t *testing.T) {
	// No over-blocking: a fully valid request stays clean.
	result := runCookie(t, cookieCall{cookies: map[string][]string{"session_id": {"alpha"}}})
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: all-valid request produced findings: %q", cookieDescriptions(result))
	}
}

func TestCookieParamOptionalAbsentNotFlagged(t *testing.T) {
	result := runCookie(t, cookieCall{path: "/sessions"})
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: absent optional cookie flagged: %q", cookieDescriptions(result))
	}
}

func TestCookieParamOptionalPresentViolatingDetected(t *testing.T) {
	// An optional cookie that IS present must still satisfy its schema.
	result := runCookie(t, cookieCall{path: "/sessions", cookies: map[string][]string{"theme": {"neon"}}})
	if len(result.Findings) == 0 || !strings.Contains(cookieDescriptions(result), "theme") {
		t.Fatalf("FAIL: present-but-violating optional cookie produced no theme finding: %q", cookieDescriptions(result))
	}
}

func TestCookieParamOptionalValidClean(t *testing.T) {
	result := runCookie(t, cookieCall{path: "/sessions", cookies: map[string][]string{"theme": {"dark"}}})
	if len(result.Findings) != 0 {
		t.Fatalf("FAIL: valid optional cookie flagged: %q", cookieDescriptions(result))
	}
}

func TestCookieParamEmptyValueStillValidated(t *testing.T) {
	// "session_id=" TRANSMITS a cookie with an empty value — present, not
	// missing. It must fail the enum as a value violation, not be reported
	// as absent (pins the exists-vs-empty semantics of the missing branch).
	result := runCookie(t, cookieCall{cookies: map[string][]string{"session_id": {""}}})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: empty-value cookie produced no findings")
	}
	if strings.Contains(cookieDescriptions(result), "missing") {
		t.Fatalf("FAIL: transmitted empty cookie misreported as missing: %q", cookieDescriptions(result))
	}
}

func TestCookieParamMatchedValueIsOffendingValue(t *testing.T) {
	result := runCookie(t, cookieCall{cookies: map[string][]string{"session_id": {"omega"}}})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: expected findings")
	}
	if got := result.Findings[0].MatchedValue; got != "omega" {
		t.Fatalf("FAIL: MatchedValue = %v, want the offending value omega", got)
	}
}

func TestCookieParamHeaderControlStillDetected(t *testing.T) {
	// Fixture sanity: the non-cookie validators in the same spec still fire.
	result := runCookie(t, cookieCall{
		headers: map[string][]string{"X-Api-Version": {"v3"}},
		cookies: map[string][]string{"session_id": {"alpha"}},
	})
	if len(result.Findings) == 0 || !strings.Contains(cookieDescriptions(result), "X-Api-Version") {
		t.Fatalf("FAIL: violating header produced no X-Api-Version finding: %q", cookieDescriptions(result))
	}
}

func TestCookieParamViolatingSecondValueDetected(t *testing.T) {
	// Round 84: a repeated cookie name transmits multiple values and backend
	// parsers disagree on which one they select (Go first-wins, PHP/Python
	// last-wins). EVERY transmitted value must satisfy the schema — a valid
	// first value must not shield a violating second one.
	result := runCookie(t, cookieCall{cookies: map[string][]string{"session_id": {"alpha", "omega"}}})
	if len(result.Findings) == 0 {
		t.Fatalf("FAIL: second violating cookie value produced no findings")
	}
}
