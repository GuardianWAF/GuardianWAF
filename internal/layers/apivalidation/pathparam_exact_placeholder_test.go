package apivalidation

// Regression: a path parameter must resolve to its OWN path segment.
//
// extractPathParam matched a route placeholder by SUBSTRING
// (strings.Contains(part, paramName)) and returned on the first hit, so for
// the very common OpenAPI route /users/{user_id}/posts/{id} the "id"
// parameter matched {user_id} first and returned the user_id SEGMENT value.
// The id schema was then applied to the wrong field: a value violating the id
// schema passed silently, and a legitimate user_id value was reported against
// "id".
//
// Placeholders are whole segments by construction (compilePathPattern turns
// each {name} into one capture group), so exact equality is the correct match.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// paramSpecDoc marshals a single-GET OpenAPI document with the given path and
// path parameters. json.Marshal keeps the document balanced by construction.
func paramSpecDoc(t *testing.T, path string, params []map[string]any) string {
	t.Helper()
	paramList := make([]any, 0, len(params))
	for _, p := range params {
		paramList = append(paramList, p)
	}
	b, err := json.Marshal(map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "t", "version": "1.0"},
		"paths": map[string]any{
			path: map[string]any{"get": map[string]any{"parameters": paramList}},
		},
	})
	if err != nil {
		t.Fatalf("marshaling spec: %v", err)
	}
	return string(b)
}

func paramSpecLayer(t *testing.T, spec string) *Layer {
	t.Helper()
	l := NewLayer(&Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
		CacheSize:        100,
	})
	l.enabled = true
	if err := l.LoadSchema(SchemaSource{Type: "openapi", Content: spec, Name: "params.yaml"}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return l
}

func paramSpecReq(path string) *engine.RequestContext {
	return &engine.RequestContext{
		Method:      http.MethodGet,
		Path:        path,
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
		Cookies:     map[string][]string{},
	}
}

// TestExtractPathParam_ExactPlaceholder pins the unit-level contract: the "id"
// parameter resolves to the id segment, not the preceding {user_id} segment.
func TestExtractPathParam_ExactPlaceholder(t *testing.T) {
	l := NewLayer(&Config{Enabled: true})

	cases := []struct{ param, want string }{
		{"id", "9999"},
		{"user_id", "5"},
	}
	for _, tc := range cases {
		if got := l.extractPathParam("/users/5/posts/9999", "/users/{user_id}/posts/{id}", tc.param); got != tc.want {
			t.Errorf("extractPathParam(%q) = %q, want %q", tc.param, got, tc.want)
		}
	}
}

// TestPathParamConstraintNotHijackedByLongerName is the contract-level
// regression: the id schema is enforced against the id segment.
//
// The constraint is a string keyword (maxLength), not "type: integer":
// path-parameter values are always strings (they come from strings.Split of
// the URL path), so an integer type would confound this with a separate
// pre-existing behavior.
func TestPathParamConstraintNotHijackedByLongerName(t *testing.T) {
	// Control: a single-parameter route has no name overlap and must be
	// enforced exactly as declared.
	single := paramSpecLayer(t, paramSpecDoc(t, "/items/{id}", []map[string]any{{
		"name": "id", "in": "path", "required": true,
		"schema": map[string]any{"type": "string", "maxLength": 3},
	}}))

	if f := single.Process(paramSpecReq("/items/abc")).Findings; len(f) != 0 {
		t.Fatalf("control: /items/abc is compliant but produced %d findings: %+v", len(f), f)
	}
	if single.Process(paramSpecReq("/items/9999")).Action != engine.ActionBlock {
		t.Fatal("control: /items/9999 violates maxLength 3 but was not blocked")
	}

	// The defect: overlapping placeholder names.
	l := paramSpecLayer(t, paramSpecDoc(t, "/users/{user_id}/posts/{id}", []map[string]any{
		{"name": "user_id", "in": "path", "required": true,
			"schema": map[string]any{"type": "string"}},
		{"name": "id", "in": "path", "required": true,
			"schema": map[string]any{"type": "string", "maxLength": 3}},
	}))

	if l.GetRoute(http.MethodGet, "/users/5/posts/9999") == nil {
		t.Fatal("control: route /users/{user_id}/posts/{id} did not resolve")
	}

	// Bypass direction: id=9999 is 4 chars and violates maxLength 3.
	if f := l.Process(paramSpecReq("/users/5/posts/9999")).Findings; len(f) == 0 {
		t.Fatal("id=9999 violates the id schema (maxLength 3) but was not reported — " +
			"the {user_id} placeholder hijacked the id parameter")
	}

	// Compliant request: id=3 is 3 chars and satisfies the id schema. A
	// false positive here means the id schema is being applied to user_id.
	if f := l.Process(paramSpecReq("/users/5/posts/3")).Findings; len(f) != 0 {
		t.Fatalf("/users/5/posts/3 is spec-compliant yet produced %d findings: %+v — "+
			"the id schema is being applied to the user_id segment", len(f), f)
	}
}
