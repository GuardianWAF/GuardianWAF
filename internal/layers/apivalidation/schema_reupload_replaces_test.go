package apivalidation

// Regression: LoadSchema appended every upload — a re-upload under the same
// operator-assigned Source.Name created a second CompiledSpec, so paths
// REMOVED from the updated spec stayed enforced by stale routes (the shared
// path router is only rebuilt here and by RemoveSchema) and the spec list
// grew once per re-upload, each entry retaining the full uploaded document.
// Identity is replace-by-name: LoadSchema now drops prior specs with the same
// Source.Name and rebuilds the router before compiling the new document.
// Discovered auditing the integration seams of the inline SchemaSource.Content
// uploads (commit c9e62d3); fixture documents are built with json.Marshal —
// no hand-typed brace literals.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// reuploadPostEntry builds one path entry whose POST body requires exactly one
// field.
func reuploadPostEntry(field string) map[string]any {
	return map[string]any{
		"post": map[string]any{
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"type":     "object",
							"required": []string{field},
						},
					},
				},
			},
		},
	}
}

// marshalReuploadSpec marshals a full OpenAPI document with the given paths.
func marshalReuploadSpec(t *testing.T, paths map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "t", "version": "1.0"},
		"paths":   paths,
	})
	if err != nil {
		t.Fatalf("marshaling spec: %v", err)
	}
	return string(b)
}

func TestSchemaReuploadReplacesIdentity(t *testing.T) {
	l := NewLayer(&Config{Enabled: true, ValidateRequest: true, StrictMode: false, BlockOnViolation: true, CacheSize: 100})
	l.enabled = true

	// v1: /a and /b, each requiring its own field.
	v1 := marshalReuploadSpec(t, map[string]any{
		"/a": reuploadPostEntry("fieldA"),
		"/b": reuploadPostEntry("fieldB"),
	})
	if err := l.LoadSchema(SchemaSource{Name: "spec", Type: "openapi", Content: v1}); err != nil {
		t.Fatalf("v1 load: %v", err)
	}

	// v2 (same operator-assigned name): /b removed, /a tightened to fieldA2.
	v2 := marshalReuploadSpec(t, map[string]any{"/a": reuploadPostEntry("fieldA2")})
	if err := l.LoadSchema(SchemaSource{Name: "spec", Type: "openapi", Content: v2}); err != nil {
		t.Fatalf("v2 load: %v", err)
	}

	// Control: /a is still enforced under the NEW contract — a body valid
	// under v1 must now be blocked by v2's required fieldA2.
	route := l.GetRoute(http.MethodPost, "/a")
	if route == nil {
		t.Fatalf("/a route vanished after re-upload")
	}
	if route.BodySchema == nil || route.BodySchema.Schema == nil {
		t.Fatalf("/a route lost its body schema")
	}
	body := `{"fieldA":"x"}` // valid under v1, violates v2's required fieldA2
	ctx := &engine.RequestContext{
		Method:      http.MethodPost,
		Path:        "/a",
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
		QueryParams: map[string][]string{},
		Body:        []byte(body),
		BodyString:  body,
	}
	if res := l.Process(ctx); res.Action != engine.ActionBlock {
		t.Fatalf("/a no longer enforces the re-uploaded contract (action=%v) — the new spec's routes were not compiled", res.Action)
	}

	// /b was REMOVED from the re-uploaded spec — its route must be purged,
	// not enforced from the stale v1 entry.
	if l.GetRoute(http.MethodPost, "/b") != nil {
		t.Fatalf("re-uploading %q left a STALE route for removed path /b — paths removed from an updated spec stay enforced by the previous version's routes", "spec")
	}

	// Identity is replace-by-name — exactly one spec remains for the
	// re-uploaded name (each duplicate retains the full uploaded document).
	if got := len(l.GetSpecs()); got != 1 {
		t.Fatalf("re-upload with the same Source.Name left %d compiled specs (expected 1)", got)
	}

	// Boundary: an unrelated second name must coexist.
	other := marshalReuploadSpec(t, map[string]any{"/c": reuploadPostEntry("fieldC")})
	if err := l.LoadSchema(SchemaSource{Name: "other", Type: "openapi", Content: other}); err != nil {
		t.Fatalf("other load: %v", err)
	}
	if l.GetRoute(http.MethodPost, "/c") == nil {
		t.Fatalf("unrelated-name schema lost its route")
	}
	if got := len(l.GetSpecs()); got != 2 {
		t.Fatalf("unrelated upload changed the spec count unexpectedly: %d", got)
	}
}

// TestSchemaReuploadStrictModeContract pins that a re-uploaded spec is
// enforced under the layer's global strict mode exactly like a first load:
// with StrictMode enabled and only the re-uploaded /a loaded, a request to
// the now-absent /b is blocked as "no schema defined" rather than passing
// through a stale allowance.
func TestSchemaReuploadStrictModeContract(t *testing.T) {
	l := NewLayer(&Config{Enabled: true, ValidateRequest: true, StrictMode: true, BlockOnViolation: true, CacheSize: 100})
	l.enabled = true

	v1 := marshalReuploadSpec(t, map[string]any{
		"/a": reuploadPostEntry("fieldA"),
		"/b": reuploadPostEntry("fieldB"),
	})
	if err := l.LoadSchema(SchemaSource{Name: "spec", Type: "openapi", Content: v1}); err != nil {
		t.Fatalf("v1 load: %v", err)
	}
	v2 := marshalReuploadSpec(t, map[string]any{"/a": reuploadPostEntry("fieldA2")})
	if err := l.LoadSchema(SchemaSource{Name: "spec", Type: "openapi", Content: v2}); err != nil {
		t.Fatalf("v2 load: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:      http.MethodPost,
		Path:        "/b",
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
	}
	res := l.Process(ctx)
	if res.Action != engine.ActionBlock {
		t.Fatalf("strict mode: request to removed path /b was not blocked (action=%v)", res.Action)
	}
	if len(res.Findings) == 0 || !strings.Contains(res.Findings[0].Description, "No OpenAPI schema defined") {
		t.Fatalf("strict mode: unexpected findings for removed path /b: %+v", res.Findings)
	}
}
