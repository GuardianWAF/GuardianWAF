package apivalidation

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (round 3/25): RemoveSchema pruned l.specs but left the compiled
// routes in l.router. Process resolves routes via l.router.Match — never via
// l.specs — so a "removed" schema kept enforcing its contract indefinitely:
// the dashboard DELETE reported success while violating requests stayed
// blocked by stale routes, and a spec revision that dropped a path kept
// validating the dropped endpoint against the obsolete contract.
// RemoveSchema must rebuild the router from the remaining specs.

const removeStaleRouterSpecA = `{
  "openapi": "3.0.0",
  "info": {"title": "pets", "version": "1.0.0"},
  "paths": {
    "/pets/{id}": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {"name": {"type": "string"}}
              }
            }
          }
        }
      }
    }
  }
}`

const removeStaleRouterSpecB = `{
  "openapi": "3.0.0",
  "info": {"title": "health", "version": "1.0.0"},
  "paths": {
    "/health": {"get": {}}
  }
}`

func violatingPetsRequest() *engine.RequestContext {
	return &engine.RequestContext{
		Method:     "POST",
		Path:       "/pets/123",
		Body:       []byte(`{"other":1}`),
		BodyString: `{"other":1}`,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
	}
}

func TestRemoveSchemaStopsEnforcement(t *testing.T) {
	pathA := writeTestFile(t, "remove_stale_a.json", []byte(removeStaleRouterSpecA))
	pathB := writeTestFile(t, "remove_stale_b.json", []byte(removeStaleRouterSpecB))

	l := NewLayer(&Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
		StrictMode:       false,
		ViolationScore:   40,
		CacheSize:        100,
	})
	if err := l.LoadSchema(SchemaSource{Path: pathA, Type: "openapi"}); err != nil {
		t.Fatalf("FAIL: LoadSchema(A): %v", err)
	}
	if err := l.LoadSchema(SchemaSource{Path: pathB, Type: "openapi"}); err != nil {
		t.Fatalf("FAIL: LoadSchema(B): %v", err)
	}

	// Baseline: while A is loaded, its body contract is enforced.
	if res := l.Process(violatingPetsRequest()); len(res.Findings) == 0 {
		t.Fatalf("FAIL: baseline: schema A body contract not enforced")
	}

	if !l.RemoveSchema(pathA) {
		t.Fatalf("FAIL: RemoveSchema returned false for a loaded schema")
	}
	if got := len(l.GetSpecs()); got != 1 {
		t.Fatalf("FAIL: GetSpecs after removal = %d, want 1", got)
	}

	// The removed schema's contract must no longer be enforced: no remaining
	// spec declares /pets and strict mode is off, so the request passes.
	if res := l.Process(violatingPetsRequest()); len(res.Findings) != 0 || res.Action != engine.ActionPass {
		t.Fatalf("FAIL: removed schema still enforced: %d finding(s), action=%s", len(res.Findings), res.Action)
	}

	// The remaining spec keeps serving, and the router no longer counts the
	// removed schema's routes.
	if res := l.Process(&engine.RequestContext{Method: "GET", Path: "/health"}); len(res.Findings) != 0 || res.Action != engine.ActionPass {
		t.Fatalf("FAIL: GET /health flagged after removal: %d finding(s), action=%s", len(res.Findings), res.Action)
	}
	if got := l.GetStats().RoutesDefined; got != 1 {
		t.Fatalf("FAIL: GetStats.RoutesDefined after removal = %d, want 1 (stale route counted)", got)
	}
}

func TestSchemaReloadDroppedPathStopsEnforcement(t *testing.T) {
	specA1 := `{
  "openapi": "3.0.0",
  "info": {"title": "v1", "version": "1.0.0"},
  "paths": {
    "/pets/{id}": {
      "post": {
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["name"],
                "properties": {"name": {"type": "string"}}
              }
            }
          }
        }
      }
    },
    "/health": {"get": {}}
  }
}`
	specA2 := `{
  "openapi": "3.0.0",
  "info": {"title": "v2", "version": "1.0.0"},
  "paths": {
    "/health": {"get": {}}
  }
}`
	pathV1 := writeTestFile(t, "reload_v1.json", []byte(specA1))
	pathV2 := writeTestFile(t, "reload_v2.json", []byte(specA2))

	l := NewLayer(&Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
		StrictMode:       false,
		ViolationScore:   40,
		CacheSize:        100,
	})
	if err := l.LoadSchema(SchemaSource{Path: pathV1, Type: "openapi"}); err != nil {
		t.Fatalf("FAIL: LoadSchema(v1): %v", err)
	}
	if res := l.Process(violatingPetsRequest()); len(res.Findings) == 0 {
		t.Fatalf("FAIL: baseline: v1 body contract not enforced")
	}

	// Operator revises the spec to drop /pets: remove v1, load v2.
	if !l.RemoveSchema(pathV1) {
		t.Fatalf("FAIL: RemoveSchema returned false for a loaded schema")
	}
	if err := l.LoadSchema(SchemaSource{Path: pathV2, Type: "openapi"}); err != nil {
		t.Fatalf("FAIL: LoadSchema(v2): %v", err)
	}

	// The dropped endpoint must not stay validated against the v1 contract.
	if res := l.Process(violatingPetsRequest()); len(res.Findings) != 0 || res.Action != engine.ActionPass {
		t.Fatalf("FAIL: dropped path still validated after reload: %d finding(s), action=%s", len(res.Findings), res.Action)
	}
}
