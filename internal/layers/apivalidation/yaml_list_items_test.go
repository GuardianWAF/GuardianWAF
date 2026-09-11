package apivalidation

// Regression tests for round 19/25: parseYAML's array branch discarded the
// key of any "- key: value" array item (only parseYAMLValue(value) was
// appended), so the standard OpenAPI list-of-objects shape — parameters,
// rules, servers — mangled into a flat list of scalars plus stray keys at
// the parent level, and LoadYAMLSpec failed unmarshaling the result into
// OpenAPISpec ("cannot unmarshal object into ... []Parameter"). The fix:
// multi-key items build an item object, append it, and descend into it so
// continuation keys land inside the same item; the array's owner/key are
// captured at array start (arrayOwner/arrayKey) instead of re-reading the
// stale currentKey per item.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestYAMLListOfObjectsKeepsItemShape(t *testing.T) {
	yamlDoc := []byte(`rules:
  - id: global
    scope: ip
    limit: 100
  - id: other
    scope: path
`)
	data, err := YAMLToJSON(yamlDoc)
	if err != nil {
		t.Fatalf("YAMLToJSON: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("generated JSON is not an object: %v (%s)", err, data)
	}
	rulesRaw, ok := doc["rules"].([]any)
	if !ok {
		t.Fatalf("FAIL items-not-array: rules is %T (%v), want an array of objects", doc["rules"], doc["rules"])
	}
	if len(rulesRaw) != 2 {
		t.Fatalf("FAIL item-count: %d items, want 2", len(rulesRaw))
	}
	want := []map[string]any{
		{"id": "global", "scope": "ip", "limit": float64(100)},
		{"id": "other", "scope": "path"},
	}
	for i, item := range want {
		got, ok := rulesRaw[i].(map[string]any)
		if !ok {
			t.Fatalf("FAIL item-shape: item %d is %T, want an object", i, rulesRaw[i])
		}
		for k, v := range item {
			if got[k] != v {
				t.Fatalf("FAIL item-field: item %d %s = %v, want %v", i, k, got[k], v)
			}
		}
	}
}

func TestYAMLSpecWithParameterListLoads(t *testing.T) {
	yamlDoc := []byte(`openapi: 3.0.0
info:
  title: Regression API
  version: "1.0.0"
paths:
  /items:
    get:
      parameters:
        - name: limit
          in: query
          required: true
          schema:
            type: integer
      responses:
        "200":
          description: ok
`)
	spec, err := LoadYAMLSpec(yamlDoc)
	if err != nil {
		t.Fatalf("FAIL spec-load-failed: a standard YAML spec with a parameter list must load: %v", err)
	}
	if !strings.Contains(spec.Info.Title, "Regression") {
		t.Fatalf("FAIL info-lost: title = %q", spec.Info.Title)
	}
	get := spec.Paths["/items"].Get
	if get == nil {
		t.Fatalf("FAIL route-lost: /items GET missing from the loaded spec")
	}
	if len(get.Parameters) != 1 {
		t.Fatalf("FAIL parameter-count: %d parameters, want 1", len(get.Parameters))
	}
	p := get.Parameters[0]
	if p.Name != "limit" || p.In != "query" || !p.Required {
		t.Fatalf("FAIL parameter-fields: %+v", p)
	}
	if p.Schema == nil || p.Schema.Type != "integer" {
		t.Fatalf("FAIL parameter-schema-mangled: %+v", p.Schema)
	}
}
