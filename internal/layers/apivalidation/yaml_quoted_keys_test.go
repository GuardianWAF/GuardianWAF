package apivalidation

import "testing"

// TestYAML_QuotedKeysAreUnquoted pins the key-side quote stripping in
// parseYAMLLine (unquoteYAMLKey). Machine written OpenAPI YAML routinely
// quotes keys — entirely legal YAML — and the parsed map previously kept the
// literal quote characters: a quoted path key compiled to a route pattern
// anchoring on real quote characters, which no request path contains, so the
// route could never match (silent contract loss in lenient mode; endpoint
// blocked in strict mode). parseYAMLValue already stripped quotes from
// values; keys needed the same treatment.
func TestYAML_QuotedKeysAreUnquoted(t *testing.T) {
	quotedSpec := []byte(`openapi: "3.0.0"
info:
  title: pets
  version: "1.0.0"
paths:
  "/pets/{id}":
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: ok
`)

	spec, err := LoadYAMLSpec(quotedSpec)
	if err != nil {
		t.Fatalf("LoadYAMLSpec: %v", err)
	}

	// Quoted path key must arrive unquoted.
	pathItem, ok := spec.Paths["/pets/{id}"]
	if !ok {
		keys := make([]string, 0, len(spec.Paths))
		for k := range spec.Paths {
			keys = append(keys, k)
		}
		t.Fatalf("path key %q not unquoted; Paths keys = %q", "/pets/{id}", keys)
	}
	if pathItem.Get == nil {
		t.Fatal("expected get operation on /pets/{id}")
	}

	// Quoted response-code key must arrive unquoted.
	if _, ok := pathItem.Get.Responses["200"]; !ok {
		keys := make([]string, 0, len(pathItem.Get.Responses))
		for k := range pathItem.Get.Responses {
			keys = append(keys, k)
		}
		t.Fatalf("response key %q not unquoted; Responses keys = %q", "200", keys)
	}

	// Quoted values keep stripping (control).
	if spec.Info.Version != "1.0.0" {
		t.Fatalf("quoted value stripped keys? Info.Version = %q", spec.Info.Version)
	}

	// End to end: the compiled route must match a real request path.
	l := NewLayer(DefaultConfig())
	compiled := &CompiledSpec{
		Source: SchemaSource{Type: "openapi", Path: "inline-quoted"},
		Spec:   spec,
		Routes: make(map[string]*RouteInfo),
	}
	l.compileRoutes(compiled)
	if l.router.Match("GET", "/pets/123") == nil {
		t.Fatal("route for GET /pets/123 not found from quoted-key spec")
	}
}

// TestYAML_UnquotedKeysStillWork guards against over-correcting: the plain
// unquoted OpenAPI shapes must parse exactly as before.
func TestYAML_UnquotedKeysStillWork(t *testing.T) {
	unquotedSpec := []byte(`openapi: "3.0.0"
info:
  title: pets
  version: 1.0.0
paths:
  /pets/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
`)

	spec, err := LoadYAMLSpec(unquotedSpec)
	if err != nil {
		t.Fatalf("LoadYAMLSpec: %v", err)
	}
	if _, ok := spec.Paths["/pets/{id}"]; !ok {
		t.Fatalf("path key /pets/{id} missing; Paths = %v", spec.Paths)
	}

	l := NewLayer(DefaultConfig())
	compiled := &CompiledSpec{
		Source: SchemaSource{Type: "openapi", Path: "inline-unquoted"},
		Spec:   spec,
		Routes: make(map[string]*RouteInfo),
	}
	l.compileRoutes(compiled)
	if l.router.Match("GET", "/pets/123") == nil {
		t.Fatal("route for GET /pets/123 not found from unquoted-key spec")
	}
}
