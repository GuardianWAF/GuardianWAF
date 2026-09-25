package apivalidation

// Regression (round 2026-09-24-r30-body-ct-selection): compileOperation
// selected the route's enforcing BodySchema by breaking on the first map-
// iterated requestBody content entry with a schema. Map iteration order is
// random, so a requestBody declaring multiple content types with different
// schemas compiled a boot-dependent BodySchema — one restart enforced the
// application/json contract, the next an XML variant — violating the
// contract validateRequestBody documents ("the compiled body schema comes
// from the spec's application/json entry"). Selection is now deterministic:
// application/json preferred, else the lexicographically first content type
// with a schema.

import (
	"fmt"
	"os"
	"testing"
)

const regressionSpecBody = `{"openapi":"3.0.0","info":{"title":"ct","version":"1"},"paths":{"/thing":{"post":{"requestBody":{"required":true,"content":{"text/plain":{"schema":{"type":"string","maxLength":1000}},"application/json":{"schema":{"type":"string","maxLength":1}}}},"responses":{"200":{"description":"ok"}}}}}}`

func TestBodySchemaSelectionPrefersApplicationJSON(t *testing.T) {
	tmp, err := os.CreateTemp(".", "regression-ct-*.json")
	if err != nil {
		t.Fatalf("stage spec: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, werr := tmp.WriteString(regressionSpecBody); werr != nil {
		t.Fatalf("write spec: %v", werr)
	}
	tmp.Close()

	// Eight loads: pre-fix, the probability that every load iterated
	// application/json first was 2^-8 — the old behavior fails this
	// near-certainly, the fixed behavior always passes.
	for i := 0; i < 8; i++ {
		l := NewLayer(DefaultConfig())
		src := SchemaSource{Type: "openapi", Path: tmp.Name(), Name: fmt.Sprintf("s%d", i)}
		if lerr := l.LoadSchema(src); lerr != nil {
			t.Fatalf("load %d: %v", i, lerr)
		}
		route := l.GetRoute("POST", "/thing")
		if route == nil || route.BodySchema == nil || route.BodySchema.Schema == nil {
			t.Fatalf("load %d: route/body schema missing", i)
		}
		maxLen := route.BodySchema.Schema.MaxLength
		if maxLen == nil || *maxLen != 1 {
			t.Fatalf("load %d: BodySchema came from the wrong content type (MaxLength=%v, want 1 from application/json)", i, maxLen)
		}
	}

	// Control: a single-content-type spec compiles its own schema.
	single := NewLayer(DefaultConfig())
	singleSrc := SchemaSource{
		Type: "openapi",
		Path: mustWriteSingleCTSpec(t),
		Name: "single",
	}
	if err := single.LoadSchema(singleSrc); err != nil {
		t.Fatalf("single-content-type load: %v", err)
	}
	route := single.GetRoute("POST", "/thing")
	if route == nil || route.BodySchema == nil || route.BodySchema.Schema == nil {
		t.Fatalf("single-content-type: route/body schema missing")
	}
	if maxLen := route.BodySchema.Schema.MaxLength; maxLen == nil || *maxLen != 7 {
		t.Fatalf("single-content-type: MaxLength=%v, want 7", maxLen)
	}
}

func mustWriteSingleCTSpec(t *testing.T) string {
	t.Helper()
	tmp, err := os.CreateTemp(".", "regression-ct-single-*.json")
	if err != nil {
		t.Fatalf("stage single spec: %v", err)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	spec := `{"openapi":"3.0.0","info":{"title":"single","version":"1"},"paths":{"/thing":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"string","maxLength":7}}}},"responses":{"200":{"description":"ok"}}}}}}`
	if _, werr := tmp.WriteString(spec); werr != nil {
		t.Fatalf("write single spec: %v", werr)
	}
	tmp.Close()
	return tmp.Name()
}
