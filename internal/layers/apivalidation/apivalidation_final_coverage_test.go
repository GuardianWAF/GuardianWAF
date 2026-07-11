package apivalidation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestFinalLayerBranches(t *testing.T) {
	l := NewLayer(nil)
	if l.Order() != engine.OrderAPIValidation {
		t.Fatal("wrong order")
	}
	if NewPathRouter().Match("TRACE", "/none") != nil {
		t.Fatal("unexpected route")
	}

	if _, err := l.loadJSONSchema("missing-file"); err == nil {
		t.Fatal("expected read error")
	}
	bad := writeTestFile(t, "bad-schema.json", []byte("{"))
	if _, err := l.loadJSONSchema(bad); err == nil {
		t.Fatal("expected JSON error")
	}
	if _, err := l.readFile(string([]byte{'x', 0})); err == nil {
		t.Fatal("expected path error")
	}

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.StrictMode = false
	l = NewLayer(cfg)
	ctx := &engine.RequestContext{Method: "GET", Path: "/none"}
	if got := l.Process(ctx); got.Action != engine.ActionPass {
		t.Fatal(got.Action)
	}
	l.specs = []*CompiledSpec{{}}
	if got := l.Process(ctx); got.Action != engine.ActionPass {
		t.Fatal(got.Action)
	}

	cfg.StrictMode = true
	if got := l.Process(ctx); got.Action != engine.ActionBlock {
		t.Fatal(got.Action)
	}
	tenant := &config.WAFConfig{}
	ctx.TenantWAFConfig = tenant
	if got := l.Process(ctx); got.Action != engine.ActionPass {
		t.Fatal(got.Action)
	}

	route := &RouteInfo{Path: "/users/{id}", Parameters: []CompiledParameter{
		{Name: "missing", In: "path", Required: true},
		{Name: "optional", In: "path"},
		{Name: "q", In: "query", Schema: &Schema{Type: "integer"}},
	}}
	ctx = &engine.RequestContext{Path: "/users/abc", QueryParams: map[string][]string{"q": {"bad"}}}
	v := NewSchemaValidator(true)
	if len(l.validatePathParameters(ctx, route, v)) != 1 {
		t.Fatal("expected missing path finding")
	}
	if len(l.validateQueryParameters(ctx, route, v)) != 1 {
		t.Fatal("expected query finding")
	}
	if got := l.extractPathParam("/different/abc", "/users/{id}", "id"); got != "" {
		t.Fatal(got)
	}
	if got := l.extractPathParam("/users", "/users/{id}", "id"); got != "" {
		t.Fatal(got)
	}

	bodyRoute := &RouteInfo{BodySchema: &CompiledBodySchema{Schema: &Schema{Type: "object", Required: []string{"name"}}}}
	ctx = &engine.RequestContext{Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, QueryParams: map[string][]string{"x": {"a", "b"}}, Body: []byte("x")}
	if len(l.validateRequestBody(ctx, bodyRoute, v)) == 0 {
		t.Fatal("expected form finding")
	}
}

func TestFinalSchemaAndYAMLBranches(t *testing.T) {
	if got := getJSONType(struct{}{}); got != "unknown" {
		t.Fatal(got)
	}
	data := []byte("items:\n  - one\n  - two\nobjects:\n  - thing:\n      value: yes\n")
	if _, err := parseYAML(data); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadYAMLSpec([]byte("info: nope\n")); err == nil {
		t.Fatal("expected spec type error")
	}
	var out map[string]any
	if err := SimpleYAMLUnmarshal(nil, &out); err == nil {
		t.Fatal("expected empty YAML error")
	}

	// A directory passes confinement but cannot be read as a regular schema file.
	dir := filepath.Join(".", ".test_tmp", t.Name())
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if _, err := NewLayer(nil).readFile(dir); err == nil {
		t.Fatal("expected directory read error")
	}
}
