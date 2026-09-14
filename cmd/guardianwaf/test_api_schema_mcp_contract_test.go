package main

import (
	"os"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

// Regression (hunt round 5/25): mcpEngineAdapter.TestAPISchema accepted
// method, path AND body but never used the body — it only checked route
// existence, so ANY body against a known route returned {"valid": true}.
// The dashboard adapter had the same disease once (its fixed code comments
// that the old stub "manufactured pass results") and now drives the layer's
// real Process pipeline; the MCP tool must do the same.

func newAPISchemaHarness(t *testing.T) (*mcpEngineAdapter, *apivalidation.Layer) {
	t.Helper()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lcfg := apivalidation.DefaultConfig()
	lcfg.Enabled = true
	lcfg.ValidateRequest = true
	apiLayer := apivalidation.NewLayer(lcfg)
	eng.AddLayer(engine.OrderedLayer{Layer: apiLayer, Order: engine.OrderAPIValidation})
	if eng.FindLayer("apivalidation") != engine.Layer(apiLayer) {
		t.Fatal("harness: FindLayer did not resolve the added apivalidation layer")
	}
	return &mcpEngineAdapter{engine: eng, cfg: cfg}, apiLayer
}

// loadInlineSchema stages the schema content in a temp file and loads it —
// the established inline-upload route (apivalidation.SchemaSource has no
// content field; Source.Name is the compiled spec's identity key). The
// layer's readFile confines schema paths to the working directory, so the
// staging file is created there (os.CreateTemp("."), the convention the
// dashboard adapter uses).
func loadInlineSchema(t *testing.T, apiLayer *apivalidation.Layer, name, schema string) {
	t.Helper()
	f, err := os.CreateTemp(".", name+".schema-*.json")
	if err != nil {
		t.Fatalf("stage schema: %v", err)
	}
	path := f.Name()
	t.Cleanup(func() { os.Remove(path) })
	if _, err := f.WriteString(schema); err != nil {
		f.Close()
		t.Fatalf("stage schema: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("stage schema: %v", err)
	}
	if err := apiLayer.LoadSchema(apivalidation.SchemaSource{Type: "jsonschema", Path: path, Name: name}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
}

func TestMCPTestAPISchemaValidatesBody(t *testing.T) {
	adapter, apiLayer := newAPISchemaHarness(t)
	loadInlineSchema(t, apiLayer, "pets", `{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)

	// Defect path: valid JSON that violates the required "name" field must
	// come back invalid with a violation — not a manufactured pass.
	out, err := adapter.TestAPISchema("POST", "/*", `{"tag":"no-name-here"}`)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", out)
	}
	if valid, _ := m["valid"].(bool); valid {
		t.Fatalf("FAIL: TestAPISchema returned valid=true for a body violating the required \"name\" field (body parameter ignored — route existence only)")
	}
	if violations, _ := m["violations"].([]any); len(violations) == 0 {
		t.Fatalf("FAIL: violations list is empty for a schema-violating body")
	}

	// Control: a conforming body stays valid (no false positives).
	out, err = adapter.TestAPISchema("POST", "/*", `{"name":"ok"}`)
	if err != nil {
		t.Fatal(err)
	}
	m = out.(map[string]any)
	if valid, _ := m["valid"].(bool); !valid {
		t.Fatalf("FAIL: conforming body reported invalid: %v", m["violations"])
	}
}
