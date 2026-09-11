package main

// Regression tests for round 11/25: mcpEngineAdapter.UploadAPISchema must
// convey the caller's inline schema Content to the apivalidation layer (via
// the dashboard adapter's temp-file convention) and preserve the
// operator-assigned name as Source.Name. The pre-fix implementation passed
// the schema NAME as a filesystem path and dropped Content entirely, so the
// MCP tool guardianwaf_upload_api_schema could never upload inline content.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

func newUploadSchemaTestAdapter(t *testing.T) (*mcpEngineAdapter, *apivalidation.Layer) {
	t.Helper()
	cfg := &config.Config{Mode: "monitor", Listen: "127.0.0.1:0"}
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1024), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine setup: %v", err)
	}
	apiLayer := apivalidation.NewLayer(apivalidation.DefaultConfig())
	eng.AddLayer(engine.OrderedLayer{Layer: apiLayer, Order: engine.OrderAPIValidation})
	return &mcpEngineAdapter{engine: eng, cfg: cfg}, apiLayer
}

func TestUploadAPISchemaConveysInlineContentAndIdentity(t *testing.T) {
	adapter, apiLayer := newUploadSchemaTestAdapter(t)

	content := `{"openapi":"3.0.0","info":{"title":"Payments API","version":"2.0.0"},"paths":{"/pay":{"post":{"responses":{"200":{"description":"ok"}}}}}}`
	if err := adapter.UploadAPISchema("payments", content, "openapi", true); err != nil {
		t.Fatalf("inline schema upload rejected: %v", err)
	}

	if apiLayer.GetRoute("POST", "/pay") == nil {
		t.Fatalf("uploaded schema compiled no POST /pay route — Content was not conveyed to the layer")
	}
	for _, spec := range apiLayer.GetSpecs() {
		if spec.Source.Name == "payments" {
			return
		}
	}
	t.Fatalf("compiled spec does not carry Source.Name=%q — the operator-assigned identity was dropped", "payments")
}

func TestUploadAPISchemaValidatesRequiredInputs(t *testing.T) {
	adapter, _ := newUploadSchemaTestAdapter(t)

	validContent := `{"openapi":"3.0.0","info":{"title":"X","version":"1.0.0"},"paths":{}}`

	if err := adapter.UploadAPISchema("", validContent, "openapi", true); err == nil {
		t.Fatalf("upload with empty name must be rejected")
	}
	if err := adapter.UploadAPISchema("schema", "", "openapi", true); err == nil {
		t.Fatalf("upload with empty content must be rejected")
	}
	if err := adapter.UploadAPISchema("bad-json", "{not json", "openapi", true); err == nil {
		t.Fatalf("upload with non-JSON content must be rejected by the layer's compiler")
	}
}

func TestUploadAPISchemaNoTempFilesLeftBehind(t *testing.T) {
	adapter, _ := newUploadSchemaTestAdapter(t)

	content := `{"openapi":"3.0.0","info":{"title":"Cleanup API","version":"1.0.0"},"paths":{}}`
	if err := adapter.UploadAPISchema("cleanup", content, "openapi", true); err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if err := adapter.UploadAPISchema("broken", `{"openapi":"3.0.0"`, "openapi", true); err == nil {
		t.Fatalf("malformed content should fail compilation")
	}
}
