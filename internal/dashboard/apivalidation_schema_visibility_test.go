package dashboard

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

// Regression: the schema list/detail endpoints were always-empty/404 —
//
// Defect: apiValidationAdapter.GetSchemas/GetSchema return nil
// unconditionally while apivalidation.Layer.GetSpecs() holds the compiled
// specs — a schema uploaded through the dashboard is invisible to the list
// and detail endpoints forever (the blind-config class, round 71 #5).
//
// Deeper: the layer keys specs by Source.Path (the upload's temp-file path,
// deleted after load) — the operator-assigned name was never passed to the
// layer at all. The fix restores the identity chain: SchemaSource gains a
// Name field, the upload sets it, and the adapters map GetSpecs() back to
// the API's schema view (title fallback for legacy config-loaded specs).

func TestAPISchemasVisibleAfterUpload(t *testing.T) {
	// A real layer with request-validation enabled (the round-77 lesson: the
	// Process gate checks l.config.ValidateRequest).
	layer := apivalidation.NewLayer(&apivalidation.Config{Enabled: true, ValidateRequest: true})
	adapter := &apiValidationAdapter{layer: layer}

	// Upload a named schema: POST /users requires an integer id.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "users-api", "version": "1"},
		"paths": {
			"/users": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {"id": {"type": "integer"}},
									"required": ["id"]
								}
							}
						}
					}
				}
			}
		}
	}`
	if err := adapter.LoadSchema(&APISchemaInfo{Name: "users", Format: "openapi", Content: spec}); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	// (a) The uploaded schema must be discoverable through the list.
	schemas := adapter.GetSchemas()
	found := false
	for _, s := range schemas {
		if s.Name == "users" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: uploaded schema is invisible to GetSchemas — the adapter returned nil unconditionally while layer.GetSpecs() holds the compiled spec (the operator's dashboard shows an empty schema list forever)")
	}

	// (b) The uploaded schema must resolve by name through the detail path.
	if adapter.GetSchema("users") == nil {
		t.Fatalf("FAIL: GetSchema(\"users\") returned nil — the schema is loaded but the API cannot resolve it by name")
	}
}
