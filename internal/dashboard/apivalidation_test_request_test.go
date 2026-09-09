package dashboard

// Regression: apiValidationAdapter.TestRequest was an always-valid stub —
//
// Defect: apiValidationAdapter.TestRequest returned APIValidationResult{Valid:
// true} unconditionally — a pure always-pass stub. The "test your validation"
// endpoint therefore could never report a violation: an operator loading a
// strict OpenAPI contract and probing it with a violating request was told
// the request is valid, manufacturing confidence that API contracts enforce
// when nothing was ever validated. Worse than a merely broken check (round
// 72's TestPattern containment): this one cannot fail by design.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

func TestAPITestRequestValidates(t *testing.T) {
	// A real layer with request-validation enabled (the Process gate checks
	// l.config.ValidateRequest before doing anything).
	layer := apivalidation.NewLayer(&apivalidation.Config{
		Enabled:         true,
		ValidateRequest: true,
	})
	adapter := &apiValidationAdapter{layer: layer}

	// Load a minimal OpenAPI spec: POST /users requires an integer id.
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "t", "version": "1"},
		"paths": {
			"/users": {
				"post": {
					"requestBody": {
						"required": true,
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

	// A body violating the contract (string id where an integer is required)
	// must be reported invalid, with the violations populated.
	result := adapter.TestRequest("POST", "/users", `{"id":"not-a-number"}`)
	if result.Valid {
		t.Fatalf("FAIL: TestRequest reported valid for a request that violates the loaded schema — the stub returned Valid:true unconditionally, manufacturing pass results for the test endpoint (an operator could believe their API contracts enforce when nothing was validated)")
	}
	if len(result.Violations) == 0 {
		t.Fatalf("FAIL: no violations reported for the schema-violating request")
	}
}
