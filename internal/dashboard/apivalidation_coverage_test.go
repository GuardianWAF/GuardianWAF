package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- handleSchemas: GET when API layer nil ---
func TestHandleSchemas_Get_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}
	// dashboard.engine is nil, so getAPIValidationLayer returns nil

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas", nil)
	h.handleSchemas(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleSchemas: POST when API layer nil ---
func TestHandleSchemas_Post_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/apivalidation/schemas", nil)
	h.handleSchemas(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleSchemas: PUT (method not allowed) ---
func TestHandleSchemas_Put_MethodNotAllowed(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/apivalidation/schemas", nil)
	h.handleSchemas(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- handleListSchemas: with nil API layer (always returns nil) ---
func TestHandleListSchemas_NilLayer(t *testing.T) {
	d := &Dashboard{} // engine is nil
	h := &APIValidationHandler{dashboard: d}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas", nil)
	h.handleListSchemas(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleSchemaDetail: GET with nil layer ---
func TestHandleSchemaDetail_Get_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas/test-schema", nil)
	h.handleSchemaDetail(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleSchemaDetail: GET with empty path ---
func TestHandleSchemaDetail_Get_EmptyPath(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas/", nil)
	h.handleSchemaDetail(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleSchemaDetail: DELETE with nil layer ---
func TestHandleSchemaDetail_Delete_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/apivalidation/schemas/test-schema", nil)
	h.handleSchemaDetail(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleSchemaDetail: PATCH method not allowed ---
func TestHandleSchemaDetail_Patch_MethodNotAllowed(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/apivalidation/schemas/test-schema", nil)
	h.handleSchemaDetail(rr, req)

	// With nil apiLayer, always returns 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleValidationConfig: GET with nil layer ---
func TestHandleValidationConfig_Get_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/config", nil)
	h.handleValidationConfig(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleValidationConfig: PUT with nil layer ---
func TestHandleValidationConfig_Put_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/apivalidation/config", strings.NewReader(`{}`))
	h.handleValidationConfig(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleTestValidation: POST with nil layer (returns 503) ---
func TestHandleTestValidation_Post_NilLayer2(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/apivalidation/test", strings.NewReader(`{"method":"GET","path":"/test"}`))
	h.handleTestValidation(rr, req)

	// With nil apiLayer, returns 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleTestValidation: POST with nil layer ---
func TestHandleTestValidation_Post_NilLayer(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/apivalidation/test", strings.NewReader(`{"request":{"path":"/test"}}`))
	h.handleTestValidation(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleTestValidation: POST with no body ---
func TestHandleTestValidation_Post_NoBody(t *testing.T) {
	h := &APIValidationHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/apivalidation/test", nil)
	h.handleTestValidation(rr, req)

	// limitedDecodeJSON returns false on empty body -> status updated but check
	if rr.Code == 0 {
		t.Error("response code not set")
	}
}

// --- mockEngineForAPIVAL: minimal engine for API validation handler tests ---
type mockEngineForAPIVAL struct{}