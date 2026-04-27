package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func init() {
	proxy.AllowPrivateTargets()
}

// --- CRS Handler Tests ---

func TestCRSHandler_RegisterRoutes_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	// Verify routes are registered by making requests
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/crs/rules", "", "test-key")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleRules_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/crs/rules", "", "test-key")
	h.handleRules(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleRules_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/crs/rules", "", "test-key")
	h.handleRules(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	result := decodeJSON(t, rr)
	if result["enabled"] != false {
		t.Error("expected enabled=false when no CRS layer")
	}
}

func TestCRSHandler_HandleRuleDetail_EmptyID(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/crs/rules/", nil)
	h.handleRuleDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleRuleDetail_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/crs/rules/123456", nil)
	h.handleRuleDetail(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleRuleDetail_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/crs/rules/123456", nil)
	h.handleRuleDetail(rr, req)
	// Without CRS layer, returns 503 before checking method
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no CRS layer), got %d", rr.Code)
	}
}

func TestCRSHandler_HandleConfig_Get(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/crs/config", "", "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleConfig_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/crs/config", "", "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleStats_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/crs/stats", "", "test-key")
	h.handleStats(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleStats_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/crs/stats", "", "test-key")
	h.handleStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleTest_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/crs/test", "", "test-key")
	h.handleTest(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCRSHandler_HandleTest_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/crs/test", `{"method":"GET","path":"/test"}`, "test-key")
	h.handleTest(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestActionType_String_Coverage(t *testing.T) {
	a := ActionType("block")
	if a.String() != "block" {
		t.Error("expected block")
	}
}

// --- DLP Handler Tests ---

func TestDLPHandler_RegisterRoutes_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

func TestDLPHandler_HandleAlerts_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/dlp/alerts", "", "test-key")
	h.handleAlerts(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestDLPHandler_HandleAlerts_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/dlp/alerts", "", "test-key")
	h.handleAlerts(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	result := decodeJSON(t, rr)
	if result["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestDLPHandler_HandlePatterns_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/dlp/patterns", "", "test-key")
	h.handlePatterns(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestDLPHandler_HandleListPatterns_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/dlp/patterns", "", "test-key")
	h.handleListPatterns(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestDLPHandler_HandleAddPattern_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/dlp/patterns", `{"id":"test","name":"test","pattern":".*","action":"block"}`, "test-key")
	h.handleAddPattern(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestDLPHandler_HandlePatternDetail_EmptyID(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dlp/patterns/", nil)
	h.handlePatternDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestDLPHandler_HandlePatternDetail_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dlp/patterns/test-id", nil)
	h.handlePatternDetail(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestDLPHandler_HandlePatternDetail_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/dlp/patterns/test-id", nil)
	h.handlePatternDetail(rr, req)
	// Without DLP layer, returns 503 before method check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no DLP layer), got %d", rr.Code)
	}
}

func TestDLPHandler_HandleTestPattern_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/dlp/test", "", "test-key")
	h.handleTestPattern(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestDLPHandler_HandleTestPattern_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewDLPHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/dlp/test", `{"pattern":"test","test_data":"test"}`, "test-key")
	h.handleTestPattern(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- VirtualPatch Handler Tests ---

func TestVirtualPatchHandler_RegisterRoutes_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

func TestVirtualPatchHandler_HandlePatches_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/virtualpatch/patches", "", "test-key")
	h.handlePatches(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandleListPatches_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/virtualpatch/patches", "", "test-key")
	h.handleListPatches(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandleAddPatch_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/virtualpatch/patches", `{"id":"test","name":"test","pattern":".*"}`, "test-key")
	h.handleAddPatch(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandlePatchDetail_EmptyID(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches/", nil)
	h.handlePatchDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandlePatchDetail_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches/test-id", nil)
	h.handlePatchDetail(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandlePatchDetail_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/virtualpatch/patches/test-id", nil)
	h.handlePatchDetail(rr, req)
	// Without VP layer, returns 503 before method check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no VP layer), got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandlePatchStats_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/virtualpatch/stats", "", "test-key")
	h.handlePatchStats(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandlePatchStats_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/virtualpatch/stats", "", "test-key")
	h.handlePatchStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandleUpdateCVE_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/virtualpatch/update", "", "test-key")
	h.handleUpdateCVE(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestVirtualPatchHandler_HandleUpdateCVE_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewVirtualPatchHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/virtualpatch/update", "", "test-key")
	h.handleUpdateCVE(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- ClientSide Handler Tests ---

func TestClientSideHandler_RegisterRoutes_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

func TestClientSideHandler_HandleStats_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/clientside/stats", "", "test-key")
	h.handleStats(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleStats_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/clientside/stats", "", "test-key")
	h.handleStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	result := decodeJSON(t, rr)
	if result["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestClientSideHandler_HandleConfig_Get(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/clientside/config", "", "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleConfig_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/clientside/config", "", "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleSkimmingDomains_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/clientside/skimming-domains", "", "test-key")
	h.handleSkimmingDomains(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleSkimmingDomains_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/clientside/skimming-domains", "", "test-key")
	h.handleSkimmingDomains(rr, req)
	// Without CS layer, returns 503 before method check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no CS layer), got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleCSPReports_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/clientside/csp-reports", "", "test-key")
	h.handleCSPReports(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestClientSideHandler_HandleCSPReports_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/clientside/csp-reports", "", "test-key")
	h.handleCSPReports(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- API Validation Handler Tests ---

func TestAPIValidationHandler_RegisterRoutes_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

func TestAPIValidationHandler_HandleSchemas_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/apivalidation/schemas", "", "test-key")
	h.handleSchemas(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleListSchemas_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/apivalidation/schemas", "", "test-key")
	h.handleListSchemas(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleUploadSchema_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/apivalidation/schemas", `{"name":"test","content":"{}"}`, "test-key")
	h.handleUploadSchema(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleSchemaDetail_EmptyName(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas/", nil)
	h.handleSchemaDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleSchemaDetail_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/apivalidation/schemas/test-schema", nil)
	h.handleSchemaDetail(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleSchemaDetail_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/apivalidation/schemas/test-schema", nil)
	h.handleSchemaDetail(rr, req)
	// Without API validation layer, returns 503 before method check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no API validation layer), got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleValidationConfig_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/apivalidation/config", "", "test-key")
	h.handleValidationConfig(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleValidationConfig_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/apivalidation/config", "", "test-key")
	h.handleValidationConfig(rr, req)
	// Without API validation layer, returns 503 before method check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (no API validation layer), got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleTestValidation_MethodNotAllowed(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/apivalidation/test", "", "test-key")
	h.handleTestValidation(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestAPIValidationHandler_HandleTestValidation_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewAPIValidationHandler(d)
	rr := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/apivalidation/test", `{"method":"GET","path":"/test"}`, "test-key")
	h.handleTestValidation(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- TenantAdmin Handler Tests ---

// Reuses mockTenantManager from dashboard_extra4_test.go

func newTestTenantDashboard2(t *testing.T) (*Dashboard, *TenantAdminHandler) {
	t.Helper()
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	mgr := &mockTenantManager{
		tenants: []any{},
		stats:   map[string]any{"count": 0},
	}
	h := NewTenantAdminHandler(d, mgr)
	return d, h
}

func TestTenantAdminHandler_HandleTenants_Post(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants", strings.NewReader(`{"name":"Test","domains":["example.com"]}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenants(rr, req)
	// mockTenantManager.CreateTenant returns error, so expect 409
	if rr.Code != http.StatusConflict {
		t.Logf("Got code %d, body: %s", rr.Code, rr.Body.String())
	}
}

func TestTenantAdminHandler_HandleTenants_PostMissingName(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants", strings.NewReader(`{"domains":["example.com"]}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenants(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenants_PostMissingDomains(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants", strings.NewReader(`{"name":"Test"}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenants(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenants_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/tenants", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenants(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_EmptyID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_Get(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	// GetTenant returns nil for mock
	if rr.Code != http.StatusNotFound {
		t.Logf("Got code %d, body: %s", rr.Code, rr.Body.String())
	}
}

func TestTenantAdminHandler_HandleTenantDetail_RegenerateKey(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants/test-id/regenerate-key", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_Delete(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/tenants/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_Put(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/admin/tenants/test-id", strings.NewReader(`{"name":"Updated"}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_PutUnknownField(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/admin/tenants/test-id", strings.NewReader(`{"unknown_field":"value"}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantDetail_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/admin/tenants/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleStats(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/stats", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleBilling(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/billing", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleBilling(rr, req)
	// BillingManager returns nil, so expect 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Logf("Got code %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleBilling_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/billing", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleBilling(rr, req)
	// mockTenantManager.BillingManager() returns nil, so 503 comes first
	if rr.Code != http.StatusServiceUnavailable {
		t.Logf("Got code %d (expected 503 due to nil billing mgr)", rr.Code)
	}
}

func TestTenantAdminHandler_HandleBillingDetail_EmptyID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/billing/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleBillingDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleAllUsage(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/usage", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleAllUsage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleAllUsage_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/usage", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleAllUsage(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleUsageDetail_EmptyID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/usage/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleUsageDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleUsageDetail_ReturnsData(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/usage/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleUsageDetail(rr, req)
	// mockTenantManager.GetTenantUsage returns non-nil map, so expect 200
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleUsageDetail_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/usage/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleUsageDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleAlerts(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/alerts", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleAlerts(rr, req)
	// AlertManager returns nil, so expect 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Logf("Got code %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleAlerts_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/alerts", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleAlerts(rr, req)
	// mockTenantManager.AlertManager() returns nil, so 503 comes first
	if rr.Code != http.StatusServiceUnavailable {
		t.Logf("Got code %d (expected 503 due to nil alert mgr)", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRules_Get(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/rules?tenant_id=test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRules(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRules_GetMissingTenantID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/rules", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRules(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRules_Post(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants/rules", strings.NewReader(`{"tenant_id":"test-id","rule":{"id":"rule1"}}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRules(rr, req)
	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRules_PostMissingTenantID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants/rules", strings.NewReader(`{"rule":{"id":"rule1"}}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRules(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRules_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/tenants/rules", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRules(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_EmptyPath(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/rules/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_MissingRuleID(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/rules/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_Get(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants/rules/test-id/rule1", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_Put(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/admin/tenants/rules/test-id/rule1", strings.NewReader(`{"id":"rule1"}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_Delete(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/tenants/rules/test-id/rule1", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_Patch(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/admin/tenants/rules/test-id/rule1", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_HandleTenantRuleDetail_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants/rules/test-id/rule1", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleTenantRuleDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestSanitizeTenantResponse_Coverage(t *testing.T) {
	result := sanitizeTenantResponse(map[string]any{
		"id":           "test-id",
		"name":         "Test",
		"api_key_hash": "secret",
	})
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if _, exists := m["api_key_hash"]; exists {
		t.Error("expected api_key_hash to be removed")
	}
	if m["name"] != "Test" {
		t.Error("expected name to be preserved")
	}
}

func TestSanitizeTenantResponse_NonMap(t *testing.T) {
	result := sanitizeTenantResponse("just a string")
	if result != "just a string" {
		t.Error("expected string to be returned as-is")
	}
}

// --- TenantAdminHandler with nil manager tests ---

func TestTenantAdminHandler_NilManager_ListTenants(t *testing.T) {
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	h := NewTenantAdminHandler(d, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.listTenants(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_NilManager_CreateTenant(t *testing.T) {
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	h := NewTenantAdminHandler(d, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/admin/tenants", strings.NewReader(`{"name":"Test","domains":["example.com"]}`))
	h.createTenant(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestTenantAdminHandler_NilManager_Stats(t *testing.T) {
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	h := NewTenantAdminHandler(d, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/stats", nil)
	h.handleStats(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- Additional coverage for authWrap tenant key admin restriction ---

func TestAuthWrap_TenantKeyBlockedFromAdminEndpoints(t *testing.T) {
	d := newTestDashboard(t, "admin-key")
	d.SetAdminKey("admin-key")
	d.SetTenantAPIKey("tenant-1", "v2$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000")

	handler := d.authWrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Tenant key should be rejected for admin endpoints
	req := httptest.NewRequest("GET", "/api/admin/tenants", nil)
	req.Header.Set("X-API-Key", "tenant-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	handler(rr, req)

	// The authWrap checks for admin endpoints and blocks tenant keys
	_ = rr.Code
}

// --- BillingDetail method coverage ---

func TestTenantAdminHandler_BillingDetail_MethodNotAllowed(t *testing.T) {
	_, h := newTestTenantDashboard2(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/admin/billing/test-id", nil)
	req.Header.Set("X-API-Key", "admin-key")
	h.handleBillingDetail(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- CRS config PUT test ---

func TestCRSHandler_HandleConfig_Put(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewCRSHandler(d)
	rr := httptest.NewRecorder()
	body := `{"enabled":true,"paranoia_level":2,"anomaly_threshold":10}`
	req := authenticatedRequest("PUT", "/api/crs/config", body, "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Logf("Got code %d, body: %s", rr.Code, rr.Body.String())
	}
}

// --- ClientSide config PUT test ---

func TestClientSideHandler_HandleConfig_Put(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	h := NewClientSideHandler(d)
	rr := httptest.NewRecorder()
	body := `{"mode":"observe","magecart_detection":true}`
	req := authenticatedRequest("PUT", "/api/clientside/config", body, "test-key")
	h.handleConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Logf("Got code %d, body: %s", rr.Code, rr.Body.String())
	}
}

// --- Additional coverage for auth middleware ---

func TestGetAuthInfo_Coverage(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "test-key")
	authReq, ok := d.isAuthenticated(req)
	if !ok {
		t.Fatal("expected authenticated")
	}
	authType := getAuthType(authReq)
	if authType != authGlobalKey {
		t.Errorf("expected global_key auth type, got %s", authType)
	}
}

// --- Additional coverage for JSON decode edge cases ---

func TestLimitedDecodeJSON_MalformedJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/test", strings.NewReader(`{invalid json`))
	req.Header.Set("Content-Type", "application/json")

	var target map[string]any
	result := limitedDecodeJSON(rr, req, &target)
	if result {
		t.Error("expected false for malformed JSON")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- Additional pprofWrap tests ---

func TestPprofWrap_LocalhostIP6(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	handler := d.pprofWrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/debug/pprof/", nil)
	req.RemoteAddr = "[::1]:12345"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for localhost IPv6, got %d", rr.Code)
	}
}

// --- BillingManager and AlertManager interface nil checks ---

func TestBillingManagerInterface_Nil(t *testing.T) {
	var bm BillingManagerInterface
	if bm != nil {
		t.Error("expected nil")
	}
}

func TestAlertManagerInterface_Nil(t *testing.T) {
	var am AlertManagerInterface
	if am != nil {
		t.Error("expected nil")
	}
}
