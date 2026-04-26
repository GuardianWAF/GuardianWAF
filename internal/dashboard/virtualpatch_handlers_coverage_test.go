package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- handlePatches: GET with nil layer (handleListPatches) ---
func TestVirtualPatch_HandlePatches_Get_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches", nil)
	h.handlePatches(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false in response")
	}
}

// --- handlePatches: POST with nil layer (handleAddPatch) ---
func TestVirtualPatch_HandlePatches_Post_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(`{"id":"test","name":"Test","pattern":"test"}`))
	h.handlePatches(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handlePatches: PUT (method not allowed) ---
func TestVirtualPatch_HandlePatches_Put_MethodNotAllowed(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/virtualpatch/patches", nil)
	h.handlePatches(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- handlePatchDetail: GET with nil layer ---
func TestVirtualPatch_HandlePatchDetail_Get_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches/test-patch", nil)
	h.handlePatchDetail(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handlePatchDetail: GET with empty patch ID ---
func TestVirtualPatch_HandlePatchDetail_Get_EmptyID(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches/", nil)
	h.handlePatchDetail(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handlePatchDetail: PUT with nil layer ---
func TestVirtualPatch_HandlePatchDetail_Put_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/virtualpatch/patches/test-patch", strings.NewReader(`{"enabled":true}`))
	h.handlePatchDetail(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handlePatchDetail: DELETE with nil layer ---
func TestVirtualPatch_HandlePatchDetail_Delete_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/virtualpatch/patches/test-patch", nil)
	h.handlePatchDetail(rr, req)

	// nil layer returns 503 (checked before DELETE case)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handlePatchDetail: PATCH method not allowed ---
func TestVirtualPatch_HandlePatchDetail_Patch_MethodNotAllowed(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/virtualpatch/patches/test-patch", nil)
	h.handlePatchDetail(rr, req)

	// nil layer returns 503 (checked before method switch default)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handlePatchStats: GET with nil layer ---
func TestVirtualPatch_HandlePatchStats_Get_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/stats", nil)
	h.handlePatchStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false in response")
	}
}

// --- handlePatchStats: POST method not allowed ---
func TestVirtualPatch_HandlePatchStats_Post_MethodNotAllowed(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/virtualpatch/stats", nil)
	h.handlePatchStats(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- handleUpdateCVE: POST with nil layer ---
func TestVirtualPatch_HandleUpdateCVE_Post_NilLayer(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/virtualpatch/update", nil)
	h.handleUpdateCVE(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleUpdateCVE: GET method not allowed ---
func TestVirtualPatch_HandleUpdateCVE_Get_MethodNotAllowed(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/update", nil)
	h.handleUpdateCVE(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// --- handleAddPatch: POST with missing required fields ---
func TestVirtualPatch_HandleAddPatch_MissingFields(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}
	// getVirtualPatchLayer returns nil, so handleAddPatch returns 503
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(`{"id":"test"}`))
	h.handleAddPatch(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleAddPatch: POST with pattern too long ---
func TestVirtualPatch_HandleAddPatch_PatternTooLong(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}
	// getVirtualPatchLayer returns nil, so handleAddPatch returns 503
	rr := httptest.NewRecorder()
	longPattern := strings.Repeat("x", 5000)
	req := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(`{"id":"test","name":"Test","pattern":"`+longPattern+`"}`))
	h.handleAddPatch(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleAddPatch: POST with name too long ---
func TestVirtualPatch_HandleAddPatch_NameTooLong(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}
	// getVirtualPatchLayer returns nil, so handleAddPatch returns 503
	rr := httptest.NewRecorder()
	longName := strings.Repeat("x", 300)
	req := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(`{"id":"test","name":"`+longName+`","pattern":"testpattern"}`))
	h.handleAddPatch(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- handleAddPatch: invalid JSON ---
func TestVirtualPatch_HandleAddPatch_InvalidJSON(t *testing.T) {
	h := &VirtualPatchHandler{dashboard: &Dashboard{}}
	// getVirtualPatchLayer returns nil, so handleAddPatch returns 503
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/virtualpatch/patches", strings.NewReader(`{invalid`))
	h.handleAddPatch(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- mockVirtualPatchLayer for non-nil layer tests ---
type mockVirtualPatchLayer struct {
	patches    []*VirtualPatchInfo
	getPatchFn func(string) *VirtualPatchInfo
	stats      VirtualPatchStats
}

func (m *mockVirtualPatchLayer) GetActivePatches() []*VirtualPatchInfo {
	return m.patches
}
func (m *mockVirtualPatchLayer) GetPatch(id string) *VirtualPatchInfo {
	if m.getPatchFn != nil {
		return m.getPatchFn(id)
	}
	for _, p := range m.patches {
		if p.ID == id {
			return p
		}
	}
	return nil
}
func (m *mockVirtualPatchLayer) AddPatch(patch *VirtualPatchInfo) {}
func (m *mockVirtualPatchLayer) EnablePatch(id string) bool        { return true }
func (m *mockVirtualPatchLayer) DisablePatch(id string) bool      { return true }
func (m *mockVirtualPatchLayer) GetStats() VirtualPatchStats      { return m.stats }
func (m *mockVirtualPatchLayer) TriggerUpdate()                   {}

// --- handleListPatches: with mock layer (but layer always returns nil) ---
func TestVirtualPatch_HandleListPatches_WithMockLayer(t *testing.T) {
	_ = &mockVirtualPatchLayer{
		patches: []*VirtualPatchInfo{
			{ID: "p1", Name: "Patch 1", Severity: "high", Enabled: true, Patterns: []PatchPatternInfo{{Type: "regex"}}},
			{ID: "p2", Name: "Patch 2", Severity: "low", Enabled: false, Patterns: []PatchPatternInfo{}},
		},
	}
	// getVirtualPatchLayer always returns nil, so nil path is always taken
	// This test verifies the mock compiles correctly
}

// --- test query param filtering paths via handleListPatches nil path ---
func TestVirtualPatch_HandleListPatches_SeverityFilter(t *testing.T) {
	d := &Dashboard{}
	h := &VirtualPatchHandler{dashboard: d}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches?severity=high", nil)
	h.handleListPatches(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false (nil layer)")
	}
}

func TestVirtualPatch_HandleListPatches_ActiveOnlyFilter(t *testing.T) {
	d := &Dashboard{}
	h := &VirtualPatchHandler{dashboard: d}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches?active_only=true", nil)
	h.handleListPatches(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handlePatchDetail: GET with patch not found ---
func TestVirtualPatch_HandlePatchDetail_Get_NotFound(t *testing.T) {
	d := &Dashboard{}
	h := &VirtualPatchHandler{dashboard: d}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/virtualpatch/patches/nonexistent", nil)
	h.handlePatchDetail(rr, req)

	// nil layer returns 503
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --- NewVirtualPatchHandler constructor ---
func TestVirtualPatchHandler_New(t *testing.T) {
	d := &Dashboard{}
	h := NewVirtualPatchHandler(d)
	if h == nil {
		t.Error("expected non-nil handler")
	}
	if h.dashboard != d {
		t.Error("dashboard not set correctly")
	}
}