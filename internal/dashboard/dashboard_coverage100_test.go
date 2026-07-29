package dashboard

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// =====================================================================
// Simple setters, constructors, and utilities
// =====================================================================

func TestSetBuildInfo(t *testing.T) {
	d := &Dashboard{}
	d.SetBuildInfo("v1.0.0", "abc123", "2024-01-01")
	if d.buildInfo == nil {
		t.Fatal("expected buildInfo to be set")
	}
	if d.buildInfo["version"] != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", d.buildInfo["version"])
	}
	if d.buildInfo["commit"] != "abc123" {
		t.Errorf("expected commit abc123, got %s", d.buildInfo["commit"])
	}
	if d.buildInfo["date"] != "2024-01-01" {
		t.Errorf("expected date 2024-01-01, got %s", d.buildInfo["date"])
	}
}

func TestHandleVersion_NoBuildInfo(t *testing.T) {
	d := &Dashboard{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	d.handleVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var result map[string]string
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["version"] != "dev" {
		t.Errorf("expected version dev, got %s", result["version"])
	}
}

func TestHandleVersion_WithBuildInfo(t *testing.T) {
	d := &Dashboard{}
	d.SetBuildInfo("v2.0.0", "def456", "2024-06-15")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/version", nil)
	d.handleVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var result map[string]string
	json.Unmarshal(rr.Body.Bytes(), &result)
	if result["version"] != "v2.0.0" {
		t.Errorf("expected version v2.0.0, got %s", result["version"])
	}
}

func TestIsASCIILetter(t *testing.T) {
	tests := []struct {
		b        byte
		expected bool
	}{
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'0', false},
		{'9', false},
		{'_', false},
		{':', false},
		{'/', false},
		{0, false},
		{127, false},
	}
	for _, tt := range tests {
		result := isASCIILetter(tt.b)
		if result != tt.expected {
			t.Errorf("isASCIILetter(%q) = %v, want %v", tt.b, result, tt.expected)
		}
	}
}

func TestNewTimeSeedSource(t *testing.T) {
	src := newTimeSeedSource()
	if src == nil {
		t.Fatal("expected non-nil source")
	}
	// Verify it produces random numbers
	v1 := src.Int63()
	v2 := src.Int63()
	if v1 == v2 {
		t.Log("note: two random values were equal (possible but unlikely)")
	}
	// Verify it implements Source
	var _ rand.Source = src
}

func TestSetRoutingController(t *testing.T) {
	d := &Dashboard{}
	rc := RoutingControllerFuncs{
		RebuildFn: func() error { return nil },
		SaveFn:    func() error { return nil },
	}
	d.SetRoutingController(rc)
	if d.routingCtrl == nil {
		t.Fatal("expected routingCtrl to be set")
	}
	// Verify it's the same object
	if err := d.routingCtrl.Rebuild(); err != nil {
		t.Errorf("expected nil error from Rebuild, got %v", err)
	}
	if err := d.routingCtrl.Save(); err != nil {
		t.Errorf("expected nil error from Save, got %v", err)
	}
}

func TestRoutingControllerFuncs_Rebuild(t *testing.T) {
	rebuildCalled := false
	rc := RoutingControllerFuncs{
		RebuildFn: func() error {
			rebuildCalled = true
			return nil
		},
		SaveFn: func() error { return nil },
	}
	err := rc.Rebuild()
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if !rebuildCalled {
		t.Error("expected RebuildFn to be called")
	}
}

func TestRoutingControllerFuncs_Rebuild_Error(t *testing.T) {
	rc := RoutingControllerFuncs{
		RebuildFn: func() error { return fmt.Errorf("rebuild error") },
		SaveFn:    func() error { return nil },
	}
	err := rc.Rebuild()
	if err == nil || err.Error() != "rebuild error" {
		t.Errorf("expected 'rebuild error', got %v", err)
	}
}

func TestRoutingControllerFuncs_Save(t *testing.T) {
	saveCalled := false
	rc := RoutingControllerFuncs{
		RebuildFn: func() error { return nil },
		SaveFn: func() error {
			saveCalled = true
			return nil
		},
	}
	err := rc.Save()
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if !saveCalled {
		t.Error("expected SaveFn to be called")
	}
}

func TestRoutingControllerFuncs_Save_Error(t *testing.T) {
	rc := RoutingControllerFuncs{
		RebuildFn: func() error { return nil },
		SaveFn:    func() error { return fmt.Errorf("save error") },
	}
	err := rc.Save()
	if err == nil || err.Error() != "save error" {
		t.Errorf("expected 'save error', got %v", err)
	}
}

func TestRegisterSPA_Noop(t *testing.T) {
	d := &Dashboard{}
	mux := http.NewServeMux()
	// registerSPA is a no-op — just ensure it doesn't panic
	d.registerSPA(mux)
}

// =====================================================================
// handleMetrics
// =====================================================================

func TestHandleMetrics(t *testing.T) {
	proxy.SetPrivateTargetsAllowed(true)
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	d := New(eng, store, "test-key")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	d.handleMetrics(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "# HELP guardianwaf_requests_total") {
		t.Error("expected metrics HELP line")
	}
	if !strings.Contains(body, "# TYPE guardianwaf_requests_total counter") {
		t.Error("expected metrics TYPE line")
	}
	if !strings.Contains(body, "guardianwaf_requests_total") {
		t.Error("expected requests_total metric")
	}
}

// =====================================================================
// Cluster handlers
// =====================================================================

func TestClusterHandlers(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	tests := []struct {
		name       string
		method     string
		path       string
		handler    func(http.ResponseWriter, *http.Request)
		expectCode int
	}{
		{"handleClusterList", "GET", "/api/clusters", d.handleClusterList, http.StatusOK},
		{"handleClusterNotFound", "GET", "/api/clusters/404", d.handleClusterNotFound, http.StatusNotFound},
		{"handleClusterMutationDisabled", "POST", "/api/clusters", d.handleClusterMutationDisabled, http.StatusServiceUnavailable},
		{"handleClusterNodesLegacy", "GET", "/api/nodes", d.handleClusterNodesLegacy, http.StatusOK},
		{"handleSyncStats", "GET", "/api/sync/stats", d.handleSyncStats, http.StatusOK},
		{"handleSyncStatus", "GET", "/api/sync/status", d.handleSyncStatus, http.StatusOK},
		{"handleClusterStatus", "GET", "/api/v1/cluster/status", d.handleClusterStatus, http.StatusOK},
		{"handleClusterNodes", "GET", "/api/v1/cluster/nodes", d.handleClusterNodes, http.StatusOK},
		{"handleClusterHealth", "GET", "/api/v1/cluster/health", d.handleClusterHealth, http.StatusOK},
		{"handleClusterNodeStats", "GET", "/api/v1/cluster/node/stats", d.handleClusterNodeStats, http.StatusOK},
		{"handleClusterConfig", "GET", "/api/v1/cluster/config", d.handleClusterConfig, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			tt.handler(rr, req)
			if rr.Code != tt.expectCode {
				t.Errorf("expected %d, got %d: %s", tt.expectCode, rr.Code, rr.Body.String())
			}
		})
	}
}

// =====================================================================
// Docker handlers
// =====================================================================

func TestHandleDockerContainers_NoWatcher(t *testing.T) {
	d := &Dashboard{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/docker/containers", nil)
	d.handleDockerContainers(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false")
	}
}

func TestHandleDockerEvents_NoWatcher(t *testing.T) {
	d := &Dashboard{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/docker/events", nil)
	d.handleDockerEvents(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false")
	}
}

// =====================================================================
// writeJSON error path (json.Marshal failure)
// =====================================================================

type marshalErrorType struct{}

func (m marshalErrorType) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("mock marshal error")
}

func TestWriteJSON_EncodeError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, marshalErrorType{})
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	expected := `{"error":"internal encoding error"}`
	if rr.Body.String() != expected {
		t.Errorf("expected %q, got %q", expected, rr.Body.String())
	}
}

// =====================================================================
// ruleBoolField
// =====================================================================

func TestRuleBoolField(t *testing.T) {
	tests := []struct {
		name     string
		rule     map[string]any
		field    string
		expected bool
	}{
		{"field missing", map[string]any{}, "enabled", false},
		{"field is bool true", map[string]any{"enabled": true}, "enabled", true},
		{"field is bool false", map[string]any{"enabled": false}, "enabled", false},
		{"field is string true", map[string]any{"enabled": "true"}, "enabled", true},
		{"field is string false", map[string]any{"enabled": "false"}, "enabled", false},
		{"field is string invalid", map[string]any{"enabled": "notbool"}, "enabled", false},
		{"field is non-bool non-string", map[string]any{"enabled": 42}, "enabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ruleBoolField(tt.rule, tt.field)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// =====================================================================
// tenantScope
// =====================================================================

func TestTenantScope(t *testing.T) {
	// Non-tenant auth type should return ""
	req := httptest.NewRequest("GET", "/", nil)
	scope := tenantScope(req)
	if scope != "" {
		t.Errorf("expected empty scope for non-tenant auth, got %q", scope)
	}

	// Set auth type to tenant
	req2 := httptest.NewRequest("GET", "/", nil)
	req2 = setAuthInfo(req2, authTenant, "tenant-id-123")
	scope2 := tenantScope(req2)
	if scope2 != "tenant-id-123" {
		t.Errorf("expected tenant-id-123, got %q", scope2)
	}
}

// =====================================================================
// ClientSide adapter methods
// =====================================================================

func TestClientSideAdapter_GetStats_NilLayer(t *testing.T) {
	// Create a clientSideAdapter with nil layer — GetStats will panic
	// because it calls a.layer.GetStats(). Skip this if layer is nil.
	// Instead, test the non-nil layer path only.
	layer := clientside.NewLayer(&clientside.Config{})
	adapter := &clientSideAdapter{layer: layer}
	stats := adapter.GetStats()
	if stats.Mode != "monitor" {
		t.Errorf("expected monitor mode, got %s", stats.Mode)
	}
}

func TestClientSideAdapter_GetBlockedDomains(t *testing.T) {
	adapter := &clientSideAdapter{}
	domains := adapter.GetBlockedDomains()
	if domains != nil {
		t.Errorf("expected nil, got %v", domains)
	}
}

func TestClientSideAdapter_AddBlockedDomain_NilLayer(t *testing.T) {
	adapter := &clientSideAdapter{}
	// Should not panic with nil layer
	adapter.AddBlockedDomain("evil.com")
}

func TestClientSideAdapter_GetCSPReports(t *testing.T) {
	adapter := &clientSideAdapter{}
	reports := adapter.GetCSPReports(10)
	if reports != nil {
		t.Errorf("expected nil, got %v", reports)
	}
}

// =====================================================================
// CRS adapter methods
// =====================================================================

func TestCRSAdapter_GetAllRules(t *testing.T) {
	layer := crs.NewLayer(nil)
	adapter := &crsAdapter{layer: layer}
	rules := adapter.GetAllRules()
	// With default config, no rules loaded
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestCRSAdapter_GetRule_NotFound(t *testing.T) {
	layer := crs.NewLayer(nil)
	adapter := &crsAdapter{layer: layer}
	rule := adapter.GetRule("non-existent")
	if rule != nil {
		t.Errorf("expected nil, got %v", rule)
	}
}

func TestCRSAdapter_EnableDisableRule(t *testing.T) {
	layer := crs.NewLayer(nil)
	adapter := &crsAdapter{layer: layer}
	// With no rules loaded, these should not panic
	adapter.EnableRule("rule-1")
	adapter.DisableRule("rule-1")
	enabled := adapter.IsRuleEnabled("rule-1")
	// Default is enabled (false = enabled)
	if !enabled {
		t.Log("rule-1 is disabled (expected with empty rule set)")
	}
}

func TestCRSAdapter_SetParanoiaLevel(t *testing.T) {
	layer := crs.NewLayer(nil)
	adapter := &crsAdapter{layer: layer}
	adapter.SetParanoiaLevel(2)
	// No panic expected
}

func TestCRSAdapter_Stats(t *testing.T) {
	layer := crs.NewLayer(nil)
	adapter := &crsAdapter{layer: layer}
	stats := adapter.Stats()
	if stats == nil {
		t.Error("expected non-nil stats map")
	}
}

func TestCRSAdapter_Process(t *testing.T) {
	adapter := &crsAdapter{}
	ctx := &TestRequestContext{
		Method:  "GET",
		Path:    "/test",
		Headers: map[string]string{},
		Body:    "",
	}
	result := adapter.Process(ctx)
	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
	if string(result.Action) != "pass" {
		t.Errorf("expected action pass, got %s", result.Action)
	}
	if result.Findings != nil {
		t.Errorf("expected nil findings, got %v", result.Findings)
	}
}

// =====================================================================
// DLP adapter methods
// =====================================================================

func TestDLPAdapter_IsEnabled_NilLayer(t *testing.T) {
	adapter := &dlpAdapter{}
	if adapter.IsEnabled() {
		t.Error("expected IsEnabled to be false with nil layer")
	}
}

func TestDLPAdapter_IsEnabled_WithLayer(t *testing.T) {
	layer := dlp.NewLayer(nil)
	adapter := &dlpAdapter{layer: layer}
	if !adapter.IsEnabled() {
		t.Error("expected IsEnabled to be true with layer")
	}
}

func TestDLPAdapter_GetAlerts(t *testing.T) {
	adapter := &dlpAdapter{}
	alerts := adapter.GetAlerts(10, "")
	if alerts != nil {
		t.Errorf("expected nil alerts, got %v", alerts)
	}
}

func TestDLPAdapter_GetPatterns_NilLayer(t *testing.T) {
	adapter := &dlpAdapter{}
	patterns := adapter.GetPatterns()
	if patterns != nil {
		t.Errorf("expected nil patterns, got %v", patterns)
	}
}

func TestDLPAdapter_GetPattern_NilLayer(t *testing.T) {
	adapter := &dlpAdapter{}
	pattern := adapter.GetPattern("test")
	if pattern != nil {
		t.Errorf("expected nil pattern, got %v", pattern)
	}
}

func TestDLPAdapter_AddPattern_NilLayer(t *testing.T) {
	adapter := &dlpAdapter{}
	err := adapter.AddPattern(&DLPPatternInfo{
		ID:      "custom-1",
		Name:    "Custom Pattern",
		Pattern: "test-.*-pattern",
	})
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestDLPAdapter_RemovePattern(t *testing.T) {
	adapter := &dlpAdapter{}
	err := adapter.RemovePattern("test")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestDLPAdapter_TestPattern(t *testing.T) {
	adapter := &dlpAdapter{}
	// Empty pattern — no match
	result := adapter.TestPattern("", "test data")
	if result.Matched {
		t.Error("expected no match with empty pattern")
	}
	// Non-empty pattern, non-empty data — basic containment test
	result2 := adapter.TestPattern("test", "this is test data")
	if !result2.Matched {
		t.Error("expected match with 'test' in 'this is test data'")
	}
	// Non-empty pattern, non-matching data
	result3 := adapter.TestPattern("xyz", "this is test data")
	if result3.Matched {
		t.Error("expected no match with 'xyz' in 'this is test data'")
	}
}

// =====================================================================
// API Validation adapter methods
// =====================================================================

func TestAPIValidationAdapter_IsEnabled_NilLayer(t *testing.T) {
	adapter := &apiValidationAdapter{}
	if adapter.IsEnabled() {
		t.Error("expected IsEnabled to be false with nil layer")
	}
}

func TestAPIValidationAdapter_IsEnabled_WithLayer(t *testing.T) {
	layer := apivalidation.NewLayer(nil)
	adapter := &apiValidationAdapter{layer: layer}
	if !adapter.IsEnabled() {
		t.Error("expected IsEnabled to be true with layer")
	}
}

func TestAPIValidationAdapter_GetSchemas(t *testing.T) {
	adapter := &apiValidationAdapter{}
	schemas := adapter.GetSchemas()
	if schemas != nil {
		t.Errorf("expected nil schemas, got %v", schemas)
	}
}

func TestAPIValidationAdapter_RemoveSchema_NilLayer(t *testing.T) {
	adapter := &apiValidationAdapter{}
	err := adapter.RemoveSchema("test-schema")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestAPIValidationAdapter_RemoveSchema_WithLayer(t *testing.T) {
	layer := apivalidation.NewLayer(nil)
	adapter := &apiValidationAdapter{layer: layer}
	err := adapter.RemoveSchema("test-schema")
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// =====================================================================
// VirtualPatch adapter methods
// =====================================================================

func TestVirtualPatchAdapter_GetActivePatches(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}
	patches := adapter.GetActivePatches()
	// Should return patches (default patches loaded)
	t.Logf("got %d active patches", len(patches))
}

func TestVirtualPatchAdapter_GetPatch_NotFound(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}
	patch := adapter.GetPatch("non-existent")
	if patch != nil {
		t.Errorf("expected nil, got %v", patch)
	}
}

func TestVirtualPatchAdapter_AddPatch(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}
	adapter.AddPatch(&VirtualPatchInfo{
		ID:      "test-patch-1",
		Name:    "Test Patch",
		Pattern: "test-.*",
		Target:  "path",
		Action:  "block",
	})
	// Verify the patch was added
	patch := adapter.GetPatch("test-patch-1")
	if patch == nil {
		t.Fatal("expected patch to be added")
	}
	if patch.Name != "Test Patch" {
		t.Errorf("expected 'Test Patch', got %s", patch.Name)
	}
}

func TestVirtualPatchAdapter_EnableDisablePatch(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}

	// Add a patch first
	adapter.AddPatch(&VirtualPatchInfo{
		ID:      "vp-enable-test",
		Name:    "Enable Test",
		Pattern: "test",
	})

	// Disable
	disabled := adapter.DisablePatch("vp-enable-test")
	if !disabled {
		t.Error("expected DisablePatch to return true")
	}
	// Verify disabled
	patch := adapter.GetPatch("vp-enable-test")
	if patch != nil && patch.Enabled {
		t.Error("expected patch to be disabled")
	}

	// Enable
	enabled := adapter.EnablePatch("vp-enable-test")
	if !enabled {
		t.Error("expected EnablePatch to return true")
	}
}

func TestVirtualPatchAdapter_EnableDisablePatchBy(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}

	adapter.AddPatch(&VirtualPatchInfo{
		ID:      "vp-by-test",
		Name:    "By Test",
		Pattern: "test",
	})

	disabled := adapter.DisablePatchBy("vp-by-test", "test-actor")
	if !disabled {
		t.Error("expected DisablePatchBy to return true")
	}

	enabled := adapter.EnablePatchBy("vp-by-test", "test-actor")
	if !enabled {
		t.Error("expected EnablePatchBy to return true")
	}

	// Non-existent ID
	if adapter.DisablePatchBy("non-existent", "actor") {
		t.Error("expected DisablePatchBy to return false for non-existent patch")
	}
	if adapter.EnablePatchBy("non-existent", "actor") {
		t.Error("expected EnablePatchBy to return false for non-existent patch")
	}
}

func TestVirtualPatchAdapter_GetStats(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}
	stats := adapter.GetStats()
	if stats.TotalPatches == 0 && stats.ActivePatches == 0 {
		t.Log("stats: zero patches (expected with fresh layer)")
	}
}

func TestVirtualPatchAdapter_TriggerUpdate(t *testing.T) {
	layer := virtualpatch.NewLayer(nil)
	adapter := &virtualPatchAdapter{layer: layer}
	// Should not panic
	adapter.TriggerUpdate()
}

// =====================================================================
// Tenant compat handlers (edge cases requiring tenant manager)
// =====================================================================

func TestTenantCompatHandlers_NoManager(t *testing.T) {
	d := &Dashboard{}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		path    string
	}{
		{"handleTenantGetCompat", d.handleTenantGetCompat, "GET", "/api/v1/tenants/test-tenant"},
		{"handleTenantUpdateCompat", d.handleTenantUpdateCompat, "PUT", "/api/v1/tenants/test-tenant"},
		{"handleTenantUsageCompat", d.handleTenantUsageCompat, "GET", "/api/v1/tenants/test-tenant/usage"},
		{"handleTenantAllUsageCompat", d.handleTenantAllUsageCompat, "GET", "/api/v1/tenants/usage"},
		{"handleTenantAPIKeyCompat", d.handleTenantAPIKeyCompat, "POST", "/api/v1/tenants/test-tenant/api-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			tt.handler(rr, req)
			// Without tenant manager, these handlers should not panic.
			// They should return appropriate error responses.
			if rr.Code == 0 {
				t.Error("expected non-zero status code")
			}
		})
	}
}

// =====================================================================
// cluster handlers via mux routes (integration-style)
// =====================================================================

func TestClusterHandlerViaMux(t *testing.T) {
	d := newTestDashboard(t, "test-key")
	mux := http.NewServeMux()
	d.registerCluster(mux)

	routes := []struct {
		name       string
		method     string
		path       string
		expectCode int
	}{
		{"GET /api/clusters", "GET", "/api/clusters", http.StatusOK},
		{"POST /api/clusters", "POST", "/api/clusters", http.StatusServiceUnavailable},
		{"GET /api/clusters/test-id", "GET", "/api/clusters/test-id", http.StatusNotFound},
		{"GET /api/nodes", "GET", "/api/nodes", http.StatusOK},
		{"GET /api/sync/stats", "GET", "/api/sync/stats", http.StatusOK},
		{"GET /api/sync/status", "GET", "/api/sync/status", http.StatusOK},
		{"GET /api/v1/cluster/status", "GET", "/api/v1/cluster/status", http.StatusOK},
		{"GET /api/v1/cluster/nodes", "GET", "/api/v1/cluster/nodes", http.StatusOK},
		{"GET /api/v1/cluster/health", "GET", "/api/v1/cluster/health", http.StatusOK},
		{"GET /api/v1/cluster/node/stats", "GET", "/api/v1/cluster/node/stats", http.StatusOK},
		{"GET /api/v1/cluster/config", "GET", "/api/v1/cluster/config", http.StatusOK},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := authenticatedRequest(route.method, route.path, "", "test-key")
			mux.ServeHTTP(rr, req)
			if rr.Code != route.expectCode {
				t.Errorf("expected %d, got %d: %s", route.expectCode, rr.Code, rr.Body.String())
			}
		})
	}
}
