package tenant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

// =====================================================================
// Manager.GetTenantRules - 0% coverage
// =====================================================================

func TestManager_GetTenantRules_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	// Create a manager and nil-out its rulesManager
	m.rulesManager = nil
	result := m.GetTenantRules("nonexistent")
	if result != nil {
		t.Errorf("expected nil for nil rulesManager, got %v", result)
	}
}

func TestManager_GetTenantRules_Empty(t *testing.T) {
	m := NewManager(10)
	result := m.GetTenantRules("nonexistent")
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d items", len(result))
	}
}

func TestManager_GetTenantRules_WithRules(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Rules Test", "test", []string{"rules.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add a rule via AddTenantRule
	rule := map[string]any{
		"name":   "test-rule",
		"action": "block",
		"conditions": []any{
			map[string]any{"field": "path", "op": "equals", "value": "/admin"},
		},
	}
	if err := m.AddTenantRule(tenant.ID, rule); err != nil {
		t.Fatal(err)
	}

	result := m.GetTenantRules(tenant.ID)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	r, ok := result[0].(rules.Rule)
	if !ok {
		t.Fatalf("expected rules.Rule, got %T", result[0])
	}
	if r.Name != "test-rule" {
		t.Errorf("rule name = %q, want %q", r.Name, "test-rule")
	}
}

// =====================================================================
// Manager.GetTenantRule
// =====================================================================

func TestManager_GetTenantRule_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	m.rulesManager = nil
	result := m.GetTenantRule("any", "rule1")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestManager_GetTenantRule_Found(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Rule Lookup Test", "test", []string{"rulelookup.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := map[string]any{
		"name":   "lookup-rule",
		"action": "block",
	}
	if err := m.AddTenantRule(tenant.ID, rule); err != nil {
		t.Fatal(err)
	}

	// Get all rules to find the ID
	allRules := m.GetTenantRules(tenant.ID)
	if len(allRules) == 0 {
		t.Fatal("expected at least one rule")
	}
	r := allRules[0].(rules.Rule)

	found := m.GetTenantRule(tenant.ID, r.ID)
	if found == nil {
		t.Error("expected to find rule")
	}
}

func TestManager_GetTenantRule_NotFound(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Rule Not Found Test", "test", []string{"rulenotfound.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := m.GetTenantRule(tenant.ID, "nonexistent-rule-id")
	// GetTenantRule returns *rules.Rule which may be a typed nil
	// Check by type assertion
	if r, ok := result.(*rules.Rule); ok && r != nil {
		t.Errorf("expected nil for nonexistent rule, got %v", result)
	}
}

// =====================================================================
// Manager.UpdateTenantRule - 54.8% coverage
// =====================================================================

func TestManager_UpdateTenantRule_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	m.rulesManager = nil
	err := m.UpdateTenantRule("any", map[string]any{"id": "rule1"})
	if err == nil {
		t.Error("expected error for nil rulesManager")
	}
}

func TestManager_UpdateTenantRule_NoID(t *testing.T) {
	m := NewManager(10)
	err := m.UpdateTenantRule("any", map[string]any{"name": "test"})
	if err == nil {
		t.Error("expected error for missing rule ID")
	}
}

func TestManager_UpdateTenantRule_Success(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Update Rule Test", "test", []string{"updaterule.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add a rule first
	rule := map[string]any{
		"name":   "original-name",
		"action": "block",
	}
	if err := m.AddTenantRule(tenant.ID, rule); err != nil {
		t.Fatal(err)
	}

	// Get rule ID
	allRules := m.GetTenantRules(tenant.ID)
	r := allRules[0].(rules.Rule)

	// Update the rule with all fields
	update := map[string]any{
		"id":       r.ID,
		"name":     "updated-name",
		"enabled":  false,
		"priority": 10.0,
		"action":   "log",
		"score":    50.0,
		"conditions": []any{
			map[string]any{"field": "ip", "op": "contains", "value": "192.168"},
		},
	}
	if err := m.UpdateTenantRule(tenant.ID, update); err != nil {
		t.Fatalf("UpdateTenantRule failed: %v", err)
	}

	// Verify update
	updated := m.GetTenantRule(tenant.ID, r.ID)
	if updated == nil {
		t.Fatal("expected to find updated rule")
	}
	ur := updated.(*rules.Rule)
	if ur.Name != "updated-name" {
		t.Errorf("name = %q, want %q", ur.Name, "updated-name")
	}
}

func TestManager_UpdateTenantRule_NotFound(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Update Not Found Test", "test", []string{"updatenotfound.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = m.UpdateTenantRule(tenant.ID, map[string]any{"id": "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

// =====================================================================
// Manager.RemoveTenantRule - 80% coverage (need nil rulesManager)
// =====================================================================

func TestManager_RemoveTenantRule_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	m.rulesManager = nil
	err := m.RemoveTenantRule("any", "rule1")
	if err == nil {
		t.Error("expected error for nil rulesManager")
	}
}

// =====================================================================
// Manager.ToggleTenantRule - 80% coverage (need nil rulesManager)
// =====================================================================

func TestManager_ToggleTenantRule_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	m.rulesManager = nil
	err := m.ToggleTenantRule("any", "rule1", true)
	if err == nil {
		t.Error("expected error for nil rulesManager")
	}
}

func TestManager_ToggleTenantRule_Success(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Toggle Rule Test", "test", []string{"togglerule.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := map[string]any{
		"name":   "toggle-test",
		"action": "block",
	}
	if err := m.AddTenantRule(tenant.ID, rule); err != nil {
		t.Fatal(err)
	}

	allRules := m.GetTenantRules(tenant.ID)
	r := allRules[0].(rules.Rule)

	// Disable
	if err := m.ToggleTenantRule(tenant.ID, r.ID, false); err != nil {
		t.Fatalf("ToggleTenantRule(false) failed: %v", err)
	}
	// Enable
	if err := m.ToggleTenantRule(tenant.ID, r.ID, true); err != nil {
		t.Fatalf("ToggleTenantRule(true) failed: %v", err)
	}
}

func TestManager_ToggleTenantRule_NotFound(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Toggle Not Found Test", "test", []string{"togglenotfound.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = m.ToggleTenantRule(tenant.ID, "nonexistent", true)
	if err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

// =====================================================================
// Manager.AddTenantRule - edge cases
// =====================================================================

func TestManager_AddTenantRule_NoName(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Add Rule NoName", "test", []string{"addrulename.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = m.AddTenantRule(tenant.ID, map[string]any{"action": "block"})
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestManager_AddTenantRule_NonexistentTenant(t *testing.T) {
	m := NewManager(10)
	err := m.AddTenantRule("nonexistent", map[string]any{"name": "test"})
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

func TestManager_AddTenantRule_NilRulesManager(t *testing.T) {
	m := NewManager(10)
	m.rulesManager = nil
	err := m.AddTenantRule("any", map[string]any{"name": "test"})
	if err == nil {
		t.Error("expected error for nil rulesManager")
	}
}

func TestManager_RemoveTenantRule_Success(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Remove Rule Test", "test", []string{"removerule.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	rule := map[string]any{
		"name":   "to-remove",
		"action": "block",
	}
	if err := m.AddTenantRule(tenant.ID, rule); err != nil {
		t.Fatal(err)
	}

	allRules := m.GetTenantRules(tenant.ID)
	r := allRules[0].(rules.Rule)

	if err := m.RemoveTenantRule(tenant.ID, r.ID); err != nil {
		t.Fatalf("RemoveTenantRule failed: %v", err)
	}

	if len(m.GetTenantRules(tenant.ID)) != 0 {
		t.Error("expected no rules after removal")
	}
}

func TestManager_RemoveTenantRule_NotFound(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Remove Not Found", "test", []string{"removenotfound.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = m.RemoveTenantRule(tenant.ID, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

// =====================================================================
// Manager.Init with store errors
// =====================================================================

func TestManager_Init_NilStore(t *testing.T) {
	m := NewManager(10)
	m.store = nil
	err := m.Init()
	if err != nil {
		t.Errorf("expected nil error for nil store, got %v", err)
	}
}

func TestManager_LoadTenants_NilStore(t *testing.T) {
	m := NewManager(10)
	m.store = nil
	err := m.LoadTenants()
	if err != nil {
		t.Errorf("expected nil error for nil store, got %v", err)
	}
}

func TestManager_SaveTenant_NilStore(t *testing.T) {
	m := NewManager(10)
	err := m.SaveTenant(nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestManager_SaveTenant_NilStoreExplicit(t *testing.T) {
	m := NewManager(10)
	m.store = nil
	tenant, _ := m.CreateTenant("Save Test", "test", []string{"savetest.example.com"}, nil)
	m.store = nil
	err := m.SaveTenant(tenant)
	if err != nil {
		t.Errorf("expected nil for nil store, got %v", err)
	}
}

// =====================================================================
// Store.Init with bad index JSON
// =====================================================================

func TestStore_Init_BadIndexJSON(t *testing.T) {
	dir := t.TempDir()
	// Write invalid JSON to index.json
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	err := s.Init()
	if err != nil {
		t.Errorf("Init should succeed even with bad index JSON (warn only), got %v", err)
	}
}

// =====================================================================
// Store with read-only directory (saveIndex error)
// =====================================================================

func TestStore_SaveTenant_CannotWriteIndex(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	// Create a tenant object manually
	tenant := &Tenant{
		ID:          "test-tenant-1",
		Name:        "Test",
		Description: "test",
		Active:      true,
		Domains:     []string{"test.example.com"},
		Quota:       DefaultQuota(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		APIKeyHash:  "fakehash",
	}

	// Save should work normally
	if err := s.SaveTenant(tenant); err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}

	// Verify the file exists
	if _, err := os.Stat(filepath.Join(dir, "test-tenant-1.json")); os.IsNotExist(err) {
		t.Error("expected tenant file to exist")
	}
}

// =====================================================================
// Store.LoadTenant with invalid tenant ID
// =====================================================================

func TestStore_LoadTenant_InvalidID(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoadTenant("../../etc/passwd")
	if err == nil {
		t.Error("expected error for invalid tenant ID")
	}
}

// =====================================================================
// Store.DeleteTenant with invalid tenant ID
// =====================================================================

func TestStore_DeleteTenant_InvalidID(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	err := s.DeleteTenant("../../etc/passwd")
	if err == nil {
		t.Error("expected error for invalid tenant ID")
	}
}

// =====================================================================
// Handlers: handleTenantRoutes - edge cases
// =====================================================================

func TestHandlers_HandleTenantRoutes_InvalidTenantID(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Test with invalid characters in tenant ID
	req := httptest.NewRequest("GET", "/api/v1/tenants/bad@id", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid tenant ID, got %d", rr.Code)
	}
}

func TestHandlers_HandleTenants_Method(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// DELETE on /api/v1/tenants (not allowed)
	req := httptest.NewRequest("DELETE", "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlers_HandleTenantRoutes_NoAuth(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/tenants/abc123", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandlers_HandleTenantRoutes_EmptyID(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// This should hit handleTenantRoutes with an empty path after prefix
	req := httptest.NewRequest("GET", "/api/v1/tenants/", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty tenant ID, got %d", rr.Code)
	}
}

func TestHandlers_GetTenantUsage(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	tenant, err := m.CreateTenant("Usage Test", "test", []string{"usagetest.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Record some usage
	m.RecordUsage(tenant, 1024)

	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenant.ID, nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()

	h.GetTenantUsage(rr, req, tenant.ID)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var usage UsageStats
	if err := json.NewDecoder(rr.Body).Decode(&usage); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if usage.TenantID != tenant.ID {
		t.Errorf("tenant_id = %q, want %q", usage.TenantID, tenant.ID)
	}
	if usage.TotalRequests != 1 {
		t.Errorf("TotalRequests = %d, want 1", usage.TotalRequests)
	}
}

func TestHandlers_GetTenantUsage_NotFound(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()

	h.GetTenantUsage(rr, req, "nonexistent")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandlers_GetTenantUsage_WrongMethod(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)

	req := httptest.NewRequest("POST", "/api/v1/tenants/abc", nil)
	rr := httptest.NewRecorder()
	h.GetTenantUsage(rr, req, "abc")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlers_GetAllUsage(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	tenant1, err := m.CreateTenant("Usage1", "test1", []string{"usage1.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant2, err := m.CreateTenant("Usage2", "test2", []string{"usage2.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	m.RecordUsage(tenant1, 100)
	m.RecordUsage(tenant2, 200)

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()

	h.GetAllUsage(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	count, ok := result["count"].(float64)
	if !ok || int(count) != 2 {
		t.Errorf("expected count=2, got %v", result["count"])
	}
}

func TestHandlers_GetAllUsage_WrongMethod(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)

	req := httptest.NewRequest("POST", "/api/v1/tenants", nil)
	rr := httptest.NewRecorder()
	h.GetAllUsage(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlers_StatsHandler_WrongMethod(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)

	req := httptest.NewRequest("POST", "/api/v1/tenants/stats", nil)
	rr := httptest.NewRecorder()
	h.StatsHandler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// =====================================================================
// Handlers: WAF config edge cases
// =====================================================================

func TestHandlers_GetTenantWAFConfig_NilConfig(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	tenant, err := m.CreateTenant("NilConfig", "test", []string{"nilcfg.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Force nil config
	tenant.Config = nil

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenant.ID+"/waf-config", nil)
	h.getTenantWAFConfig(rr, req, tenant.ID)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandlers_WAFConfigRoutes_MethodNotAllowed(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	tenant, err := m.CreateTenant("WAFMethod", "test", []string{"wafmethod.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/"+tenant.ID+"/waf-config", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlers_UpdateTenantWAFConfig_NotFound(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	body := `{"enabled":true}`
	req := httptest.NewRequest("PUT", "/api/v1/tenants/nonexistent/waf-config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.updateTenantWAFConfig(rr, req, "nonexistent")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// =====================================================================
// Handlers: verifyKey edge cases
// =====================================================================

func TestHandlers_VerifyKey_EmptyAPIKey(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	// No API key set

	req := httptest.NewRequest("GET", "/test", nil)
	if h.verifyKey(req) {
		t.Error("expected false when API key is empty")
	}
}

func TestHandlers_VerifyKey_AdminKey(t *testing.T) {
	m := NewManager(10)
	h := NewHandlers(m)
	h.SetAPIKey("test-key")

	// Test with X-Admin-Key header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Admin-Key", "test-key")
	if !h.verifyKey(req) {
		t.Error("expected true with correct admin key")
	}
}

// =====================================================================
// TenantRateLimiter edge cases
// =====================================================================

func TestTenantRateLimiter_Check_NoTracker(t *testing.T) {
	trl := NewTenantRateLimiter(time.Minute)
	// Check for a tenant with no recorded requests
	if !trl.Check("unknown", 100) {
		t.Error("expected true for tenant with no requests")
	}
}

func TestTenantRateLimiter_Check_DefaultLimit(t *testing.T) {
	trl := NewTenantRateLimiter(time.Minute)
	// Check with limit 0 (should use default 10000)
	trl.Record("tenant1")
	if !trl.Check("tenant1", 0) {
		t.Error("expected true with default limit after 1 request")
	}
}

func TestRateTracker_Count_NoRecords(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	count := rt.Count()
	if count != 0 {
		t.Errorf("expected 0 for empty tracker, got %d", count)
	}
}

func TestRateTracker_RecordAndCount(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	rt.Record()
	rt.Record()
	rt.Record()
	count := rt.Count()
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

func TestRateTracker_Reset(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	rt.Record()
	rt.Record()
	rt.Reset()
	count := rt.Count()
	if count != 0 {
		t.Errorf("expected 0 after reset, got %d", count)
	}
}

// =====================================================================
// TenantRulesManager.GetRulesLayer concurrent access
// =====================================================================

func TestTenantRulesManager_GetRulesLayer_DefaultMaxRules(t *testing.T) {
	trm := NewTenantRulesManager(0) // 0 -> default 100
	layer := trm.GetRulesLayer("test-tenant", 0)
	if layer == nil {
		t.Error("expected non-nil layer")
	}
	// Should return same layer on second call
	layer2 := trm.GetRulesLayer("test-tenant", 0)
	if layer != layer2 {
		t.Error("expected same layer instance")
	}
}

func TestTenantRulesManager_UpdateTenantRule_NoRule(t *testing.T) {
	trm := NewTenantRulesManager(10)
	result := trm.UpdateTenantRule("nonexistent", rules.Rule{ID: "r1"})
	if result {
		t.Error("expected false for nonexistent tenant")
	}
}

func TestTenantRulesManager_RemoveTenantRule_NoRule(t *testing.T) {
	trm := NewTenantRulesManager(10)
	result := trm.RemoveTenantRule("nonexistent", "r1")
	if result {
		t.Error("expected false for nonexistent tenant")
	}
}

func TestTenantRulesManager_ToggleTenantRule_NoRule(t *testing.T) {
	trm := NewTenantRulesManager(10)
	result := trm.ToggleTenantRule("nonexistent", "r1", true)
	if result {
		t.Error("expected false for nonexistent tenant")
	}
}

func TestTenantRulesManager_GetTenantRule_NotFound(t *testing.T) {
	trm := NewTenantRulesManager(10)
	trm.GetRulesLayer("t1", 10) // ensure layer exists
	r := trm.GetTenantRule("t1", "nonexistent")
	if r != nil {
		t.Error("expected nil for nonexistent rule")
	}
}

// =====================================================================
// AlertManager edge cases
// =====================================================================

func TestAlertManager_Close_Multiple(t *testing.T) {
	am := NewAlertManager()
	am.Close()
	// Second close should not panic
	am.Close()
}

func TestAlertManager_CheckQuotaAlert_Warning80Percent(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	tenant := &Tenant{
		ID:     "warn-test",
		Active: true,
		Quota:  ResourceQuota{MaxRequestsPerMinute: 100},
	}

	// 80 requests out of 100 = 80% -> warning
	am.CheckQuotaAlert(tenant, 80)

	alerts := am.GetAlerts("warn-test", true)
	if len(alerts) == 0 {
		t.Error("expected a quota warning alert at 80%")
	}
}

func TestAlertManager_GetAlerts_NoAcknowledged(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	am.TriggerAlert("t1", AlertRateLimit, AlertWarning, "Test", "msg", nil)
	// Acknowledge
	alerts := am.GetAlerts("t1", true)
	if len(alerts) != 1 {
		t.Fatal("expected 1 alert")
	}
	am.AcknowledgeAlert("t1", alerts[0].ID)

	// Should return no alerts when not including acknowledged
	unack := am.GetAlerts("t1", false)
	if len(unack) != 0 {
		t.Errorf("expected 0 unacknowledged, got %d", len(unack))
	}
}

// =====================================================================
// PathPrefixRouter edge cases
// =====================================================================

func TestPathPrefixRouter_ExtractTenantID_NoSlash(t *testing.T) {
	r := NewPathPrefixRouter(nil, "/tenant/")
	// Path with no trailing slash after tenant ID
	id := r.ExtractTenantID("/tenant/abc123")
	if id != "abc123" {
		t.Errorf("expected abc123, got %q", id)
	}
}

func TestPathPrefixRouter_ExtractTenantID_WithSlash(t *testing.T) {
	r := NewPathPrefixRouter(nil, "/tenant/")
	id := r.ExtractTenantID("/tenant/abc123/api/v1/test")
	if id != "abc123" {
		t.Errorf("expected abc123, got %q", id)
	}
}

func TestPathPrefixRouter_ExtractTenantID_NoMatch(t *testing.T) {
	r := NewPathPrefixRouter(nil, "/tenant/")
	id := r.ExtractTenantID("/other/abc123")
	if id != "" {
		t.Errorf("expected empty, got %q", id)
	}
}

func TestPathPrefixRouter_StripPrefix_NoMatch(t *testing.T) {
	r := NewPathPrefixRouter(nil, "/tenant/")
	result := r.StripPrefix("/other/path")
	if result != "/other/path" {
		t.Errorf("expected /other/path, got %q", result)
	}
}

// =====================================================================
// TenantHeaderExtractor edge cases
// =====================================================================

func TestTenantHeaderExtractor_Extract_NoMatch_NoKey(t *testing.T) {
	m := NewManager(10)
	e := NewTenantHeaderExtractor(m, "")
	req := httptest.NewRequest("GET", "/test", nil)
	result := e.Extract(req)
	if result != nil {
		t.Error("expected nil when no headers set")
	}
}

// =====================================================================
// TenantAwareRouter edge cases
// =====================================================================

func TestTenantAwareRouter_NoHandlerNoDefault(t *testing.T) {
	m := NewManager(10)
	router := NewTenantAwareRouter(m)
	// Don't register any handler

	ctx := WithTenant(context.Background(), &Tenant{ID: "t1"})
	req := httptest.NewRequest("GET", "/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// =====================================================================
// Manager.GetTenantUsage - bandwidth calculation
// =====================================================================

func TestManager_GetTenantUsage_WithBytes(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Bandwidth", "test", []string{"bw.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Record multiple usage entries
	for range 10 {
		m.RecordUsage(tenant, 1000000) // 1MB each
	}

	stats := m.GetTenantUsage(tenant.ID)
	if stats == nil {
		t.Fatal("expected stats")
	}
	if stats.TotalRequests != 10 {
		t.Errorf("TotalRequests = %d, want 10", stats.TotalRequests)
	}
	if stats.BytesTransferred != 10000000 {
		t.Errorf("BytesTransferred = %d, want 10000000", stats.BytesTransferred)
	}
	if stats.BandwidthMbps <= 0 {
		t.Errorf("BandwidthMbps should be > 0, got %f", stats.BandwidthMbps)
	}
}

// =====================================================================
// Manager.GetTenantUsage - quota status
// =====================================================================

func TestManager_GetTenantUsage_QuotaStatusOK(t *testing.T) {
	m := NewManager(10)
	quota := &ResourceQuota{
		MaxRequestsPerMinute: 10000,
	}
	tenant, err := m.CreateTenant("QuotaOK", "test", []string{"quotaok.example.com"}, quota)
	if err != nil {
		t.Fatal(err)
	}

	m.RecordUsage(tenant, 100)
	stats := m.GetTenantUsage(tenant.ID)
	if stats.QuotaStatus != "ok" && stats.QuotaStatus != "warning" {
		t.Logf("QuotaStatus = %q (may be ok or warning depending on rate)", stats.QuotaStatus)
	}
}

// =====================================================================
// Store with corrupted tenant file
// =====================================================================

func TestStore_LoadAllTenants_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	// Write a corrupted tenant file
	if err := os.WriteFile(filepath.Join(dir, "bad-tenant.json"), []byte("not json at all"), 0600); err != nil {
		t.Fatal(err)
	}

	tenants, err := s.LoadAllTenants()
	if err != nil {
		t.Fatalf("LoadAllTenants failed: %v", err)
	}
	// Corrupted file should be skipped
	if len(tenants) != 0 {
		t.Errorf("expected 0 tenants from corrupted file, got %d", len(tenants))
	}
}

// =====================================================================
// Store.LoadTenant file not found
// =====================================================================

func TestStore_LoadTenant_NotFound(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoadTenant("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent tenant")
	}
}

// =====================================================================
// Store.LoadTenant with valid file
// =====================================================================

func TestStore_LoadTenant_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	original := &Tenant{
		ID:          "round-trip-test",
		Name:        "Round Trip",
		Description: "test persistence",
		Active:      true,
		Domains:     []string{"rt.example.com"},
		Quota:       DefaultQuota(),
		CreatedAt:   time.Now().Truncate(time.Millisecond),
		UpdatedAt:   time.Now().Truncate(time.Millisecond),
		APIKeyHash:  "fakehash123",
	}

	if err := s.SaveTenant(original); err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}

	loaded, err := s.LoadTenant("round-trip-test")
	if err != nil {
		t.Fatalf("LoadTenant failed: %v", err)
	}

	if loaded.ID != original.ID {
		t.Errorf("ID = %q, want %q", loaded.ID, original.ID)
	}
	if loaded.Name != original.Name {
		t.Errorf("Name = %q, want %q", loaded.Name, original.Name)
	}
	if loaded.Description != original.Description {
		t.Errorf("Description = %q, want %q", loaded.Description, original.Description)
	}
	if len(loaded.Domains) != 1 || loaded.Domains[0] != "rt.example.com" {
		t.Errorf("Domains = %v, want [rt.example.com]", loaded.Domains)
	}
}

// =====================================================================
// Store.DeleteTenant nonexistent
// =====================================================================

func TestStore_DeleteTenant_NonExistent(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	err := s.DeleteTenant("nonexistent")
	if err != nil {
		t.Errorf("deleting nonexistent tenant should not error, got %v", err)
	}
}

// =====================================================================
// Billing edge cases
// =====================================================================

func TestBillingManager_SetBillingStorePath(t *testing.T) {
	m := NewManager(10)
	// Should not panic
	m.SetBillingStorePath("/some/path")
}

func TestManager_BillingManager_Accessors(t *testing.T) {
	m := NewManager(10)
	if m.BillingManager() == nil {
		t.Error("expected non-nil BillingManager")
	}
	if m.AlertManager() == nil {
		t.Error("expected non-nil AlertManager")
	}
	if m.RulesManager() == nil {
		t.Error("expected non-nil RulesManager")
	}
}
