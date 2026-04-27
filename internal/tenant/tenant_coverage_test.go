package tenant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

func init() {
	log.SetOutput(io.Discard)
}

func TestCoverage_Store_CRUD(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)
	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	tenant := &Tenant{
		ID: "test-tenant-1", Name: "Test Tenant", Description: "A test tenant",
		CreatedAt: time.Now(), UpdatedAt: time.Now(), Active: true,
		APIKeyHash: "hash123", Domains: []string{"test.example.com"},
		Quota: DefaultQuota(), Config: config.DefaultConfig(),
	}
	if err := store.SaveTenant(tenant); err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}
	loaded, err := store.LoadTenant("test-tenant-1")
	if err != nil {
		t.Fatalf("LoadTenant failed: %v", err)
	}
	if loaded.Name != "Test Tenant" {
		t.Errorf("Name = %s, want Test Tenant", loaded.Name)
	}
	_, err = store.LoadTenant("non-existent")
	if err == nil {
		t.Error("expected error for non-existent tenant")
	}
	if err := store.DeleteTenant("test-tenant-1"); err != nil {
		t.Fatalf("DeleteTenant failed: %v", err)
	}
	_, err = store.LoadTenant("test-tenant-1")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestCoverage_Store_LoadAllTenants(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)
	store.Init()
	for i := range 3 {
		tenant := &Tenant{
			ID: fmt.Sprintf("tenant-%d", i), Name: fmt.Sprintf("Tenant %d", i),
			Description: "desc", CreatedAt: time.Now(), UpdatedAt: time.Now(),
			Active: true, APIKeyHash: "hash",
			Domains: []string{fmt.Sprintf("t%d.example.com", i)}, Quota: DefaultQuota(),
		}
		store.SaveTenant(tenant)
	}
	tenants, err := store.LoadAllTenants()
	if err != nil {
		t.Fatalf("LoadAllTenants failed: %v", err)
	}
	if len(tenants) != 3 {
		t.Errorf("tenants count = %d, want 3", len(tenants))
	}
}

func TestCoverage_Store_NilConfig(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)
	store.Init()
	tn := &Tenant{
		ID: "nil-cfg", Name: "Nil", Description: "desc",
		CreatedAt: time.Now(), UpdatedAt: time.Now(), Active: true,
		APIKeyHash: "hash", Domains: []string{"nil.example.com"},
		Quota: DefaultQuota(), Config: nil,
	}
	store.SaveTenant(tn)
	loaded, err := store.LoadTenant("nil-cfg")
	if err != nil {
		t.Fatalf("LoadTenant failed: %v", err)
	}
	if loaded.Config == nil {
		t.Error("expected default config when nil was saved")
	}
}

func TestCoverage_Store_DeleteNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)
	store.Init()
	if err := store.DeleteTenant("non-existent"); err != nil {
		t.Errorf("DeleteTenant non-existent: %v", err)
	}
}

func TestCoverage_Store_DefaultBasePath(t *testing.T) {
	store := NewStore("")
	if store.basePath != "data/tenants" {
		t.Errorf("basePath = %s, want data/tenants", store.basePath)
	}
}

func TestCoverage_safeTenantID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"valid-id_123", true}, {"", false}, {"a/b", false}, {"a.b", false},
		{strings.Repeat("a", 129), false}, {strings.Repeat("a", 128), true},
		{"has space", false},
	}
	for _, tt := range tests {
		if safeTenantID(tt.id) != tt.valid {
			t.Errorf("safeTenantID(%q) mismatch", tt.id)
		}
	}
}

func TestCoverage_Manager_Init(t *testing.T) {
	tmpDir := t.TempDir()
	m := NewManagerWithStore(10, filepath.Join(tmpDir, "tenants"))
	if err := m.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestCoverage_Manager_Init_Persisted(t *testing.T) {
	tmpDir := t.TempDir()
	sp := filepath.Join(tmpDir, "tenants")
	m1 := NewManagerWithStore(10, sp)
	m1.Init()
	m1.CreateTenant("P", "desc", []string{"p.com"}, nil)
	m2 := NewManagerWithStore(10, sp)
	if err := m2.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if m2.GetTenantByDomain("p.com") == nil {
		t.Error("expected to find persisted tenant")
	}
}

func TestCoverage_Manager_MaxTenantsReached(t *testing.T) {
	m := NewManager(1)
	_, _ = m.CreateTenant("First", "desc", []string{"first.com"}, nil)
	_, err := m.CreateTenant("Second", "desc", []string{"second.com"}, nil)
	if err == nil {
		t.Error("expected error when max tenants reached")
	}
}

func TestCoverage_UpdateTenant_DomainConflict(t *testing.T) {
	m := NewManager(10)
	m.CreateTenant("T1", "desc", []string{"t1.com"}, nil)
	t2, _ := m.CreateTenant("T2", "desc", []string{"t2.com"}, nil)
	err := m.UpdateTenant(t2.ID, &TenantUpdate{Domains: []string{"t1.com"}})
	if err == nil {
		t.Error("expected error for domain conflict")
	}
}

func TestCoverage_UpdateTenant_DomainRotation(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T1", "desc", []string{"old.com"}, nil)
	if err := m.UpdateTenant(t1.ID, &TenantUpdate{Domains: []string{"new.com"}}); err != nil {
		t.Fatalf("UpdateTenant failed: %v", err)
	}
	if m.GetTenantByDomain("old.com") != nil {
		t.Error("old domain should be freed")
	}
	if m.GetTenantByDomain("new.com") == nil {
		t.Error("new domain should resolve")
	}
}

func TestCoverage_UpdateTenant_ConfigUpdate(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = false
	if err := m.UpdateTenant(t1.ID, &TenantUpdate{Config: cfg}); err != nil {
		t.Fatalf("UpdateTenant with config failed: %v", err)
	}
	u := m.GetTenant(t1.ID)
	if u.Config.WAF.Detection.Enabled {
		t.Error("Detection.Enabled should be false")
	}
}

func TestCoverage_UpdateTenant_NonExistent(t *testing.T) {
	m := NewManager(10)
	err := m.UpdateTenant("nonexistent", &TenantUpdate{Name: "x"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestCoverage_DeleteTenant_DefaultReassignment(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("F", "desc", []string{"f.com"}, nil)
	t2, _ := m.CreateTenant("S", "desc", []string{"s.com"}, nil)
	if m.GetDefaultTenantID() != t1.ID {
		t.Error("first tenant should be default")
	}
	m.DeleteTenant(t1.ID)
	if m.GetDefaultTenantID() != t2.ID {
		t.Error("second should be default")
	}
}

func TestCoverage_RegenerateAPIKey_NonExistent(t *testing.T) {
	m := NewManager(10)
	_, err := m.RegenerateAPIKey("nonexistent")
	if err == nil {
		t.Error("expected error")
	}
}

func TestCoverage_ResolveTenant_RejectUnmatched(t *testing.T) {
	m := NewManager(10)
	m.RejectUnmatched = true
	req := httptest.NewRequest("GET", "http://unknown.com/api", nil)
	if m.ResolveTenant(req) != nil {
		t.Error("expected nil when RejectUnmatched")
	}
}

func TestCoverage_ResolveTenant_APIKeyPriority(t *testing.T) {
	m := NewManager(10)
	_, _ = m.CreateTenant("T1", "desc", []string{"t1.com"}, nil)
	t2, _ := m.CreateTenant("T2", "desc", []string{"t2.com"}, nil)
	apiKey, _ := m.RegenerateAPIKey(t2.ID)
	req := httptest.NewRequest("GET", "http://t1.com/api", nil)
	req.Header.Set("X-GuardianWAF-Tenant-Key", apiKey)
	tenant := m.ResolveTenant(req)
	if tenant == nil || tenant.ID != t2.ID {
		t.Error("API key should take priority")
	}
}

func TestCoverage_GetTenantByDomain_Wildcard(t *testing.T) {
	m := NewManager(10)
	m.CreateTenant("W", "desc", []string{"*.example.com"}, nil)
	if m.GetTenantByDomain("sub.example.com") == nil {
		t.Error("expected wildcard match")
	}
}

func TestCoverage_CheckQuota_NilTenant(t *testing.T) {
	m := NewManager(10)
	if m.CheckQuota(nil) != nil {
		t.Error("CheckQuota nil should return nil")
	}
}

func TestCoverage_CheckQuota_InactiveTenant(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	m.UpdateTenant(t1.ID, &TenantUpdate{Active: boolPtr(false)})
	if m.CheckQuota(t1) == nil {
		t.Error("expected error for inactive tenant")
	}
}

func TestCoverage_RecordUsage_NilTenant(t *testing.T) {
	m := NewManager(10)
	m.RecordUsage(nil, 100)
}

func TestCoverage_RecordBlocked_NilTenant(t *testing.T) {
	m := NewManager(10)
	m.RecordBlocked(nil)
}

func TestCoverage_CleanupRateLimiter(t *testing.T) {
	m := NewManager(10)
	m.CleanupRateLimiter(time.Hour)
}

func TestCoverage_Accessors(t *testing.T) {
	m := NewManager(10)
	if m.BillingManager() == nil {
		t.Error("BillingManager should not be nil")
	}
	if m.AlertManager() == nil {
		t.Error("AlertManager should not be nil")
	}
	m.SetBillingStorePath("/some/path")
}

func TestCoverage_GetTenantUsage(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	m.RecordUsage(t1, 1024)
	m.RecordUsage(t1, 2048)
	usage := m.GetTenantUsage(t1.ID)
	if usage == nil {
		t.Fatal("expected usage")
	}
	if usage.TotalRequests != 2 {
		t.Errorf("TotalRequests = %d, want 2", usage.TotalRequests)
	}
}

func TestCoverage_GetTenantUsage_NonExistent(t *testing.T) {
	m := NewManager(10)
	if m.GetTenantUsage("nonexistent") != nil {
		t.Error("expected nil")
	}
}

func TestCoverage_GetAllUsage(t *testing.T) {
	m := NewManager(10)
	m.CreateTenant("T1", "desc", []string{"t1.com"}, nil)
	m.CreateTenant("T2", "desc", []string{"t2.com"}, nil)
	if len(m.GetAllUsage()) != 2 {
		t.Error("expected 2 usage entries")
	}
}

func TestCoverage_verifyAPIKey_AllFormats(t *testing.T) {
	// v2 format
	key := "gwaf_test_v2"
	h := hashAPIKey(key)
	matched, legacy := verifyAPIKey(h, key)
	if !matched || legacy {
		t.Error("v2 should match without legacy flag")
	}
	matched, _ = verifyAPIKey(h, "wrong")
	if matched {
		t.Error("wrong key should not match v2")
	}
	// v1 format
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	v1key := "gwaf_v1_key"
	v1hash := sha256.Sum256(append(salt, []byte(v1key)...))
	v1stored := hex.EncodeToString(salt) + "$" + hex.EncodeToString(v1hash[:])
	matched, legacy = verifyAPIKey(v1stored, v1key)
	if !matched || !legacy {
		t.Error("v1 should match with legacy flag")
	}
	// Legacy unsalted
	legacyKey := "gwaf_legacy"
	legacyHash := sha256.Sum256([]byte(legacyKey))
	legacyStored := hex.EncodeToString(legacyHash[:])
	matched, legacy = verifyAPIKey(legacyStored, legacyKey)
	if !matched || !legacy {
		t.Error("legacy should match with legacy flag")
	}
	matched, _ = verifyAPIKey(legacyStored, "wrong")
	if matched {
		t.Error("wrong key should not match legacy")
	}
	// Invalid hex
	matched, legacy = verifyAPIKey("v2$ZZZZ$abcd", "anykey")
	if matched || legacy {
		t.Error("invalid hex should not match")
	}
}

func TestCoverage_GetTenantByAPIKey_LegacyUpgrade(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	key := "gwaf_upgrade_key"
	h := sha256.Sum256([]byte(key))
	t1.APIKeyHash = hex.EncodeToString(h[:])
	found := m.GetTenantByAPIKey(key)
	if found == nil || found.ID != t1.ID {
		t.Error("should find tenant with legacy key")
	}
	if !strings.HasPrefix(t1.APIKeyHash, "v2$") {
		t.Error("hash should be upgraded to v2")
	}
}

type mockClusterSync struct {
	mu        sync.Mutex
	calls     []string
	shouldErr bool
}

func (m *mockClusterSync) BroadcastEvent(entityType, entityID, action string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("%s/%s/%s", entityType, entityID, action))
	if m.shouldErr {
		return fmt.Errorf("mock error")
	}
	return nil
}

func TestCoverage_ClusterSync(t *testing.T) {
	m := NewManager(10)
	cs := &mockClusterSync{}
	m.SetClusterSync(cs)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	m.UpdateTenant(t1.ID, &TenantUpdate{Name: "Updated"})
	m.DeleteTenant(t1.ID)
	time.Sleep(200 * time.Millisecond)
	cs.mu.Lock()
	if len(cs.calls) < 3 {
		t.Errorf("expected >= 3 calls, got %d", len(cs.calls))
	}
	cs.mu.Unlock()
}

func TestCoverage_ClusterSync_Error(t *testing.T) {
	m := NewManager(10)
	cs := &mockClusterSync{shouldErr: true}
	m.SetClusterSync(cs)
	m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	time.Sleep(100 * time.Millisecond)
}

func TestCoverage_DeleteTenantWithCleanup(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)
	if err := m.DeleteTenantWithCleanup(t1.ID); err != nil {
		t.Errorf("DeleteTenantWithCleanup failed: %v", err)
	}
}

func TestCoverage_RulesManager_Operations(t *testing.T) {
	m := NewManager(10)
	t1, _ := m.CreateTenant("T", "desc", []string{"t.com"}, nil)

	// Add rule
	err := m.AddTenantRule(t1.ID, map[string]any{
		"name": "SQLi", "priority": 10, "action": "block", "score": 80,
		"conditions": []any{map[string]any{"field": "uri", "op": "contains", "value": "OR 1=1"}},
	})
	if err != nil {
		t.Fatalf("AddTenantRule failed: %v", err)
	}

	ruleList := m.RulesManager().GetTenantRules(t1.ID)
	if len(ruleList) != 1 {
		t.Fatalf("rules = %d, want 1", len(ruleList))
	}

	// Get rule
	r := m.GetTenantRule(t1.ID, ruleList[0].ID)
	if r == nil {
		t.Error("expected rule by ID")
	}

	// Update rule
	err = m.UpdateTenantRule(t1.ID, map[string]any{
		"id": ruleList[0].ID, "name": "Updated", "enabled": true, "action": "log", "score": 50,
	})
	if err != nil {
		t.Errorf("UpdateTenantRule failed: %v", err)
	}

	// Toggle rule
	err = m.ToggleTenantRule(t1.ID, ruleList[0].ID, false)
	if err != nil {
		t.Errorf("ToggleTenantRule failed: %v", err)
	}

	// Remove rule
	err = m.RemoveTenantRule(t1.ID, ruleList[0].ID)
	if err != nil {
		t.Errorf("RemoveTenantRule failed: %v", err)
	}

	// Error cases
	if m.AddTenantRule("nonexistent", map[string]any{"name": "X"}) == nil {
		t.Error("expected error for non-existent tenant")
	}
	if m.AddTenantRule(t1.ID, map[string]any{"priority": 10}) == nil {
		t.Error("expected error for missing name")
	}
	if m.UpdateTenantRule(t1.ID, map[string]any{"name": "X"}) == nil {
		t.Error("expected error for missing id")
	}
	if m.UpdateTenantRule(t1.ID, map[string]any{"id": "bad", "name": "X"}) == nil {
		t.Error("expected error for non-existent rule")
	}
	if m.RemoveTenantRule(t1.ID, "bad") == nil {
		t.Error("expected error for non-existent rule")
	}
	if m.ToggleTenantRule(t1.ID, "bad", true) == nil {
		t.Error("expected error for non-existent rule")
	}
}

func TestCoverage_RulesManager_QuotaExceeded(t *testing.T) {
	trm := NewTenantRulesManager(100)
	trm.AddTenantRule("t1", rules.Rule{ID: "r1", Name: "R1", Enabled: true}, 2)
	trm.AddTenantRule("t1", rules.Rule{ID: "r2", Name: "R2", Enabled: true}, 2)
	if trm.AddTenantRule("t1", rules.Rule{ID: "r3", Name: "R3", Enabled: true}, 2) != ErrQuotaExceeded {
		t.Error("expected quota exceeded")
	}
}

func TestCoverage_RateTracker_Reset(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	rt.Record()
	rt.Record()
	if rt.Count() == 0 {
		t.Error("expected non-zero count")
	}
	rt.Reset()
	if rt.Count() != 0 {
		t.Error("expected zero after reset")
	}
}

func TestCoverage_TenantRateLimiter_Cleanup(t *testing.T) {
	trl := NewTenantRateLimiter(time.Minute)
	trl.Record("tenant-1")

	// Wait for the recorded time to age past the cleanup window
	time.Sleep(50 * time.Millisecond)
	trl.Cleanup(1 * time.Nanosecond)
	// After cleanup, the tracker should be removed
	// Count creates a new tracker if removed, so it should be 0
	if trl.Count("tenant-1") != 0 {
		t.Error("expected 0 after cleanup")
	}
}

func TestCoverage_TenantRateLimiter_DefaultLimit(t *testing.T) {
	trl := NewTenantRateLimiter(time.Minute)
	if !trl.Check("nonexistent", 0) {
		t.Error("should allow with default limit")
	}
}

func TestCoverage_NewTenantRulesManager_Default(t *testing.T) {
	trm := NewTenantRulesManager(0)
	if trm.maxRules != 100 {
		t.Errorf("maxRules = %d, want 100", trm.maxRules)
	}
}

func TestCoverage_TenantRulesManager_Quota(t *testing.T) {
	trm := NewTenantRulesManager(2)
	if !trm.CheckRuleQuota("t1", 0) {
		t.Error("unlimited should allow")
	}
	if !trm.CheckRuleQuota("t1", 10) {
		t.Error("empty should allow")
	}
	if trm.GetRuleCount("t1") != 0 {
		t.Error("expected 0 rules")
	}
}

func TestCoverage_AlertManager_Close(t *testing.T) {
	am := NewAlertManager()
	am.Close()
	am.Close()
}

func TestCoverage_AlertManager_MaxAlertsTrimming(t *testing.T) {
	am := NewAlertManager()
	am.cooldownDur = 0
	for i := range 110 {
		am.TriggerAlert("t1", AlertType(fmt.Sprintf("a%d", i)), AlertInfo, "T", "M", nil)
	}
	if len(am.GetAlerts("t1", true)) > 100 {
		t.Error("expected at most 100 alerts")
	}
}

func TestCoverage_Handlers_FullRoutes(t *testing.T) {
	mgr := NewManager(10)
	h := NewHandlers(mgr)
	h.SetAPIKey("key")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	created, _ := mgr.CreateTenant("T", "D", []string{"t.com"}, nil)

	// List tenants
	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", "key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("list = %d", w.Code)
	}
	// Create via POST
	body, _ := json.Marshal(CreateTenantRequest{Name: "T2", Domains: []string{"t2.com"}})
	req = httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("create = %d", w.Code)
	}
	// DELETE method not allowed on /tenants
	req = httptest.NewRequest("DELETE", "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("delete on list = %d", w.Code)
	}
	// Unauthorized
	req = httptest.NewRequest("GET", "/api/v1/tenants", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauth = %d", w.Code)
	}
	// GET tenant
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID, nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("get = %d", w.Code)
	}
	// DELETE tenant
	req = httptest.NewRequest("DELETE", "/api/v1/tenants/"+created.ID, nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("delete = %d", w.Code)
	}
	// PATCH not allowed
	req = httptest.NewRequest("PATCH", "/api/v1/tenants/x", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("patch = %d", w.Code)
	}
	// Empty ID
	req = httptest.NewRequest("GET", "/api/v1/tenants/", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty id = %d", w.Code)
	}
	// Invalid ID
	req = httptest.NewRequest("GET", "/api/v1/tenants/bad!id", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad id = %d", w.Code)
	}
}

func TestCoverage_Handlers_WAFConfig(t *testing.T) {
	mgr := NewManager(10)
	h := NewHandlers(mgr)
	h.SetAPIKey("key")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	created, _ := mgr.CreateTenant("T", "D", []string{"t.com"}, nil)

	// GET WAF config
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID+"/waf-config", nil)
	req.Header.Set("X-API-Key", "key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("get waf = %d", w.Code)
	}
	// PUT WAF config
	wafCfg := config.WAFConfig{}
	wafCfg.Detection.Enabled = false
	body, _ := json.Marshal(wafCfg)
	req = httptest.NewRequest("PUT", "/api/v1/tenants/"+created.ID+"/waf-config", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("put waf = %d", w.Code)
	}
	// DELETE not allowed on waf-config
	req = httptest.NewRequest("DELETE", "/api/v1/tenants/"+created.ID+"/waf-config", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("delete waf = %d", w.Code)
	}
	// Non-existent tenant WAF config
	req = httptest.NewRequest("GET", "/api/v1/tenants/nonexistent/waf-config", nil)
	req.Header.Set("X-API-Key", "key")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent waf = %d", w.Code)
	}
}

func TestCoverage_Handlers_EdgeCases(t *testing.T) {
	mgr := NewManager(10)
	h := NewHandlers(mgr)
	created, _ := mgr.CreateTenant("T", "D", []string{"t.com"}, nil)

	// RegenerateAPIKey wrong method
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID+"/regenerate-key", nil)
	w := httptest.NewRecorder()
	h.RegenerateAPIKeyHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("wrong method = %d", w.Code)
	}
	// RegenerateAPIKey invalid path
	req = httptest.NewRequest("POST", "/api/v1/tenants/invalid", nil)
	w = httptest.NewRecorder()
	h.RegenerateAPIKeyHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid path = %d", w.Code)
	}
	// StatsHandler wrong method
	req = httptest.NewRequest("POST", "/api/v1/stats", nil)
	w = httptest.NewRecorder()
	h.StatsHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("stats wrong method = %d", w.Code)
	}
	// GetTenantUsage wrong method
	req = httptest.NewRequest("POST", "/usage", nil)
	w = httptest.NewRecorder()
	h.GetTenantUsage(w, req, created.ID)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("usage wrong method = %d", w.Code)
	}
	// GetTenantUsage GET
	req = httptest.NewRequest("GET", "/usage", nil)
	w = httptest.NewRecorder()
	h.GetTenantUsage(w, req, created.ID)
	if w.Code != http.StatusOK {
		t.Errorf("usage get = %d", w.Code)
	}
	// GetTenantUsage non-existent
	req = httptest.NewRequest("GET", "/usage", nil)
	w = httptest.NewRecorder()
	h.GetTenantUsage(w, req, "nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("usage nonexistent = %d", w.Code)
	}
	// GetAllUsage wrong method
	req = httptest.NewRequest("POST", "/usage", nil)
	w = httptest.NewRecorder()
	h.GetAllUsage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("all usage wrong method = %d", w.Code)
	}
	// GetAllUsage GET
	req = httptest.NewRequest("GET", "/usage", nil)
	w = httptest.NewRecorder()
	h.GetAllUsage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("all usage get = %d", w.Code)
	}
	// RegenerateAPIKey non-existent
	req = httptest.NewRequest("POST", "/api/v1/tenants/nonexistent/regenerate-key", nil)
	w = httptest.NewRecorder()
	h.RegenerateAPIKeyHandler(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("regen nonexistent = %d", w.Code)
	}
}

func TestCoverage_sanitizeErr(t *testing.T) {
	if sanitizeErr(nil) != "" {
		t.Error("nil should be empty")
	}
	if sanitizeErr(fmt.Errorf("path /etc/passwd")) != "internal error" {
		t.Error("path should be internal error")
	}
	if sanitizeErr(fmt.Errorf("path \\etc")) != "internal error" {
		t.Error("backslash should be internal error")
	}
	if sanitizeErr(fmt.Errorf("goroutine 1")) != "internal error" {
		t.Error("goroutine should be internal error")
	}
	if sanitizeErr(fmt.Errorf("runtime/ x")) != "internal error" {
		t.Error("runtime should be internal error")
	}
	if len(sanitizeErr(fmt.Errorf("%s", strings.Repeat("x", 300)))) > 200 {
		t.Error("should be truncated")
	}
}

func TestCoverage_Handlers_CreateUpdateDelete_Errors(t *testing.T) {
	mgr := NewManager(10)
	h := NewHandlers(mgr)

	// Create invalid JSON
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()
	h.createTenant(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid json = %d", w.Code)
	}
	// Create duplicate domain
	body, _ := json.Marshal(CreateTenantRequest{Name: "T", Domains: []string{"t.com"}})
	req0 := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	h.createTenant(httptest.NewRecorder(), req0)
	req = httptest.NewRequest("POST", "/", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.createTenant(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate = %d", w.Code)
	}
	// Update invalid JSON
	t1, _ := mgr.CreateTenant("T2", "D", []string{"t2.com"}, nil)
	req = httptest.NewRequest("PUT", "/", bytes.NewReader([]byte("bad")))
	w = httptest.NewRecorder()
	h.updateTenant(w, req, t1.ID)
	if w.Code != http.StatusBadRequest {
		t.Errorf("update invalid json = %d", w.Code)
	}
	// Update non-existent
	body, _ = json.Marshal(UpdateTenantRequest{Name: "X"})
	req = httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.updateTenant(w, req, "nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("update nonexistent = %d", w.Code)
	}
	// Delete non-existent
	req = httptest.NewRequest("DELETE", "/", nil)
	w = httptest.NewRecorder()
	h.deleteTenant(w, req, "nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("delete nonexistent = %d", w.Code)
	}
}

func TestCoverage_Middleware_Handler_WithContext(t *testing.T) {
	mw := NewMiddleware(NewManager(10))
	mw.manager.CreateTenant("T", "D", []string{"t.com"}, nil)
	var captured *Tenant
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetTenant(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Handler(next)
	req := httptest.NewRequest("GET", "http://t.com/api", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if captured == nil {
		t.Error("expected tenant in context")
	}
}

func TestCoverage_BillingManager_LoadBadJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sp := filepath.Join(tmpDir, "billing.json")
	os.WriteFile(sp, []byte("not valid json"), 0600)
	_ = NewBillingManager(sp)
}

func TestCoverage_IsTenantActive_NonExistent(t *testing.T) {
	m := NewManager(10)
	if m.IsTenantActive("nonexistent") {
		t.Error("expected false")
	}
}

func TestCoverage_verifyKey_EdgeCases(t *testing.T) {
	h := NewHandlers(NewManager(10))
	req := httptest.NewRequest("GET", "/", nil)
	if h.verifyKey(req) {
		t.Error("should refuse without key set")
	}
	h.SetAPIKey("key")
	req.Header.Set("X-Admin-Key", "key")
	if !h.verifyKey(req) {
		t.Error("should accept X-Admin-Key")
	}
}

func TestCoverage_CheckQuotaAlert_Unlimited(t *testing.T) {
	am := NewAlertManager()
	tn := &Tenant{ID: "t1", Quota: ResourceQuota{MaxRequestsPerMinute: 0}}
	am.CheckQuotaAlert(tn, 100000)
	if len(am.GetAlerts("t1", true)) != 0 {
		t.Error("expected 0 alerts for unlimited")
	}
}

func TestCoverage_AlertManager_AckWrongTenant(t *testing.T) {
	am := NewAlertManager()
	am.TriggerAlert("t1", AlertQuotaWarning, AlertWarning, "T", "M", nil)
	if am.AcknowledgeAlert("t2", "any") {
		t.Error("should not find on wrong tenant")
	}
}

func TestCoverage_TenantRulesManager_Concurrent(t *testing.T) {
	trm := NewTenantRulesManager(100)
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			trm.GetRulesLayer(fmt.Sprintf("t-%d", i), 10)
			trm.GetTenantRules(fmt.Sprintf("t-%d", i))
			trm.GetRuleCount(fmt.Sprintf("t-%d", i))
		}(i)
	}
	wg.Wait()
}
