package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func legacyTenantKeyHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func TestTenantAPIKeyCannotMintGlobalSession(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	d.SetTenantAPIKey("tenant-a", legacyTenantKeyHash("tenant-key"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("X-API-Key", "tenant-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "forged"})
	resp := httptest.NewRecorder()

	d.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("tenant request status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			t.Fatalf("tenant API-key request minted a browser session: %#v", cookie)
		}
	}
}

func TestTenantEventDetailEnforcesOwnership(t *testing.T) {
	store := events.NewMemoryStore(10)
	eng := newTestEngine(t)
	d := New(eng, store, "global-key")
	t.Cleanup(d.Close)
	d.SetTenantAPIKey("tenant-a", legacyTenantKeyHash("tenant-key"))

	if err := store.Store(engine.Event{ID: "event-b", TenantID: "tenant-b"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(engine.Event{ID: "event-a", TenantID: "tenant-a"}); err != nil {
		t.Fatal(err)
	}

	request := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events/"+id, nil)
		req.Header.Set("X-API-Key", "tenant-key")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		resp := httptest.NewRecorder()
		d.Handler().ServeHTTP(resp, req)
		return resp
	}

	if resp := request("event-b"); resp.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant event status = %d, want %d: %s", resp.Code, http.StatusNotFound, resp.Body.String())
	}
	if resp := request("event-a"); resp.Code != http.StatusOK {
		t.Fatalf("owned event status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
}

type tenantAuthFixture struct {
	ID         string `json:"id"`
	APIKeyHash string `json:"api_key_hash"`
}

type tenantSnapshotManager struct {
	*mockTenantManager
	hashes map[string]string
}

func (m *tenantSnapshotManager) TenantAPIKeyHashes() map[string]string { return m.hashes }

func TestSyncTenantAPIKeysUsesSnapshotProvider(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	manager := &tenantSnapshotManager{
		mockTenantManager: &mockTenantManager{},
		hashes: map[string]string{
			"tenant-a": legacyTenantKeyHash("tenant-key"),
		},
	}

	d.syncTenantAPIKeys(manager)
	manager.hashes["tenant-a"] = legacyTenantKeyHash("changed-after-sync")

	if !tenantKeyAuthenticates(d, "tenant-a", "tenant-key") {
		t.Fatal("snapshot provider tenant key was not loaded")
	}
	if tenantKeyAuthenticates(d, "tenant-a", "changed-after-sync") {
		t.Fatal("dashboard retained a mutable provider-owned snapshot")
	}
}

func TestSyncTenantAPIKeysAcceptsStructRecords(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	manager := &mockTenantManager{tenants: []any{&tenantAuthFixture{
		ID:         "tenant-a",
		APIKeyHash: legacyTenantKeyHash("tenant-key"),
	}}}

	d.syncTenantAPIKeys(manager)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "tenant-key")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	if authenticated, ok := d.isAuthenticated(req); !ok || getAuthType(authenticated) != authTenant {
		t.Fatal("struct-backed tenant key was not loaded into dashboard authentication")
	}
}

type rotatingTenantManager struct {
	*mockTenantManager
	record tenantAuthFixture
	key    string
}

func (m *rotatingTenantManager) ListTenants() []any   { return []any{&m.record} }
func (m *rotatingTenantManager) GetTenant(string) any { return &m.record }
func (m *rotatingTenantManager) RegenerateAPIKey(string) (string, error) {
	return m.key, nil
}

type tenantLifecycleManager struct {
	*mockTenantManager
	record       *tenantAuthFixture
	generatedKey string
	deleted      bool
}

func (m *tenantLifecycleManager) ListTenants() []any {
	if m.deleted || m.record == nil {
		return nil
	}
	return []any{m.record}
}

func (m *tenantLifecycleManager) CreateTenant(string, string, []string, any) (any, error) {
	return m.record, nil
}

func (m *tenantLifecycleManager) RegenerateAPIKey(string) (string, error) {
	m.record.APIKeyHash = legacyTenantKeyHash(m.generatedKey)
	return m.generatedKey, nil
}

func (m *tenantLifecycleManager) DeleteTenant(string) error {
	m.deleted = true
	return nil
}

func tenantKeyAuthenticates(d *Dashboard, tenantID, key string) bool {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", key)
	req.Header.Set("X-Tenant-ID", tenantID)
	_, ok := d.isAuthenticated(req)
	return ok
}

func TestCreateAndDeleteTenantRefreshDashboardAuthentication(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	manager := &tenantLifecycleManager{
		mockTenantManager: &mockTenantManager{},
		record:            &tenantAuthFixture{ID: "tenant-a"},
		generatedKey:      "created-key",
	}
	handler := NewTenantAdminHandler(d, manager)

	createResp := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/api/admin/tenants", strings.NewReader(`{"name":"Tenant A","domains":["a.example"]}`))
	createReq.Header.Set("Content-Type", "application/json")
	handler.createTenant(createResp, createReq)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d: %s", createResp.Code, http.StatusCreated, createResp.Body.String())
	}
	if !tenantKeyAuthenticates(d, "tenant-a", "created-key") {
		t.Fatal("created tenant key did not authenticate immediately")
	}

	deleteResp := httptest.NewRecorder()
	handler.deleteTenant(deleteResp, httptest.NewRequest(http.MethodDelete, "/", nil), "tenant-a")
	if deleteResp.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d: %s", deleteResp.Code, http.StatusNoContent, deleteResp.Body.String())
	}
	if tenantKeyAuthenticates(d, "tenant-a", "created-key") {
		t.Fatal("deleted tenant key still authenticated")
	}
}

func TestRegenerateTenantKeyRefreshesDashboardAuthentication(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	d.SetTenantAPIKey("tenant-a", legacyTenantKeyHash("old-key"))
	manager := &rotatingTenantManager{
		mockTenantManager: &mockTenantManager{},
		record: tenantAuthFixture{
			ID:         "tenant-a",
			APIKeyHash: legacyTenantKeyHash("new-key"),
		},
		key: "new-key",
	}
	handler := NewTenantAdminHandler(d, manager)
	resp := httptest.NewRecorder()
	handler.regenerateAPIKey(resp, httptest.NewRequest(http.MethodPost, "/", nil), "tenant-a")
	if resp.Code != http.StatusOK {
		t.Fatalf("regenerate status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}

	authenticates := func(key string) bool {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
		req.Header.Set("X-API-Key", key)
		req.Header.Set("X-Tenant-ID", "tenant-a")
		_, ok := d.isAuthenticated(req)
		return ok
	}
	if authenticates("old-key") {
		t.Fatal("old tenant key still authenticated after regeneration")
	}
	if !authenticates("new-key") {
		t.Fatal("new tenant key did not authenticate immediately after regeneration")
	}
}

func TestRotateKeyRejectsPreviousGraceKey(t *testing.T) {
	d := newTestDashboard(t, "old-key")
	t.Cleanup(d.Close)
	d.apiKey.Store(&apiKeyHolder{
		Current:   "current-key",
		Previous:  "old-key",
		ExpiresAt: time.Now().Add(time.Minute),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rotate-key", strings.NewReader(`{"current_key":"old-key","new_key":"replacement-key-123"}`))
	resp := httptest.NewRecorder()
	d.handleRotateKey(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("rotation with grace key status = %d, want %d: %s", resp.Code, http.StatusForbidden, resp.Body.String())
	}
}

func TestSessionRefreshPreservesCreationTime(t *testing.T) {
	d := newTestDashboard(t, "global-key")
	t.Cleanup(d.Close)
	clientIP := "192.0.2.20"
	createdAt := time.Now().Add(-6 * 24 * time.Hour).Truncate(time.Second)
	token := signSessionAt(clientIP, time.Now().Add(-time.Hour), createdAt)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	req.RemoteAddr = clientIP + ":1234"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	resp := httptest.NewRecorder()
	d.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("session request status = %d, want %d: %s", resp.Code, http.StatusOK, resp.Body.String())
	}
	var refreshed string
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			refreshed = cookie.Value
			break
		}
	}
	parts := strings.SplitN(refreshed, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("invalid refreshed session token %q", refreshed)
	}
	if parts[1] != strings.SplitN(token, ".", 3)[1] {
		t.Fatalf("session creation timestamp changed during refresh: old=%q new=%q", token, refreshed)
	}
	v, ok := activeSessions.Load(clientIP)
	if !ok {
		t.Fatal("refreshed session was not tracked")
	}
	sm := v.(*ipSessionMap)
	sm.mu.Lock()
	_, oldTracked := sm.tokens[token]
	_, newTracked := sm.tokens[refreshed]
	trackedCount := len(sm.tokens)
	sm.mu.Unlock()
	if oldTracked || !newTracked || trackedCount != 1 {
		t.Fatalf("session refresh did not replace its active slot: old=%v new=%v count=%d", oldTracked, newTracked, trackedCount)
	}
}

func TestConcurrentSessionEvictionInvalidatesOldestToken(t *testing.T) {
	clientIP := "192.0.2.30"
	activeSessions.Delete(clientIP)
	t.Cleanup(func() { activeSessions.Delete(clientIP) })

	now := time.Now()
	tokens := make([]string, 0, MaxConcurrentSessionsPerIP+1)
	for i := range MaxConcurrentSessionsPerIP + 1 {
		token := signSessionAt(clientIP, now.Add(time.Duration(i)*time.Second), now)
		tokens = append(tokens, token)
		registerActiveSession(token, clientIP)
	}

	if verifySession(tokens[0], clientIP) {
		t.Fatal("oldest session still verified after concurrent-session eviction")
	}
	if !verifySession(tokens[len(tokens)-1], clientIP) {
		t.Fatal("newest session was invalidated by concurrent-session eviction")
	}
}

func TestRegisterActiveSessionIsIdempotentAtCapacity(t *testing.T) {
	clientIP := "192.0.2.31"
	activeSessions.Delete(clientIP)
	t.Cleanup(func() { activeSessions.Delete(clientIP) })

	now := time.Now()
	var newest string
	for i := range MaxConcurrentSessionsPerIP {
		newest = signSessionAt(clientIP, now.Add(time.Duration(i)*time.Second), now)
		registerActiveSession(newest, clientIP)
	}
	registerActiveSession(newest, clientIP)

	if !verifySession(newest, clientIP) {
		t.Fatal("re-registering an active token at capacity revoked that token")
	}
}
