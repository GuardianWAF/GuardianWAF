package tenant

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverageGap_ManagerCloseAndNilCloseWithContext(t *testing.T) {
	m := NewManager(10)
	m.Close()

	var nilManager *Manager
	if err := nilManager.CloseWithContext(context.Background()); err != nil {
		t.Fatalf("nil CloseWithContext error = %v", err)
	}
}

func TestCoverageGap_AlertCleanupRemovesOldAcknowledgedAndCooldowns(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	old := Alert{
		ID:           "old",
		TenantID:     "tenant-1",
		Type:         AlertQuotaWarning,
		Severity:     AlertWarning,
		Timestamp:    time.Now().Add(-2 * time.Hour),
		Acknowledged: true,
	}
	keep := Alert{
		ID:        "keep",
		TenantID:  "tenant-2",
		Type:      AlertQuotaWarning,
		Severity:  AlertWarning,
		Timestamp: time.Now(),
	}
	am.alerts["tenant-1"] = []Alert{old}
	am.alerts["tenant-2"] = []Alert{keep}
	am.cooldowns["stale"] = time.Now().Add(-11 * time.Minute)
	am.cooldowns["fresh"] = time.Now()

	am.Cleanup(time.Hour)

	if alerts := am.GetAlerts("tenant-1", true); len(alerts) != 0 {
		t.Fatalf("expected old acknowledged alerts removed, got %d", len(alerts))
	}
	if alerts := am.GetAlerts("tenant-2", true); len(alerts) != 1 {
		t.Fatalf("expected recent alert kept, got %d", len(alerts))
	}
	if _, ok := am.cooldowns["stale"]; ok {
		t.Fatal("expected stale cooldown removed")
	}
	if _, ok := am.cooldowns["fresh"]; !ok {
		t.Fatal("expected fresh cooldown kept")
	}
}

func TestCoverageGap_StoreHelperBranches(t *testing.T) {
	if _, err := cleanTenantStorePath("bad\x00path"); err == nil {
		t.Fatal("expected NUL path error")
	}
	if got := validTenantDataFilename("index.json"); got {
		t.Fatal("index.json must be rejected")
	}
	if got := validTenantDataFilename("../tenant.json"); got {
		t.Fatal("path traversal filename must be rejected")
	}
	if got := validTenantDataFilename("tenant.txt"); got {
		t.Fatal("non-json filename must be rejected")
	}
	if _, err := tenantFilePath("bad\x00base", "tenant.json"); err == nil {
		t.Fatal("expected tenantFilePath to reject invalid base path")
	}
	if got := pathWithinDir("bad\x00dir", "tenant.json"); got {
		t.Fatal("invalid dir should not be within dir")
	}

	s := NewStore("bad\x00path")
	if s.basePath != "data/tenants" {
		t.Fatalf("basePath = %q, want fallback data/tenants", s.basePath)
	}
}

func TestCoverageGap_LoadTenantUnexpectedIndexedFile(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	s.index["tenant1"] = "other.json"
	if _, err := s.LoadTenant("tenant1"); err == nil {
		t.Fatal("expected unexpected index entry error")
	}
}

func TestCoverageGap_LoadAllTenantsSkipsInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	valid := `{"id":"tenant1","name":"Tenant 1","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","active":true,"api_key_hash":"hash","domains":["tenant1.example.com"],"quota":{}}`
	if err := os.WriteFile(filepath.Join(dir, "tenant1.json"), []byte(valid), 0o600); err != nil {
		t.Fatalf("write valid tenant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write bad ext: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad-id!.json"), []byte(valid), 0o600); err != nil {
		t.Fatalf("write invalid filename: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tenant2.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatalf("write invalid json: %v", err)
	}
	mismatch := `{"id":"tenant-three","name":"Tenant 3","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","active":true,"api_key_hash":"hash","domains":["tenant3.example.com"],"quota":{}}`
	if err := os.WriteFile(filepath.Join(dir, "tenant3.json"), []byte(mismatch), 0o600); err != nil {
		t.Fatalf("write mismatched id: %v", err)
	}

	tenants, err := s.LoadAllTenants()
	if err != nil {
		t.Fatalf("LoadAllTenants: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != "tenant1" {
		t.Fatalf("expected only valid tenant loaded, got %#v", tenants)
	}
}

func TestCoverageGap_TenantResponseWriterRepeatHeaderAndHijackSuccess(t *testing.T) {
	m := NewManager(10)
	tenant, err := m.CreateTenant("Test", "desc", []string{"test.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	rec := httptest.NewRecorder()
	w := &tenantResponseWriter{ResponseWriter: rec, tenant: tenant, manager: m}
	w.WriteHeader(http.StatusForbidden)
	blocked := tenant.BlockedCount
	w.WriteHeader(http.StatusForbidden)
	if tenant.BlockedCount != blocked {
		t.Fatalf("blocked count changed on repeated WriteHeader: got %d want %d", tenant.BlockedCount, blocked)
	}

	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	hijackable := &hijackableResponseWriter{ResponseWriter: httptest.NewRecorder(), conn: server}
	w = &tenantResponseWriter{ResponseWriter: hijackable, tenant: tenant, manager: m}
	conn, rw, err := w.Hijack()
	if err != nil {
		t.Fatalf("Hijack error = %v", err)
	}
	if conn == nil || rw == nil {
		t.Fatal("expected hijackable connection and readwriter")
	}
}

func TestCoverageGap_RateLimiterConstructorDefaults(t *testing.T) {
	rt := NewRateTracker(10 * time.Second)
	if got := len(rt.slots); got != 60 {
		t.Fatalf("slot count = %d, want 60 minimum", got)
	}

	trl := NewTenantRateLimiter(0)
	if trl.window != time.Minute {
		t.Fatalf("window = %v, want %v", trl.window, time.Minute)
	}
}

type hijackableResponseWriter struct {
	http.ResponseWriter
	conn net.Conn
}

func (h *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn))
	return h.conn, rw, nil
}
