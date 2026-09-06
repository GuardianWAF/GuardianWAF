package tenant

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression tests: SaveTenant must ensure the store directory exists at
// write time. NewStore (and therefore NewManagerWithStore) cleans — and may
// even default — the store path but never creates the directory; only the
// separate Store.Init() lifecycle step did the MkdirAll. SaveTenant wrote
// path+".tmp" and renamed with no dir-ensure, so on a freshly constructed
// manager every save failed and the manager logged it as a non-fatal WARN:
// persistence silently did not persist for any caller following the
// documented persistence constructor. Repo convention (ai/store.go,
// tenant/billing.go, compliance.go) is write-time dir-ensure.

func TestSaveTenantPersistsWithoutInit(t *testing.T) {
	// Store path whose directory does not exist yet.
	storeDir := filepath.Join(t.TempDir(), "tenants")
	m := NewManagerWithStore(10, storeDir)

	created, err := m.CreateTenant("Acme", "", []string{"acme.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	tenantFile := filepath.Join(storeDir, created.ID+".json")
	if _, err := os.Stat(tenantFile); err != nil {
		t.Fatalf("FAIL: tenant file %s was not persisted after CreateTenant (stat: %v) — persistence silently skipped", tenantFile, err)
	}
	if _, err := os.Stat(filepath.Join(storeDir, "index.json")); err != nil {
		t.Fatalf("FAIL: store index.json was not persisted (stat: %v)", err)
	}

	// Round-trip: a second manager on the same path, initialized, loads it.
	m2 := NewManagerWithStore(10, storeDir)
	if err := m2.Init(); err != nil {
		t.Fatalf("second manager Init: %v", err)
	}
	if got := m2.GetTenant(created.ID); got == nil || got.ID != created.ID {
		t.Fatalf("FAIL: tenant %s did not survive a persistence round-trip (got %v)", created.ID, got)
	}
}

// Write-time ensure must also self-heal when the directory is removed after
// earlier successful saves.
func TestSaveTenantSelfHealsRemovedDir(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "tenants")
	s := NewStore(storeDir)

	tenant := &Tenant{ID: "selfheal", Name: "Self Heal", Active: true}
	if err := s.SaveTenant(tenant); err != nil {
		t.Fatalf("first SaveTenant: %v", err)
	}
	if err := os.RemoveAll(storeDir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := s.SaveTenant(tenant); err != nil {
		t.Fatalf("FAIL: SaveTenant after external directory removal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(storeDir, "selfheal.json")); err != nil {
		t.Fatalf("FAIL: tenant file not re-persisted after directory removal (stat: %v)", err)
	}
}
