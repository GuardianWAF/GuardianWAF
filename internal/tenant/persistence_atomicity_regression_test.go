package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func persistenceFixture(t *testing.T) (*Manager, *Tenant, string) {
	t.Helper()
	dir := t.TempDir()
	m := NewManagerWithStore(10, dir)
	t.Cleanup(m.Close)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("original-key"))
	tn := &Tenant{ID: "atomic", Name: "original", Active: true, Domains: []string{"original.test"}, APIKeyHash: hex.EncodeToString(hash[:]), Config: config.DefaultConfig(), Quota: DefaultQuota()}
	if err := m.SaveTenant(tn); err != nil {
		t.Fatal(err)
	}
	m.tenants[tn.ID] = tn
	m.domains["original.test"] = tn.ID
	m.defaultTenantID = tn.ID
	return m, tn, dir
}

func blockPersistenceIndex(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "index.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestTenantFailedUpdateDoesNotPublish(t *testing.T) {
	m, tn, dir := persistenceFixture(t)
	if err := os.Mkdir(filepath.Join(dir, tn.ID+".json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	active := false
	changed := config.DefaultConfig()
	changed.WAF.Detection.Enabled = false
	err := m.UpdateTenant(tn.ID, &TenantUpdate{Name: "changed", Active: &active, Domains: []string{"changed.test"}, Config: changed})
	if err == nil {
		t.Fatal("expected storage failure")
	}
	if tn.Name != "original" || !tn.Active || !tn.Config.WAF.Detection.Enabled || m.GetTenantByDomain("original.test") != tn || m.GetTenantByDomain("changed.test") != nil {
		t.Fatal("failed update published partial state")
	}
	disk, err := m.store.LoadTenant(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Name != "original" || !disk.Active {
		t.Fatal("failed update changed persisted state")
	}
	if err := os.Remove(filepath.Join(dir, tn.ID+".json.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateTenant(tn.ID, &TenantUpdate{Name: "changed", Domains: []string{"changed.test"}}); err != nil {
		t.Fatal(err)
	}
	if tn.Name != "changed" || m.GetTenantByDomain("changed.test") != tn {
		t.Fatal("successful update not published")
	}
}

func TestTenantFailedIndexWriteDoesNotRotateOrDelete(t *testing.T) {
	for _, operation := range []string{"rotate", "delete"} {
		t.Run(operation, func(t *testing.T) {
			m, tn, dir := persistenceFixture(t)
			before, err := os.ReadFile(filepath.Join(dir, tn.ID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			blockPersistenceIndex(t, dir)
			if operation == "rotate" {
				key, err := m.RegenerateAPIKey(tn.ID)
				if err == nil || key != "" {
					t.Fatal("failed rotation returned success/key")
				}
			} else if err := m.DeleteTenant(tn.ID); err == nil {
				t.Fatal("failed delete returned success")
			}
			if m.GetTenant(tn.ID) != tn || m.GetTenantByDomain("original.test") != tn || m.GetTenantByAPIKey("original-key") == nil {
				t.Fatal("failed persistence changed live identity")
			}
			after, err := os.ReadFile(filepath.Join(dir, tn.ID+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("index failure changed authoritative tenant record")
			}
		})
	}
}

func TestTenantFailedCreateDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerWithStore(10, dir)
	t.Cleanup(m.Close)
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	// Seed an index so the same injected failure covers the very first tenant.
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	blockPersistenceIndex(t, dir)
	tn, err := m.CreateTenant("new", "", []string{"new.test"}, nil)
	if err == nil || tn != nil {
		t.Fatal("failed creation returned a tenant")
	}
	if len(m.ListTenants()) != 0 || m.GetTenantByDomain("new.test") != nil || m.GetDefaultTenantID() != "" {
		t.Fatal("failed creation published identity or domain")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "index.json" {
		t.Fatal("failed creation committed a tenant record")
	}
}
