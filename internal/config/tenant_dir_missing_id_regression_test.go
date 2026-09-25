package config

// Regression (round 2026-09-25-r8-tenant-missing-id): appendTenantsFromDir
// silently dropped tenants.d/*.yaml tenant definitions that lacked an `id` —
// parseTenantDefinition returned an empty-ID TenantDefinition and the caller
// skipped it without error or log, so an operator's tenant definition was
// silently absent from cfg.Tenant.Tenants and therefore from the runtime
// tenant manager (cmd/guardianwaf/tenant_runtime.go seeds from it).
// Post-fix parseTenantDefinition errors on the missing required id (the same
// convention as parseRateLimitRule) and the caller appends unconditionally.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tenantDirMissingIDLayout(t *testing.T, dir string, tenantYAML string) {
	t.Helper()
	// A minimal main config: LoadDir's missing-main-config fallback is
	// separately defective (dead os.IsNotExist branch on the wrapped error,
	// ledgered for a later round) — this regression isolates the
	// tenants.d/missing-id contract.
	if err := os.WriteFile(filepath.Join(dir, "guardianwaf.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tenantsDir := filepath.Join(dir, "tenants.d")
	if err := os.MkdirAll(tenantsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantsDir, "team.yaml"), []byte(tenantYAML), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A tenants.d definition without an id must surface an error naming the
// missing field, not silently vanish from the config.
func TestLoadDirTenantWithoutIDIsAnError(t *testing.T) {
	dir := t.TempDir()
	tenantDirMissingIDLayout(t, dir, "name: team\ndomains:\n  - team.example.com\n")
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatalf("tenant definition without id silently ignored — LoadDir must error on the missing required id")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Fatalf("error lacks the missing-id marker: %v", err)
	}
}

// Control: a well-formed tenant definition loads with its fields.
func TestLoadDirTenantWithIDLoads(t *testing.T) {
	dir := t.TempDir()
	tenantDirMissingIDLayout(t, dir, "id: team-1\nname: team\ndomains:\n  - team.example.com\n")
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("well-formed tenant file failed to load: %v", err)
	}
	if len(cfg.Tenant.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenant.Tenants))
	}
	td := cfg.Tenant.Tenants[0]
	if td.ID != "team-1" || td.Name != "team" || !td.Active || len(td.Domains) != 1 || td.Domains[0] != "team.example.com" {
		t.Fatalf("tenant fields not populated correctly: %+v", td)
	}
}
