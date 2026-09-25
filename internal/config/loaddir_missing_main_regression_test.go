package config

// Regression (round 2026-09-25-r9-loaddir-missing-main): LoadDir's
// missing-main-config fallback was dead code — LoadFile wrapped the
// *fs.PathError with %w and os.IsNotExist does not unwrap fmt.Errorf chains,
// so `if os.IsNotExist(err) { cfg = DefaultConfig() }` never fired and
// LoadDir on a directory without guardianwaf.yaml failed with "loading main
// config: reading config file: ..." instead of starting from defaults and
// loading the subdirectories. Post-fix LoadDir detects the missing main file
// via errors.Is(err, fs.ErrNotExist).

import (
	"os"
	"path/filepath"
	"testing"
)

func loaddirLayout(t *testing.T, dir string, withMain bool) {
	t.Helper()
	if withMain {
		if err := os.WriteFile(filepath.Join(dir, "guardianwaf.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tenantsDir := filepath.Join(dir, "tenants.d")
	if err := os.MkdirAll(tenantsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tenantYAML := "id: team-1\nname: team\ndomains:\n  - team.example.com\n"
	if err := os.WriteFile(filepath.Join(tenantsDir, "team.yaml"), []byte(tenantYAML), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A directory without guardianwaf.yaml starts from defaults and still loads
// the subdirectory configs.
func TestLoadDirWithoutMainConfigStartsFromDefaults(t *testing.T) {
	dir := t.TempDir()
	loaddirLayout(t, dir, false)
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir without guardianwaf.yaml failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadDir returned nil config")
	}
	if len(cfg.Tenant.Tenants) != 1 || cfg.Tenant.Tenants[0].ID != "team-1" {
		t.Fatalf("tenants.d not loaded on the defaults-based path: %+v", cfg.Tenant.Tenants)
	}
}

// Control: with the main config present, its values overlay the defaults and
// tenants.d still loads.
func TestLoadDirWithMainConfigOverlaysDefaults(t *testing.T) {
	dir := t.TempDir()
	loaddirLayout(t, dir, true)
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir with guardianwaf.yaml failed: %v", err)
	}
	if cfg.Mode != "enforce" {
		t.Fatalf("main config mode not applied: %q", cfg.Mode)
	}
	if len(cfg.Tenant.Tenants) != 1 || cfg.Tenant.Tenants[0].ID != "team-1" {
		t.Fatalf("tenants.d not loaded: %+v", cfg.Tenant.Tenants)
	}
}

// Boundary: an empty directory (no main config, no subdirectories) yields a
// defaults-based config without error.
func TestLoadDirEmptyDirectoryYieldsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir on an empty directory failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadDir returned nil config")
	}
	if len(cfg.Tenant.Tenants) != 0 {
		t.Fatalf("unexpected tenants on an empty directory: %+v", cfg.Tenant.Tenants)
	}
}
