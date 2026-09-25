package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendTenantsFromDir_ValidYAMLFiles(t *testing.T) {
	dir := t.TempDir()

	// Write tenant1.yaml
	tenant1 := `id: tenant-001
name: Acme Corp
description: Primary tenant
api_key: key-abc123
active: true
domains:
  - acme.example.com
  - www.acme.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "tenant1.yaml"), []byte(tenant1), 0644); err != nil {
		t.Fatalf("write tenant1.yaml: %v", err)
	}

	// Write tenant2.yml (note .yml extension)
	tenant2 := `id: tenant-002
name: Beta Inc
active: false
domains:
  - beta.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "tenant2.yml"), []byte(tenant2), 0644); err != nil {
		t.Fatalf("write tenant2.yml: %v", err)
	}

	// Write a non-YAML file (must be ignored)
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0644); err != nil {
		t.Fatalf("write readme.txt: %v", err)
	}

	cfg := DefaultConfig()
	if err := appendTenantsFromDir(dir, cfg); err != nil {
		t.Fatalf("appendTenantsFromDir returned error: %v", err)
	}

	if len(cfg.Tenant.Tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(cfg.Tenant.Tenants))
	}

	// Verify tenant1
	td1 := cfg.Tenant.Tenants[0]
	if td1.ID != "tenant-001" {
		t.Errorf("tenant1 ID: got %q, want %q", td1.ID, "tenant-001")
	}
	if td1.Name != "Acme Corp" {
		t.Errorf("tenant1 Name: got %q, want %q", td1.Name, "Acme Corp")
	}
	if td1.Description != "Primary tenant" {
		t.Errorf("tenant1 Description: got %q, want %q", td1.Description, "Primary tenant")
	}
	if td1.APIKey != "key-abc123" {
		t.Errorf("tenant1 APIKey: got %q, want %q", td1.APIKey, "key-abc123")
	}
	if !td1.Active {
		t.Errorf("tenant1 Active: got false, want true")
	}
	if len(td1.Domains) != 2 {
		t.Fatalf("tenant1 Domains: got %d entries, want 2", len(td1.Domains))
	}
	if td1.Domains[0] != "acme.example.com" {
		t.Errorf("tenant1 Domains[0]: got %q, want %q", td1.Domains[0], "acme.example.com")
	}
	if td1.Domains[1] != "www.acme.example.com" {
		t.Errorf("tenant1 Domains[1]: got %q, want %q", td1.Domains[1], "www.acme.example.com")
	}

	// Verify tenant2
	td2 := cfg.Tenant.Tenants[1]
	if td2.ID != "tenant-002" {
		t.Errorf("tenant2 ID: got %q, want %q", td2.ID, "tenant-002")
	}
	if td2.Name != "Beta Inc" {
		t.Errorf("tenant2 Name: got %q, want %q", td2.Name, "Beta Inc")
	}
	if td2.Active {
		t.Errorf("tenant2 Active: got true, want false")
	}
	if len(td2.Domains) != 1 || td2.Domains[0] != "beta.example.com" {
		t.Errorf("tenant2 Domains: got %v, want [beta.example.com]", td2.Domains)
	}
}

func TestAppendTenantsFromDir_InvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// Write a file with content that triggers a parse error.
	// Non-UTF-8 bytes cause Parse to fail immediately.
	invalid := []byte{0xFF, 0xFE, 0x00, 0x01}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), invalid, 0644); err != nil {
		t.Fatalf("write bad.yaml: %v", err)
	}

	cfg := DefaultConfig()
	err := appendTenantsFromDir(dir, cfg)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

// Round 2026-09-25-r8: a tenants.d file without an id is an ERROR, not a
// silent skip — the old silent-skip contract let an operator's tenant
// definition vanish from cfg.Tenant.Tenants (and the runtime tenant manager)
// with no signal. parseTenantDefinition now follows parseRateLimitRule's
// missing-required-id convention.
func TestAppendTenantsFromDir_MissingIDIsAnError(t *testing.T) {
	dir := t.TempDir()

	noID := `name: No ID Tenant
active: true
domains:
  - noid.example.com
`
	if err := os.WriteFile(filepath.Join(dir, "noid.yaml"), []byte(noID), 0644); err != nil {
		t.Fatalf("write noid.yaml: %v", err)
	}

	cfg := DefaultConfig()
	err := appendTenantsFromDir(dir, cfg)
	if err == nil {
		t.Fatal("expected error for tenant without id, got nil")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Fatalf("error lacks the missing-id marker: %v", err)
	}
}

func TestAppendTenantsFromDir_NonexistentDirectory(t *testing.T) {
	cfg := DefaultConfig()
	// The function returns nil for nonexistent directories (os.IsNotExist guard)
	err := appendTenantsFromDir("/no/such/directory/ever", cfg)
	if err != nil {
		t.Fatalf("expected nil for nonexistent directory, got error: %v", err)
	}
	if len(cfg.Tenant.Tenants) != 0 {
		t.Fatalf("expected 0 tenants, got %d", len(cfg.Tenant.Tenants))
	}
}

func TestAppendTenantsFromDir_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	if err := appendTenantsFromDir(dir, cfg); err != nil {
		t.Fatalf("appendTenantsFromDir returned error: %v", err)
	}
	if len(cfg.Tenant.Tenants) != 0 {
		t.Fatalf("expected 0 tenants for empty directory, got %d", len(cfg.Tenant.Tenants))
	}
}

func TestAppendTenantsFromDir_SkipsSubdirectories(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory that should be skipped
	if err := os.Mkdir(filepath.Join(dir, "subdir.yaml"), 0755); err != nil {
		t.Fatalf("mkdir subdir.yaml: %v", err)
	}

	// Write one valid file alongside the directory
	tenant := `id: only-valid
name: The Only One
`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(tenant), 0644); err != nil {
		t.Fatalf("write valid.yaml: %v", err)
	}

	cfg := DefaultConfig()
	if err := appendTenantsFromDir(dir, cfg); err != nil {
		t.Fatalf("appendTenantsFromDir returned error: %v", err)
	}

	if len(cfg.Tenant.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenant.Tenants))
	}
	if cfg.Tenant.Tenants[0].ID != "only-valid" {
		t.Errorf("tenant ID: got %q, want %q", cfg.Tenant.Tenants[0].ID, "only-valid")
	}
}

func TestAppendTenantsFromDir_DefaultActiveTrue(t *testing.T) {
	dir := t.TempDir()

	// Omit the "active" field entirely — parseTenantDefinition defaults Active to true
	tenant := `id: default-active
name: Default Active
`
	if err := os.WriteFile(filepath.Join(dir, "tenant.yaml"), []byte(tenant), 0644); err != nil {
		t.Fatalf("write tenant.yaml: %v", err)
	}

	cfg := DefaultConfig()
	if err := appendTenantsFromDir(dir, cfg); err != nil {
		t.Fatalf("appendTenantsFromDir returned error: %v", err)
	}

	if len(cfg.Tenant.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenant.Tenants))
	}
	if !cfg.Tenant.Tenants[0].Active {
		t.Error("expected Active to default to true when omitted from YAML")
	}
}

func TestAppendTenantsFromDir_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()

	tenant := `id: appended
name: Appended Tenant
`
	if err := os.WriteFile(filepath.Join(dir, "extra.yaml"), []byte(tenant), 0644); err != nil {
		t.Fatalf("write extra.yaml: %v", err)
	}

	cfg := DefaultConfig()
	// Pre-populate with an existing tenant
	cfg.Tenant.Tenants = append(cfg.Tenant.Tenants, TenantDefinition{
		ID:     "pre-existing",
		Name:   "Already There",
		Active: true,
	})

	if err := appendTenantsFromDir(dir, cfg); err != nil {
		t.Fatalf("appendTenantsFromDir returned error: %v", err)
	}

	if len(cfg.Tenant.Tenants) != 2 {
		t.Fatalf("expected 2 tenants (1 pre-existing + 1 appended), got %d", len(cfg.Tenant.Tenants))
	}
	if cfg.Tenant.Tenants[0].ID != "pre-existing" {
		t.Errorf("first tenant ID: got %q, want %q", cfg.Tenant.Tenants[0].ID, "pre-existing")
	}
	if cfg.Tenant.Tenants[1].ID != "appended" {
		t.Errorf("second tenant ID: got %q, want %q", cfg.Tenant.Tenants[1].ID, "appended")
	}
}
