package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager(10)
	if m == nil {
		t.Fatal("expected manager, got nil")
	}
	if m.maxTenants != 10 {
		t.Errorf("maxTenants = %d, want 10", m.maxTenants)
	}
	if len(m.tenants) != 0 {
		t.Error("expected empty tenants map")
	}
}

func TestManager_CreateTenant(t *testing.T) {
	m := NewManager(10)

	tests := []struct {
		name        string
		tenantName  string
		description string
		domains     []string
		wantErr     bool
	}{
		{
			name:        "valid tenant",
			tenantName:  "Test Tenant",
			description: "A test tenant",
			domains:     []string{"test.example.com"},
			wantErr:     false,
		},
		{
			name:        "duplicate domain",
			tenantName:  "Another Tenant",
			description: "Another tenant",
			domains:     []string{"test.example.com"}, // Same as first
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, err := m.CreateTenant(tt.tenantName, tt.description, tt.domains, nil)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tenant == nil {
				t.Fatal("expected tenant, got nil")
			}

			if tenant.Name != tt.tenantName {
				t.Errorf("Name = %s, want %s", tenant.Name, tt.tenantName)
			}

			if tenant.APIKeyHash == "" {
				t.Error("expected API key hash to be set")
			}

			if !tenant.Active {
				t.Error("expected tenant to be active")
			}
		})
	}
}

func TestManager_GetTenant(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Get by ID
	tenant := m.GetTenant(created.ID)
	if tenant == nil {
		t.Fatal("expected to find tenant")
	}
	if tenant.ID != created.ID {
		t.Errorf("ID mismatch: got %s, want %s", tenant.ID, created.ID)
	}

	// Get non-existent
	tenant = m.GetTenant("non-existent")
	if tenant != nil {
		t.Error("expected nil for non-existent tenant")
	}
}

func TestManager_GetTenantByDomain(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	_, err := m.CreateTenant("Test", "Description", []string{"test.example.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Get by domain
	tenant := m.GetTenantByDomain("test.example.com")
	if tenant == nil {
		t.Fatal("expected to find tenant by domain")
	}

	// Get non-existent domain
	tenant = m.GetTenantByDomain("nonexistent.com")
	if tenant != nil {
		t.Error("expected nil for non-existent domain")
	}
}

func TestManager_GetTenantByAPIKey(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Regenerate API key to get the actual key
	apiKey, err := m.RegenerateAPIKey(created.ID)
	if err != nil {
		t.Fatalf("failed to regenerate API key: %v", err)
	}

	// Get by API key
	tenant := m.GetTenantByAPIKey(apiKey)
	if tenant == nil {
		t.Fatal("expected to find tenant by API key")
	}
	if tenant.ID != created.ID {
		t.Errorf("ID mismatch: got %s, want %s", tenant.ID, created.ID)
	}

	// Get with invalid key
	tenant = m.GetTenantByAPIKey("invalid-key")
	if tenant != nil {
		t.Error("expected nil for invalid API key")
	}

	// Get with empty key
	tenant = m.GetTenantByAPIKey("")
	if tenant != nil {
		t.Error("expected nil for empty API key")
	}
}

func TestManager_ResolveTenant(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	_, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Resolve by domain
	req := httptest.NewRequest("GET", "http://test.com/api", nil)
	tenant := m.ResolveTenant(req)
	if tenant == nil {
		t.Error("expected to resolve tenant by domain")
	}
}

func TestManager_UpdateTenant(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Update
	active := false
	update := &TenantUpdate{
		Name:        "Updated Name",
		Description: "Updated Description",
		Active:      &active,
	}

	err = m.UpdateTenant(created.ID, update)
	if err != nil {
		t.Fatalf("failed to update tenant: %v", err)
	}

	// Verify
	tenant := m.GetTenant(created.ID)
	if tenant.Name != "Updated Name" {
		t.Errorf("Name = %s, want Updated Name", tenant.Name)
	}
	if tenant.Description != "Updated Description" {
		t.Errorf("Description = %s, want Updated Description", tenant.Description)
	}
	if tenant.Active {
		t.Error("expected tenant to be inactive")
	}
}

func TestManager_DeleteTenant(t *testing.T) {
	m := NewManager(10)

	// Create tenant
	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Delete
	err = m.DeleteTenant(created.ID)
	if err != nil {
		t.Fatalf("failed to delete tenant: %v", err)
	}

	// Verify
	tenant := m.GetTenant(created.ID)
	if tenant != nil {
		t.Error("expected tenant to be deleted")
	}

	// Domain should be freed
	tenant = m.GetTenantByDomain("test.com")
	if tenant != nil {
		t.Error("expected domain to be unassigned")
	}

	// Delete non-existent
	err = m.DeleteTenant("non-existent")
	if err == nil {
		t.Error("expected error for non-existent tenant")
	}
}

func TestManager_ListTenants(t *testing.T) {
	m := NewManager(10)

	// Create multiple tenants
	for i := 0; i < 3; i++ {
		_, err := m.CreateTenant(
			"Tenant " + string(rune('A'+i)),
			"Description",
			[]string{string(rune('a'+i)) + ".example.com"},
			nil,
		)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}
	}

	tenants := m.ListTenants()
	if len(tenants) != 3 {
		t.Errorf("expected 3 tenants, got %d", len(tenants))
	}
}

func TestManager_Stats(t *testing.T) {
	m := NewManager(10)

	// Create tenants
	for i := 0; i < 2; i++ {
		_, err := m.CreateTenant(
			"Tenant " + string(rune('A'+i)),
			"Description",
			[]string{string(rune('a'+i)) + ".example.com"},
			nil,
		)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}
	}

	stats := m.Stats()
	if stats.TenantCount != 2 {
		t.Errorf("TenantCount = %d, want 2", stats.TenantCount)
	}
	if stats.DomainCount != 2 {
		t.Errorf("DomainCount = %d, want 2", stats.DomainCount)
	}
	if stats.MaxTenants != 10 {
		t.Errorf("MaxTenants = %d, want 10", stats.MaxTenants)
	}
}

func TestManager_CheckQuota(t *testing.T) {
	m := NewManager(10)

	// Create tenant with low quota
	quota := &ResourceQuota{
		MaxRequestsPerMinute: 1,
	}
	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, quota)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// First request should pass
	if err := m.CheckQuota(created); err != nil {
		t.Errorf("unexpected quota error: %v", err)
	}

	// Record usage to exceed quota
	for i := 0; i < 5; i++ {
		m.RecordUsage(created, 100)
	}

	// Check should now fail
	if err := m.CheckQuota(created); err == nil {
		t.Error("expected quota error after exceeding limit")
	}
}

func TestManager_RecordUsage(t *testing.T) {
	m := NewManager(10)

	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Record usage
	m.RecordUsage(created, 1000)
	m.RecordUsage(created, 2000)

	if created.RequestCount != 2 {
		t.Errorf("RequestCount = %d, want 2", created.RequestCount)
	}
	if created.ByteCount != 3000 {
		t.Errorf("ByteCount = %d, want 3000", created.ByteCount)
	}
}

func TestManager_RecordBlocked(t *testing.T) {
	m := NewManager(10)

	created, err := m.CreateTenant("Test", "Description", []string{"test.com"}, nil)
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Record blocked
	m.RecordBlocked(created)
	m.RecordBlocked(created)

	if created.BlockedCount != 2 {
		t.Errorf("BlockedCount = %d, want 2", created.BlockedCount)
	}
}

func TestDefaultQuota(t *testing.T) {
	quota := DefaultQuota()

	if quota.MaxRequestsPerMinute != 10000 {
		t.Errorf("MaxRequestsPerMinute = %d, want 10000", quota.MaxRequestsPerMinute)
	}
	if quota.MaxRules != 100 {
		t.Errorf("MaxRules = %d, want 100", quota.MaxRules)
	}
}

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		domain  string
		pattern string
		match   bool
	}{
		{"sub.example.com", "*.example.com", true},
		{"deep.sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"example.com", "example.com", true},
		{"test.com", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain+"_"+tt.pattern, func(t *testing.T) {
			result := matchWildcard(tt.domain, tt.pattern)
			if result != tt.match {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.domain, tt.pattern, result, tt.match)
			}
		})
	}
}

func TestWithTenant(t *testing.T) {
	ctx := context.Background()

	tenant := &Tenant{ID: "test-123", Name: "Test"}
	ctx = WithTenant(ctx, tenant)

	retrieved := GetTenant(ctx)
	if retrieved == nil {
		t.Fatal("expected to get tenant from context")
	}
	if retrieved.ID != tenant.ID {
		t.Errorf("ID = %s, want %s", retrieved.ID, tenant.ID)
	}
}

func TestGetTenantID(t *testing.T) {
	ctx := context.Background()

	// No tenant
	id := GetTenantID(ctx)
	if id != "" {
		t.Errorf("expected empty ID, got %s", id)
	}

	// With tenant
	tenant := &Tenant{ID: "test-123", Name: "Test"}
	ctx = WithTenant(ctx, tenant)
	id = GetTenantID(ctx)
	if id != "test-123" {
		t.Errorf("ID = %s, want test-123", id)
	}
}

func TestIsTenantRequest(t *testing.T) {
	ctx := context.Background()

	// No tenant
	if IsTenantRequest(&http.Request{}) {
		t.Error("expected false for request without tenant")
	}

	// With tenant
	tenant := &Tenant{ID: "test-123", Name: "Test"}
	ctx = WithTenant(ctx, tenant)
	req := &http.Request{}
	req = req.WithContext(ctx)
	if !IsTenantRequest(req) {
		t.Error("expected true for request with tenant")
	}
}
