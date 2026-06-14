package tenant

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlers_CreateTenant(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	reqBody := CreateTenantRequest{
		Name:        "Test Tenant",
		Description: "Test description",
		Domains:     []string{"test.example.com"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handlers.createTenant(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp CreateTenantResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Tenant == nil {
		t.Fatal("expected tenant in response")
	}

	// Tenant is returned as PublicTenant but decoded from JSON as map[string]any
	tenantMap, ok := resp.Tenant.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any for tenant, got %T", resp.Tenant)
	}
	if tenantMap["name"] != "Test Tenant" {
		t.Errorf("tenant name = %v, want Test Tenant", tenantMap["name"])
	}
	// Verify APIKeyHash is NOT exposed
	if _, hasHash := tenantMap["api_key_hash"]; hasHash {
		t.Error("api_key_hash should not be exposed in API response")
	}
	if _, hasKey := tenantMap["api_key"]; hasKey {
		t.Error("tenant object should not contain plaintext api_key")
	}
	if configMap, ok := tenantMap["waf_config"].(map[string]any); ok {
		if dashboard, ok := configMap["dashboard"].(map[string]any); ok {
			if _, hasAPIKey := dashboard["api_key"]; hasAPIKey {
				t.Fatal("nested dashboard api_key should not be exposed in tenant response")
			}
			if _, hasAdminKey := dashboard["admin_key"]; hasAdminKey {
				t.Fatal("nested dashboard admin_key should not be exposed in tenant response")
			}
		}
	}

	if resp.APIKey == "" {
		t.Error("expected API key in response")
	}
	if resp.APIKey == manager.GetTenant(resp.Tenant.(map[string]any)["id"].(string)).APIKeyHash {
		t.Fatal("one-time api key response should not equal stored hash")
	}
}

func TestHandlers_CreateTenant_Validation(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	tests := []struct {
		name       string
		body       CreateTenantRequest
		wantStatus int
	}{
		{
			name:       "missing name",
			body:       CreateTenantRequest{Domains: []string{"test.com"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing domains",
			body:       CreateTenantRequest{Name: "Test"},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/tenants", bytes.NewReader(body))
			rr := httptest.NewRecorder()

			handlers.createTenant(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandlers_CreateTenantRejectsOversizedBody(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	validPrefix := `{"name":"Test Tenant","domains":["test.example.com"]}`
	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader(validPrefix+strings.Repeat(" ", maxTenantRequestBody)))
	rr := httptest.NewRecorder()

	handlers.createTenant(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
	if got := len(manager.ListTenants()); got != 0 {
		t.Fatalf("oversized create request created %d tenants", got)
	}
}

func TestHandlers_CreateTenantRejectsTrailingJSON(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader(`{"name":"Test Tenant","domains":["test.example.com"]} {}`))
	rr := httptest.NewRecorder()

	handlers.createTenant(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got := len(manager.ListTenants()); got != 0 {
		t.Fatalf("trailing JSON create request created %d tenants", got)
	}
}

func TestHandlers_ListTenants(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	// Create test tenants
	for i := 0; i < 3; i++ {
		manager.CreateTenant("Tenant "+string(rune('A'+i)), "Desc", []string{string(rune('a'+i)) + ".com"}, nil)
	}

	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	rr := httptest.NewRecorder()

	handlers.listTenants(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["count"] != float64(3) {
		t.Errorf("count = %v, want 3", resp["count"])
	}
}

func TestHandlers_GetTenant(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	req := httptest.NewRequest("GET", "/api/v1/tenants/"+created.ID, nil)
	rr := httptest.NewRecorder()

	handlers.getTenant(rr, req, created.ID)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var tenant Tenant
	if err := json.Unmarshal(rr.Body.Bytes(), &tenant); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if tenant.ID != created.ID {
		t.Errorf("ID = %s, want %s", tenant.ID, created.ID)
	}
}

func TestHandlers_GetTenant_NotFound(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	req := httptest.NewRequest("GET", "/api/v1/tenants/nonexistent", nil)
	rr := httptest.NewRecorder()

	handlers.getTenant(rr, req, "nonexistent")

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlers_UpdateTenant(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	active := false
	update := UpdateTenantRequest{
		Name:   "Updated Name",
		Active: &active,
	}
	body, _ := json.Marshal(update)

	req := httptest.NewRequest("PUT", "/api/v1/tenants/"+created.ID, bytes.NewReader(body))
	rr := httptest.NewRecorder()

	handlers.updateTenant(rr, req, created.ID)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var tenant Tenant
	if err := json.Unmarshal(rr.Body.Bytes(), &tenant); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if tenant.Name != "Updated Name" {
		t.Errorf("Name = %s, want Updated Name", tenant.Name)
	}

	if tenant.Active {
		t.Error("expected tenant to be inactive")
	}
}

func TestHandlers_UpdateTenantRejectsOversizedBody(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)
	req := httptest.NewRequest("PUT", "/api/v1/tenants/"+created.ID, strings.NewReader(`{"name":"Updated"}`+strings.Repeat(" ", maxTenantRequestBody)))
	rr := httptest.NewRecorder()

	handlers.updateTenant(rr, req, created.ID)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
	if tenant := manager.GetTenant(created.ID); tenant.Name != "Test" {
		t.Fatalf("oversized update changed tenant name to %q", tenant.Name)
	}
}

func TestHandlers_DeleteTenant(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)

	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	req := httptest.NewRequest("DELETE", "/api/v1/tenants/"+created.ID, nil)
	rr := httptest.NewRecorder()

	handlers.deleteTenant(rr, req, created.ID)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}

	// Verify deletion
	if tenant := manager.GetTenant(created.ID); tenant != nil {
		t.Error("expected tenant to be deleted")
	}
}

func TestHandlers_StatsHandler(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)
	handlers.SetAPIKey("test-key")

	// Create test tenants
	for i := 0; i < 2; i++ {
		manager.CreateTenant("Tenant "+string(rune('A'+i)), "Desc", []string{string(rune('a'+i)) + ".com"}, nil)
	}

	req := httptest.NewRequest("GET", "/api/v1/tenants/stats", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()

	handlers.StatsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var stats ManagerStats
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if stats.TenantCount != 2 {
		t.Errorf("TenantCount = %d, want 2", stats.TenantCount)
	}
}

func TestHandlers_RegenerateAPIKeyHandler(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)
	handlers.SetAPIKey("test-key")

	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	req := httptest.NewRequest("POST", "/api/v1/tenants/"+created.ID+"/regenerate-key", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()

	handlers.RegenerateAPIKeyHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["api_key"] == "" {
		t.Error("expected API key in response")
	}
}

func TestHandlers_RegenerateAPIKeyHandler_Unauthorized(t *testing.T) {
	manager := NewManager(10)
	handlers := NewHandlers(manager)
	handlers.SetAPIKey("test-key")
	created, _ := manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	req := httptest.NewRequest("POST", "/api/v1/tenants/"+created.ID+"/regenerate-key", nil)
	rr := httptest.NewRecorder()

	handlers.RegenerateAPIKeyHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}
