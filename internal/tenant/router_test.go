package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPathPrefixRouter_ExtractTenantID(t *testing.T) {
	manager := NewManager(100)
	router := NewPathPrefixRouter(manager, "/tenant/")

	tests := []struct {
		path     string
		expected string
	}{
		{"/tenant/abc123/api", "abc123"},
		{"/tenant/xyz789/", "xyz789"},
		{"/tenant/abc123", "abc123"},
		{"/api/users", ""},
		{"/tenant/", ""},
		{"/other/path", ""},
	}

	for _, tt := range tests {
		result := router.ExtractTenantID(tt.path)
		if result != tt.expected {
			t.Errorf("ExtractTenantID(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestPathPrefixRouter_StripPrefix(t *testing.T) {
	manager := NewManager(100)
	router := NewPathPrefixRouter(manager, "/tenant/")

	tests := []struct {
		path     string
		expected string
	}{
		{"/tenant/abc123/api/users", "/api/users"},
		{"/tenant/abc123/", "/"},
		{"/tenant/abc123", "/"},
		{"/api/users", "/api/users"}, // no prefix, no strip
		{"/tenant/", "/"},            // empty tenant id
	}

	for _, tt := range tests {
		result := router.StripPrefix(tt.path)
		if result != tt.expected {
			t.Errorf("StripPrefix(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestPathPrefixRouter_DefaultPrefix(t *testing.T) {
	manager := NewManager(100)
	router := NewPathPrefixRouter(manager, "") // empty prefix should default to /tenant/

	// Should use default prefix
	result := router.ExtractTenantID("/tenant/abc123/api")
	if result != "abc123" {
		t.Errorf("ExtractTenantID with default prefix = %q, want %q", result, "abc123")
	}
}

func TestTenantAwareRouter_RegisterAndServe(t *testing.T) {
	manager := NewManager(100)
	router := NewTenantAwareRouter(manager)

	// Create handlers
	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tenant1"))
	})
	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tenant2"))
	})
	defaultHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("default"))
	})

	router.Register("tenant1", handler1)
	router.Register("tenant2", handler2)
	router.SetDefault(defaultHandler)

	tests := []struct {
		tenantID   string
		expectBody string
	}{
		{"tenant1", "tenant1"},
		{"tenant2", "tenant2"},
		{"unknown", "default"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(WithTenant(req.Context(), &Tenant{ID: tt.tenantID}))

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Body.String() != tt.expectBody {
			t.Errorf("ServeHTTP for tenant %s = %q, want %q", tt.tenantID, w.Body.String(), tt.expectBody)
		}
	}
}

func TestTenantAwareRouter_NoTenant(t *testing.T) {
	manager := NewManager(100)
	router := NewTenantAwareRouter(manager)

	defaultHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("default"))
	})
	router.SetDefault(defaultHandler)

	req := httptest.NewRequest("GET", "/", nil) // No tenant in context
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("ServeHTTP without tenant = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestTenantAwareRouter_NoHandler(t *testing.T) {
	manager := NewManager(100)
	router := NewTenantAwareRouter(manager) // No default handler

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithTenant(req.Context(), &Tenant{ID: "unknown"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("ServeHTTP without handler = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestTenantHeaderExtractor_DefaultHeaderName(t *testing.T) {
	manager := NewManager(100)
	extractor := NewTenantHeaderExtractor(manager, "")

	if extractor.headerName != "X-GuardianWAF-Tenant" {
		t.Errorf("Default header name = %s, want X-GuardianWAF-Tenant", extractor.headerName)
	}

	// Custom header name
	extractor2 := NewTenantHeaderExtractor(manager, "X-Custom-Tenant")
	if extractor2.headerName != "X-Custom-Tenant" {
		t.Errorf("Custom header name = %s, want X-Custom-Tenant", extractor2.headerName)
	}
}
