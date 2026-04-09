package tenant

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewMiddleware(t *testing.T) {
	m := NewMiddleware(nil)
	if m == nil {
		t.Fatal("expected middleware, got nil")
	}
}

func TestMiddleware_Handler(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	// Create a tenant
	m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := m.Handler(next)

	req := httptest.NewRequest("GET", "http://test.com/api", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("expected next handler to be called")
	}
}

func TestMiddleware_Handler_NoTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	handler := m.Handler(next)

	req := httptest.NewRequest("GET", "http://unknown.com/api", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestMiddleware_Handler_InactiveTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)
	m.manager.UpdateTenant(tenant.ID, &TenantUpdate{Active: boolPtr(false)})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	handler := m.Handler(next)

	req := httptest.NewRequest("GET", "http://test.com/api", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestMiddleware_Handler_QuotaExceeded(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	quota := &ResourceQuota{MaxRequestsPerMinute: 1}
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, quota)

	// Exhaust quota
	for i := 0; i < 5; i++ {
		m.manager.RecordUsage(tenant, 1)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	handler := m.Handler(next)

	req := httptest.NewRequest("GET", "http://test.com/api", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestMiddleware_Handler_QuotaOK(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.Handler(next)

	req := httptest.NewRequest("GET", "http://test.com/api", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestTenantResponseWriter_Write(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	w := &tenantResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		tenant:         tenant,
		manager:        m.manager,
		wroteHeader:    false,
	}

	n, err := w.Write([]byte("Hello"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if n != 5 {
		t.Errorf("wrote %d bytes, want 5", n)
	}
}

func TestTenantResponseWriter_WriteHeader(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	rec := httptest.NewRecorder()
	w := &tenantResponseWriter{
		ResponseWriter: rec,
		tenant:         tenant,
		manager:        m.manager,
		wroteHeader:    false,
	}

	w.WriteHeader(http.StatusOK)

	if !w.wroteHeader {
		t.Error("expected wroteHeader to be true after WriteHeader")
	}
}

func TestTenantResponseWriter_WriteHeader_Blocked(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	rec := httptest.NewRecorder()
	w := &tenantResponseWriter{
		ResponseWriter: rec,
		tenant:         tenant,
		manager:        m.manager,
		wroteHeader:    false,
	}

	initialBlocked := tenant.BlockedCount
	w.WriteHeader(http.StatusForbidden)

	if tenant.BlockedCount != initialBlocked+1 {
		t.Errorf("BlockedCount = %d, want %d", tenant.BlockedCount, initialBlocked+1)
	}
}

func TestTenantResponseWriter_Flush(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	rec := httptest.NewRecorder()
	w := &tenantResponseWriter{
		ResponseWriter: rec,
		tenant:         tenant,
		manager:        m.manager,
	}

	// Should not panic
	w.Flush()
}

func TestTenantResponseWriter_Hijack(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	rec := httptest.NewRecorder()
	w := &tenantResponseWriter{
		ResponseWriter: rec,
		tenant:         tenant,
		manager:        m.manager,
	}

	// Basic response writer doesn't implement Hijack, should return error
	_, _, err := w.Hijack()
	if err == nil {
		t.Error("expected error for non-hijackable response writer")
	}
}

func TestGetTenantConfig(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	ctx := WithTenant(context.Background(), tenant)

	cfg := GetTenantConfig(ctx)
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
}

func TestGetTenantConfig_NoTenant(t *testing.T) {
	ctx := context.Background()

	cfg := GetTenantConfig(ctx)
	if cfg != nil {
		t.Error("expected nil config for no tenant")
	}
}

func TestRequireTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireTenant(next)

	// With tenant
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithTenant(context.Background(), tenant))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRequireTenant_NoTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := m.RequireTenant(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireAdmin(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)
	m.manager.defaultTenantID = tenant.ID

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := m.RequireAdmin(next)

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithTenant(context.Background(), tenant))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestRequireAdmin_NoTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := m.RequireAdmin(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireAdmin_WrongTenant(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant1, _ := m.manager.CreateTenant("Tenant1", "Desc", []string{"t1.com"}, nil)
	tenant2, _ := m.manager.CreateTenant("Tenant2", "Desc", []string{"t2.com"}, nil)
	m.manager.defaultTenantID = tenant1.ID

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := m.RequireAdmin(next)

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithTenant(context.Background(), tenant2))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestNewTenantAwareRouter(t *testing.T) {
	r := NewTenantAwareRouter(nil)
	if r == nil {
		t.Fatal("expected router, got nil")
	}
}

func TestTenantAwareRouter_Register(t *testing.T) {
	r := NewTenantAwareRouter(nil)
	r.Register("tenant-1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	if len(r.routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(r.routes))
	}
}

func TestTenantAwareRouter_SetDefault(t *testing.T) {
	r := NewTenantAwareRouter(nil)
	r.SetDefault(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	if r.defaultHandler == nil {
		t.Error("expected default handler to be set")
	}
}

func TestTenantAwareRouter_ServeHTTP(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	defaultCalled := false
	r := NewTenantAwareRouter(m.manager)
	r.SetDefault(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultCalled = true
	}))

	handler := r.ServeHTTP

	tenantHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Register(tenant.ID, tenantHandler)

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithTenant(context.Background(), tenant))
	rr := httptest.NewRecorder()

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if defaultCalled {
		t.Error("default handler should not be called when tenant route exists")
	}
}

func TestTenantAwareRouter_ServeHTTP_NoTenant(t *testing.T) {
	r := NewTenantAwareRouter(nil)
	r.SetDefault(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestNewTenantHeaderExtractor(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	ext := NewTenantHeaderExtractor(m.manager, "")
	if ext == nil {
		t.Fatal("expected extractor, got nil")
	}

	if ext.headerName != "X-GuardianWAF-Tenant" {
		t.Errorf("headerName = %s, want X-GuardianWAF-Tenant", ext.headerName)
	}
}

func TestNewTenantHeaderExtractor_CustomHeader(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	ext := NewTenantHeaderExtractor(m.manager, "X-Custom-Tenant")
	if ext.headerName != "X-Custom-Tenant" {
		t.Errorf("headerName = %s, want X-Custom-Tenant", ext.headerName)
	}
}

func TestTenantHeaderExtractor_Extract_TenantID(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)

	ext := NewTenantHeaderExtractor(m.manager, "")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-GuardianWAF-Tenant", tenant.ID)

	extracted := ext.Extract(req)
	if extracted == nil {
		t.Fatal("expected tenant, got nil")
	}

	if extracted.ID != tenant.ID {
		t.Errorf("ID = %s, want %s", extracted.ID, tenant.ID)
	}
}

func TestTenantHeaderExtractor_Extract_APIKey(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	tenant, _ := m.manager.CreateTenant("Test", "Desc", []string{"test.com"}, nil)
	apiKey, _ := m.manager.RegenerateAPIKey(tenant.ID)

	ext := NewTenantHeaderExtractor(m.manager, "")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-GuardianWAF-Tenant-Key", apiKey)

	extracted := ext.Extract(req)
	if extracted == nil {
		t.Fatal("expected tenant, got nil")
	}

	if extracted.ID != tenant.ID {
		t.Errorf("ID = %s, want %s", extracted.ID, tenant.ID)
	}
}

func TestTenantHeaderExtractor_Extract_NoMatch(t *testing.T) {
	m := NewMiddleware(NewManager(10))
	ext := NewTenantHeaderExtractor(m.manager, "")

	req := httptest.NewRequest("GET", "/", nil)

	extracted := ext.Extract(req)
	if extracted != nil {
		t.Error("expected nil for no match")
	}
}

func boolPtr(b bool) *bool {
	return &b
}
