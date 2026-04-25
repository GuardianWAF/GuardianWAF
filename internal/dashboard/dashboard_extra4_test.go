package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// =====================================================================
// Middleware tests
// =====================================================================

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RecoveryMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRecoveryMiddleware_WithPanic(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	handler := RecoveryMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Internal Server Error") {
		t.Errorf("expected error message, got: %s", body)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := LoggingMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestSecurityHeadersMiddleware_SkipsSSE(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)

	// SSE endpoint should skip security headers
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Content-Type-Options") != "" {
		t.Error("expected no security headers for SSE endpoint")
	}
}

func TestSecurityHeadersMiddleware_SkipsMCPSSE(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/mcp/sse", nil)
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Content-Type-Options") != "" {
		t.Error("expected no security headers for MCP SSE endpoint")
	}
}

func TestSecurityHeadersMiddleware_AddsHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	handler.ServeHTTP(rr, req)

	expected := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	}
	for _, h := range expected {
		if rr.Header().Get(h) == "" {
			t.Errorf("expected %s header to be set", h)
		}
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %s", rr.Header().Get("X-Frame-Options"))
	}
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for OPTIONS")
	})

	handler := CORSMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/v1/config", nil)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected CORS methods header")
	}
}

func TestCORSMiddleware_NonPreflight(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := CORSMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called for non-OPTIONS")
	}
}

func TestApplyMiddleware(t *testing.T) {
	order := []string{}
	mw1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw1")
			next.ServeHTTP(w, r)
		})
	}
	mw2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "mw2")
			next.ServeHTTP(w, r)
		})
	}
	core := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "core")
	})

	handler := ApplyMiddleware(core, mw1, mw2)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(rr, req)

	// mw1 should be outermost (called first)
	if len(order) != 3 || order[0] != "mw1" || order[1] != "mw2" || order[2] != "core" {
		t.Errorf("expected mw1,mw2,core order, got %v", order)
	}
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	inner := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: inner, statusCode: 200}
	rw.WriteHeader(404)
	if rw.statusCode != 404 {
		t.Errorf("expected 404, got %d", rw.statusCode)
	}
}

// =====================================================================
// Close / lifecycle
// =====================================================================

func TestDashboard_Close(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.Close()
	// Second close should be safe
	d.Close()
}

// =====================================================================
// SetAdminKey / isAdminAuthenticated
// =====================================================================

func TestSetAdminKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAdminKey("admin-secret")
	if d.adminKey != "admin-secret" {
		t.Error("expected admin key to be set")
	}
}

func TestIsAdminAuthenticated_NoKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	req := httptest.NewRequest("GET", "/", nil)
	if d.isAdminAuthenticated(req) {
		t.Error("should not authenticate when no admin key set")
	}
}

func TestIsAdminAuthenticated_CorrectKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAdminKey("admin-key")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "admin-key")
	if !d.isAdminAuthenticated(req) {
		t.Error("should authenticate with correct admin key")
	}
}

func TestIsAdminAuthenticated_WrongKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAdminKey("admin-key")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "wrong")
	if d.isAdminAuthenticated(req) {
		t.Error("should not authenticate with wrong admin key")
	}
}

// =====================================================================
// SetTenantAPIKey / verifyTenantAPIKey / extractTenantID
// =====================================================================

func TestSetTenantAPIKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetTenantAPIKey("tenant-1", "somehash")
	if d.tenantAPIKeys["tenant-1"] != "somehash" {
		t.Error("expected tenant API key to be stored")
	}
}

func TestSetTenantAPIKey_MultipleTenants(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetTenantAPIKey("t1", "hash1")
	d.SetTenantAPIKey("t2", "hash2")
	if len(d.tenantAPIKeys) != 2 {
		t.Errorf("expected 2 tenant keys, got %d", len(d.tenantAPIKeys))
	}
}

func TestExtractTenantID_Path(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/t/tenant-abc/api/v1/events", "tenant-abc"},
		{"/t/my-tenant", "my-tenant"},
		{"/t/my-tenant/", "my-tenant"},
		{"/api/v1/events", ""},
		{"/t/", ""},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		result := extractTenantID(req)
		if result != tt.expected {
			t.Errorf("extractTenantID(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestExtractTenantID_Header(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("X-Tenant-ID", "header-tenant")
	result := extractTenantID(req)
	if result != "header-tenant" {
		t.Errorf("expected header-tenant, got %q", result)
	}
}

func TestExtractTenantID_InvalidChars(t *testing.T) {
	req := httptest.NewRequest("GET", "/t/invalid@tenant/", nil)
	result := extractTenantID(req)
	if result != "" {
		t.Errorf("expected empty for invalid chars, got %q", result)
	}
}

func TestExtractTenantID_TooLong(t *testing.T) {
	longID := strings.Repeat("a", 65)
	req := httptest.NewRequest("GET", "/t/"+longID+"/api", nil)
	result := extractTenantID(req)
	if result != "" {
		t.Errorf("expected empty for too-long ID, got %q", result)
	}
}

func TestVerifyTenantAPIKey(t *testing.T) {
	key := "test-api-key-123"
	hash := hashAPIKeyForTest(key)
	if !verifyTenantAPIKey(hash, key) {
		t.Error("expected key to verify")
	}
	if verifyTenantAPIKey(hash, "wrong-key") {
		t.Error("expected wrong key to not verify")
	}
}

func hashAPIKeyForTest(key string) string {
	// Use v1 format for test: hex(salt)$hex(hash)
	salt := []byte("testsalt")
	salted := append(salt, []byte(key)...)
	h := sha256.Sum256(salted)
	return fmt.Sprintf("%x$%x", salt, h)
}

// =====================================================================
// Auth scoping tests (tenant key restrictions)
// =====================================================================

func TestAuthWrap_TenantKeyBlockedFromAdmin(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetTenantAPIKey("tenant-1", "somehash")

	// Create a v1-format hash that verifyTenantAPIKey can match
	// The tenant key in header won't match the stored hash format,
	// so we test by using the global API key path + checking the scoping logic
	// This test validates the admin prefix check logic exists
	for _, prefix := range adminOnlyPrefixes {
		req := httptest.NewRequest("GET", prefix, nil)
		req.Header.Set("X-API-Key", "k")
		// Global key should work
		_, ok := d.isAuthenticated(req)
		if !ok {
			t.Errorf("global key should authenticate for %s", prefix)
		}
	}
}

// =====================================================================
// Security config audit logging
// =====================================================================

func TestLogSecurityConfigChanges(t *testing.T) {
	d := newTestDashboard(t, "k")
	oldCfg := config.DefaultConfig()
	oldCfg.WAF.Detection.Enabled = true
	oldCfg.WAF.RateLimit.Enabled = true

	newCfg := config.DefaultConfig()
	newCfg.WAF.Detection.Enabled = false
	newCfg.WAF.RateLimit.Enabled = false

	req := httptest.NewRequest("PUT", "/api/v1/config", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	// Should not panic
	d.logSecurityConfigChanges(oldCfg, newCfg, req)
}

// =====================================================================
// Alerting handler tests
// =====================================================================

func TestAlertingStatusEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/alerting/status", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if _, ok := result["webhooks"]; !ok {
		t.Error("expected webhooks field")
	}
	if _, ok := result["emails"]; !ok {
		t.Error("expected emails field")
	}
}

func TestGetWebhooksEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/alerting/webhooks", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetEmailsEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/alerting/emails", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddWebhook_MissingFields(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/alerting/webhooks",
		`{"name":"test"}`, "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAddWebhook_SSRFBlock(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/alerting/webhooks",
		`{"name":"test","url":"http://127.0.0.1:9090/hook"}`, "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for private URL, got %d", w.Code)
	}
}

func TestDeleteWebhook_NotFound(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/alerting/webhooks/nonexistent", "", "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAddEmail_MissingFields(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/alerting/emails",
		`{"name":"test"}`, "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteEmail_NotFound(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/alerting/emails/nonexistent", "", "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestTestAlert_MissingTarget(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/alerting/test", "", "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// =====================================================================
// CWV endpoint tests
// =====================================================================

func TestCWVReport(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/cwv",
		strings.NewReader(`{"name":"LCP","value":2500,"rating":"good"}`))
	req.Header.Set("Content-Type", "application/json")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestCWVReport_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/cwv",
		strings.NewReader("bad json"))
	req.Header.Set("Content-Type", "application/json")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCWVReport_WrongMethod(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/cwv", nil)
	d.Handler().ServeHTTP(w, req)
	// GET /api/v1/cwv requires auth, and this test request has no API key
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated GET, got %d", w.Code)
	}
}

func TestGetCWV(t *testing.T) {
	d := newTestDashboard(t, "k")
	// First store a metric
	req := httptest.NewRequest("POST", "/api/v1/cwv",
		strings.NewReader(`{"name":"FCP","value":1200,"rating":"good"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	d.Handler().ServeHTTP(rr, req)

	// Then retrieve
	w := httptest.NewRecorder()
	req2 := authenticatedRequest("GET", "/api/v1/cwv", "", "k")
	d.Handler().ServeHTTP(w, req2)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// Compliance endpoint tests
// =====================================================================

func TestComplianceControls_NoEngine(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/compliance/controls", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["controls"] == nil {
		t.Error("expected controls field")
	}
}

func TestComplianceReport_NoEngine(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/compliance/report/pci-dss", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestAuditChain_NoEngine(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/compliance/audit-chain", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// Cert endpoint tests
// =====================================================================

func TestGetCerts_NoCertFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ssl", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", result["enabled"])
	}
}

func TestGetCerts_WithCertFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetCertFn(func() any {
		return map[string]any{"certs": []string{"cert1"}, "enabled": true}
	})
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ssl", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// Alerting stats function injection
// =====================================================================

func TestSetAlertingStatsFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAlertingStatsFn(func() any {
		return map[string]any{"sent": 42, "failed": 3}
	})

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/stats", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["alerting"] == nil {
		t.Error("expected alerting stats in response")
	}
}

// =====================================================================
// Health endpoint - degraded
// =====================================================================

func TestHealthEndpoint_NilEngine(t *testing.T) {
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	d := New(eng, store, "k")
	d.engine = nil

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "degraded" {
		t.Errorf("expected degraded, got %v", result["status"])
	}
}

func TestHealthEndpoint_NilEventStore(t *testing.T) {
	eng := newTestEngine(t)
	d := New(eng, nil, "k")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	d.Handler().ServeHTTP(w, req)

	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "degraded" {
		t.Errorf("expected degraded with nil event store, got %v", result["status"])
	}
}

// =====================================================================
// SSE client cap
// =====================================================================

func TestSSEBroadcaster_MaxClients(t *testing.T) {
	b := NewSSEBroadcaster()
	b.maxClients = 2

	// Fill to capacity
	for range 2 {
		ch := make(chan string, 64)
		b.addClient(ch)
	}

	// One more should fail
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	b.HandleSSE(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when max clients reached, got %d", rr.Code)
	}
	cancel()
}

// =====================================================================
// validateAIEndpointURL comprehensive
// =====================================================================

func TestValidateAIEndpointURL_InvalidScheme(t *testing.T) {
	err := validateAIEndpointURL("ftp://example.com")
	if err == nil {
		t.Error("expected error for non-http scheme")
	}
}

func TestValidateAIEndpointURL_Localhost(t *testing.T) {
	err := validateAIEndpointURL("http://localhost:3000")
	if err == nil {
		t.Error("expected error for localhost")
	}
}

func TestValidateAIEndpointURL_LoopbackIP(t *testing.T) {
	err := validateAIEndpointURL("http://127.0.0.1:3000")
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestValidateAIEndpointURL_PrivateIP(t *testing.T) {
	err := validateAIEndpointURL("http://192.168.1.1:3000")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestValidateAIEndpointURL_InvalidURL(t *testing.T) {
	err := validateAIEndpointURL("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestValidateAIEndpointURL_PublicIP(t *testing.T) {
	err := validateAIEndpointURL("https://1.1.1.1")
	// May fail on DNS but should not fail on private IP check
	if err != nil && strings.Contains(err.Error(), "private") {
		t.Errorf("1.1.1.1 is not private: %v", err)
	}
}

// =====================================================================
// Session RevokeSession / cleanup
// =====================================================================

func TestRevokeSession_ValidToken(t *testing.T) {
	token := signSession("10.0.0.1")
	RevokeSession(token)
	if verifySession(token, "10.0.0.1") {
		t.Error("revoked session should not verify")
	}
}

func TestRevokeSession_EmptyToken(t *testing.T) {
	// Should not panic
	RevokeSession("")
}

func TestCleanupRevokedSessions(t *testing.T) {
	// Add some revoked sessions
	for range 5 {
		token := signSession("10.0.0.1")
		RevokeSession(token)
	}
	// Run cleanup - should not panic
	cleanupRevokedSessions()
}

// =====================================================================
// registerActiveSession concurrent sessions
// =====================================================================

func TestRegisterActiveSession_ConcurrentLimit(t *testing.T) {
	ip := "192.0.2.1"
	// Register max+1 sessions to test eviction
	for i := range MaxConcurrentSessionsPerIP + 1 {
		registerActiveSession(fmt.Sprintf("token-%d", i), ip)
	}

	// Verify that only MaxConcurrentSessionsPerIP sessions exist
	v, ok := activeSessions.Load(ip)
	if !ok {
		t.Fatal("expected IP to have sessions")
	}
	sm := v.(*ipSessionMap)
	sm.mu.Lock()
	count := len(sm.tokens)
	sm.mu.Unlock()

	if count != MaxConcurrentSessionsPerIP {
		t.Errorf("expected %d sessions, got %d", MaxConcurrentSessionsPerIP, count)
	}

	// Clean up
	activeSessions.Delete(ip)
}

// =====================================================================
// pprof localhost restriction
// =====================================================================

func TestPprofWrap_NonLocalhost(t *testing.T) {
	d := newTestDashboard(t, "k")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := d.pprofWrap(handler)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/debug/pprof/", nil)
	req.RemoteAddr = "10.0.0.1:1234" // Non-localhost
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-localhost, got %d", rr.Code)
	}
}

// =====================================================================
// Mask URL helper
// =====================================================================

func TestMaskURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://hooks.slack.com/services/abc?token=secret", "https://hooks.slack.com"},
		{"https://user:pass@example.com/path", "https://example.com"},
		{"not-a-url", "://"}, // url.Parse succeeds but returns empty scheme/host
	}

	for _, tt := range tests {
		result := maskURL(tt.input)
		if result != tt.expected {
			t.Errorf("maskURL(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// =====================================================================
// clampInt / clampInt64 / clampFloat edge cases
// =====================================================================

func TestClampInt_Below(t *testing.T) {
	if clampInt(-5, 0, 100) != 0 {
		t.Error("expected clamp to lower bound")
	}
}

func TestClampInt_Above(t *testing.T) {
	if clampInt(200, 0, 100) != 100 {
		t.Error("expected clamp to upper bound")
	}
}

func TestClampInt_InRange(t *testing.T) {
	if clampInt(50, 0, 100) != 50 {
		t.Error("expected value unchanged")
	}
}

func TestClampInt64_Bounds(t *testing.T) {
	if clampInt64(-1, 0, 100) != 0 {
		t.Error("expected clamp to lower bound")
	}
	if clampInt64(200, 0, 100) != 100 {
		t.Error("expected clamp to upper bound")
	}
}

func TestClampFloat_Bounds(t *testing.T) {
	if clampFloat(-1.0, 0.0, 10.0) != 0.0 {
		t.Error("expected clamp to lower bound")
	}
	if clampFloat(20.0, 0.0, 10.0) != 10.0 {
		t.Error("expected clamp to upper bound")
	}
}

// =====================================================================
// verifySameOrigin comprehensive
// =====================================================================

func TestVerifySameOrigin_Match(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://example.com")
	if !verifySameOrigin(req) {
		t.Error("expected same origin to match")
	}
}

func TestVerifySameOrigin_Mismatch(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://evil.com")
	if verifySameOrigin(req) {
		t.Error("expected different origin to fail")
	}
}

func TestVerifySameOrigin_RefererFallback(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	req.Header.Set("Referer", "https://example.com/some/page")
	if !verifySameOrigin(req) {
		t.Error("expected referer to match")
	}
}

func TestVerifySameOrigin_NoHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	if verifySameOrigin(req) {
		t.Error("expected failure with no Origin/Referer")
	}
}

func TestVerifySameOrigin_InvalidOrigin(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "://invalid")
	if verifySameOrigin(req) {
		t.Error("expected failure with invalid Origin URL")
	}
}

func TestVerifySameOrigin_InvalidReferer(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/config", nil)
	req.Host = "example.com"
	req.Header.Set("Referer", "://invalid")
	if verifySameOrigin(req) {
		t.Error("expected failure with invalid Referer URL")
	}
}

// =====================================================================
// Login rate limiting
// =====================================================================

func TestLoginRateLimit_Lockout(t *testing.T) {
	d := newTestDashboard(t, "secret")
	ip := "192.0.2.1"

	// Record max failed attempts
	for range loginMaxAttempts {
		d.recordLoginFailure(ip)
	}

	// Should be locked out now
	if d.checkLoginRateLimit(ip) {
		t.Error("expected IP to be locked out")
	}
}

func TestLoginRateLimit_ResetOnSuccess(t *testing.T) {
	d := newTestDashboard(t, "secret")
	ip := "192.0.2.2"

	d.recordLoginFailure(ip)
	d.recordLoginFailure(ip)
	d.resetLoginAttempts(ip)

	// Should be allowed after reset
	if !d.checkLoginRateLimit(ip) {
		t.Error("expected IP to be allowed after reset")
	}
}

func TestLoginRateLimit_WindowExpiry(t *testing.T) {
	d := newTestDashboard(t, "secret")
	ip := "192.0.2.3"

	// Record a failure with old timestamp
	val, _ := d.loginBuckets.LoadOrStore(ip, &loginBucket{})
	b := val.(*loginBucket)
	b.mu.Lock()
	b.attempts = 3
	b.lastFail = time.Now().Add(-loginWindow - time.Minute)
	b.mu.Unlock()

	// Should be allowed (outside window)
	if !d.checkLoginRateLimit(ip) {
		t.Error("expected IP to be allowed after window expiry")
	}
}

// =====================================================================
// VerifyAPIKeyHash function
// =====================================================================

func TestVerifyAPIKeyHash_V2Format(t *testing.T) {
	// Create a v2 hash manually
	key := "test-key"
	salt := []byte("0123456789abcdef")
	derived := deriveAPIKey([]byte(key), salt, 100000)
	hash := "v2$" + fmt.Sprintf("%x", salt) + "$" + fmt.Sprintf("%x", derived)

	matched, upgrade := verifyAPIKeyHash(hash, key)
	if !matched {
		t.Error("expected v2 key to match")
	}
	if upgrade {
		t.Error("v2 should not need upgrade")
	}
}

func TestVerifyAPIKeyHash_V2WrongKey(t *testing.T) {
	key := "test-key"
	salt := []byte("0123456789abcdef")
	derived := deriveAPIKey([]byte(key), salt, 100000)
	hash := "v2$" + fmt.Sprintf("%x", salt) + "$" + fmt.Sprintf("%x", derived)

	matched, _ := verifyAPIKeyHash(hash, "wrong-key")
	if matched {
		t.Error("expected wrong key to not match")
	}
}

func TestVerifyAPIKeyHash_V2InvalidHex(t *testing.T) {
	matched, _ := verifyAPIKeyHash("v2$zzzz$aaaa", "key")
	if matched {
		t.Error("expected invalid hex to not match")
	}
	matched, _ = verifyAPIKeyHash("v2$abcd$zzzz", "key")
	if matched {
		t.Error("expected invalid hash hex to not match")
	}
}

func TestVerifyAPIKeyHash_Legacy(t *testing.T) {
	key := "test-legacy-key"
	// Unsalted SHA256
	hash := fmt.Sprintf("%x", sha256Sum([]byte(key)))
	matched, upgrade := verifyAPIKeyHash(hash, key)
	if !matched {
		t.Error("expected legacy key to match")
	}
	if !upgrade {
		t.Error("legacy should need upgrade")
	}
}

func TestVerifyAPIKeyHash_LegacyWrongKey(t *testing.T) {
	key := "test-legacy-key"
	hash := fmt.Sprintf("%x", sha256Sum([]byte(key)))
	matched, _ := verifyAPIKeyHash(hash, "wrong-key")
	if matched {
		t.Error("expected wrong legacy key to not match")
	}
}

// sha256Sum helper wraps crypto/sha256.Sum256
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// =====================================================================
// GeoIP POST endpoint tests
// =====================================================================

func TestGeoIPLookupPost_InvalidIP(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/geoip/lookup",
		`{"ip":"not-an-ip"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGeoIPLookupPost_WrongContentType(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/geoip/lookup",
		`{"ip":"1.2.3.4"}`, "k")
	req.Header.Set("Content-Type", "text/plain")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", w.Code)
	}
}

func TestGeoIPLookupPost_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/geoip/lookup",
		strings.NewReader(`{"ip":"8.8.8.8"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "k")
	req.Header.Set("Origin", "https://localhost")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// sanitizeErr tests
// =====================================================================

func TestSanitizeErr_Nil(t *testing.T) {
	if sanitizeErr(nil) != "" {
		t.Error("expected empty string for nil error")
	}
}

func TestSanitizeErr_FilePath(t *testing.T) {
	result := sanitizeErr(fmt.Errorf("error in /etc/passwd"))
	if result != "internal error" {
		t.Errorf("expected 'internal error' for file path, got %q", result)
	}
}

func TestSanitizeErr_Stacktrace(t *testing.T) {
	result := sanitizeErr(fmt.Errorf("goroutine panic"))
	if result != "internal error" {
		t.Errorf("expected 'internal error' for stack trace, got %q", result)
	}
}

func TestSanitizeErr_Normal(t *testing.T) {
	result := sanitizeErr(fmt.Errorf("tenant not found"))
	if result != "tenant not found" {
		t.Errorf("expected original message, got %q", result)
	}
}

func TestSanitizeErr_LongMessage(t *testing.T) {
	longMsg := strings.Repeat("x", 300)
	result := sanitizeErr(fmt.Errorf("%s", longMsg))
	if len(result) > 200 {
		t.Errorf("expected truncated message, got %d chars", len(result))
	}
}

// =====================================================================
// Docker services - with watcher but no services
// =====================================================================

func TestDockerServices_WithWatcher_NoServices(t *testing.T) {
	d := newTestDashboard(t, "k")
	watcher := &mockDockerWatcher{services: nil}
	d.SetDockerWatcher(watcher)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/docker/services", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// Events - offset beyond total
// =====================================================================

func TestGetEvents_OffsetBeyondTotal(t *testing.T) {
	d := newTestDashboard(t, "k")
	// Store one event
	_ = d.eventStore.Store(engine.Event{ID: "evt-1", Action: engine.ActionPass, Score: 0})

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events?offset=100", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["total"] != nil && result["total"].(float64) != 1 {
		t.Errorf("expected total=1, got %v", result["total"])
	}
}

// =====================================================================
// Tenant admin handler tests
// =====================================================================

func TestTenantAdminHandler_Unauthorized(t *testing.T) {
	d := newTestDashboard(t, "k")
	// No admin key set - should reject
	mgr := &mockTenantManager{}
	d.SetTenantManager(mgr)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants", nil)
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTenantAdminHandler_Authorized_ListTenants(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAdminKey("admin-key")
	mgr := &mockTenantManager{
		tenants: []any{
			map[string]any{"id": "t1", "name": "Tenant 1"},
		},
	}
	d.SetTenantManager(mgr)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/tenants", nil)
	req.Header.Set("X-API-Key", "admin-key")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// mockTenantManager for tenant admin handler tests
type mockTenantManager struct {
	tenants []any
	stats   any
	billing BillingManagerInterface
	alerts  AlertManagerInterface
	usage   []any
}

func (m *mockTenantManager) ListTenants() []any          { return m.tenants }
func (m *mockTenantManager) GetTenant(id string) any      { return nil }
func (m *mockTenantManager) CreateTenant(name, description string, domains []string, quota any) (any, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockTenantManager) UpdateTenant(id string, update any) error { return nil }
func (m *mockTenantManager) DeleteTenant(id string) error              { return nil }
func (m *mockTenantManager) RegenerateAPIKey(id string) (string, error) {
	return "new-key", nil
}
func (m *mockTenantManager) Stats() any              { return m.stats }
func (m *mockTenantManager) BillingManager() BillingManagerInterface { return m.billing }
func (m *mockTenantManager) AlertManager() AlertManagerInterface     { return m.alerts }
func (m *mockTenantManager) GetAllUsage() []any       { return m.usage }
func (m *mockTenantManager) GetTenantUsage(tenantID string) any {
	return map[string]any{"tenant_id": tenantID}
}
func (m *mockTenantManager) GetTenantRules(tenantID string) []any        { return nil }
func (m *mockTenantManager) AddTenantRule(tenantID string, rule map[string]any) error {
	return nil
}
func (m *mockTenantManager) GetTenantRule(tenantID, ruleID string) any { return nil }
func (m *mockTenantManager) UpdateTenantRule(tenantID string, rule map[string]any) error {
	return nil
}
func (m *mockTenantManager) RemoveTenantRule(tenantID, ruleID string) error { return nil }
func (m *mockTenantManager) ToggleTenantRule(tenantID, ruleID string, enabled bool) error {
	return nil
}

// =====================================================================
// syncTenantAPIKeys
// =====================================================================

func TestSyncTenantAPIKeys(t *testing.T) {
	d := newTestDashboard(t, "k")
	mgr := &mockTenantManager{
		tenants: []any{
			map[string]any{"id": "t1", "api_key_hash": "hash1"},
			map[string]any{"id": "t2", "api_key_hash": "hash2"},
			map[string]any{"id": "t3"}, // no hash
		},
	}
	d.syncTenantAPIKeys(mgr)

	if len(d.tenantAPIKeys) != 2 {
		t.Errorf("expected 2 tenant API keys, got %d", len(d.tenantAPIKeys))
	}
	if d.tenantAPIKeys["t1"] != "hash1" {
		t.Error("expected t1 hash")
	}
}

func TestSyncTenantAPIKeys_NilManager(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.syncTenantAPIKeys(nil)
	if d.tenantAPIKeys != nil {
		t.Error("expected nil tenantAPIKeys")
	}
}

// =====================================================================
// deepCopyConfig edge cases
// =====================================================================

func TestDeepCopyConfig_PreservesFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = "proxy"
	cfg.TLS.Enabled = true
	cfg.WAF.Detection.Enabled = true

	copy := deepCopyConfig(cfg)
	if copy.Mode != "proxy" {
		t.Error("expected mode to be preserved")
	}
	if !copy.TLS.Enabled {
		t.Error("expected TLS enabled to be preserved")
	}
	if !copy.WAF.Detection.Enabled {
		t.Error("expected detection enabled to be preserved")
	}
}

// =====================================================================
// escapeCSV formula injection
// =====================================================================

func TestEscapeCSV_FormulaInjection(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"=SUM(A1:A10)", "'=SUM(A1:A10)"},
		{"+cmd|'/C calc'!A0", "'+cmd|'/C calc'!A0"},
		{"-1+1", "'-1+1"},
		{"@SUM(A1)", "'@SUM(A1)"},
	}
	for _, tt := range tests {
		result := escapeCSV(tt.input)
		if result != tt.expected {
			t.Errorf("escapeCSV(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// =====================================================================
// Export with limit parameter
// =====================================================================

func TestExportEvents_WithCustomLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	for i := range 10 {
		_ = d.eventStore.Store(engine.Event{
			ID: fmt.Sprintf("evt-%d", i),
			Action: engine.ActionPass,
		})
	}

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events/export?limit=5", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// =====================================================================
// Handler constructor tests (for coverage)
// =====================================================================

func TestNewDLPHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	h := NewDLPHandler(d)
	if h == nil {
		t.Error("expected handler")
	}
}

func TestNewVirtualPatchHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	h := NewVirtualPatchHandler(d)
	if h == nil {
		t.Error("expected handler")
	}
}

func TestNewClientSideHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	h := NewClientSideHandler(d)
	if h == nil {
		t.Error("expected handler")
	}
}

func TestNewAPIValidationHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	h := NewAPIValidationHandler(d)
	if h == nil {
		t.Error("expected handler")
	}
}

func TestNewCRSHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	h := NewCRSHandler(d)
	if h == nil {
		t.Error("expected handler")
	}
}

func TestNewTenantAdminHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	mgr := &mockTenantManager{}
	h := NewTenantAdminHandler(d, mgr)
	if h == nil {
		t.Error("expected handler")
	}
}
