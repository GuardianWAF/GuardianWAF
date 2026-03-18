package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// --- Test helpers ---

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func newTestDashboard(t *testing.T, apiKey string) *Dashboard {
	t.Helper()
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	return New(eng, store, apiKey)
}

func authenticatedRequest(method, path string, body string, apiKey string) *http.Request {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	return req
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	return result
}

// --- Auth Tests ---

func TestSignAndVerifySession(t *testing.T) {
	token := signSession()
	if token == "" {
		t.Fatal("signSession returned empty token")
	}
	if !verifySession(token) {
		t.Error("verifySession rejected valid token")
	}
}

func TestVerifySession_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dot", "nodotseparator"},
		{"bad signature", "123456789.badsignature"},
		{"tampered timestamp", "999999999.abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if verifySession(tt.token) {
				t.Error("expected invalid session")
			}
		})
	}
}

func TestIsAuthenticated_NoAPIKey(t *testing.T) {
	d := newTestDashboard(t, "")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	if !d.isAuthenticated(req) {
		t.Error("should be authenticated when no API key configured")
	}
}

func TestIsAuthenticated_APIKeyHeader(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "secret-key")
	if !d.isAuthenticated(req) {
		t.Error("should be authenticated with correct API key header")
	}
}

func TestIsAuthenticated_APIKeyQuery(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats?api_key=secret-key", nil)
	if !d.isAuthenticated(req) {
		t.Error("should be authenticated with correct API key in query")
	}
}

func TestIsAuthenticated_WrongKey(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	if d.isAuthenticated(req) {
		t.Error("should not be authenticated with wrong key")
	}
}

func TestIsAuthenticated_SessionCookie(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	token := signSession()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if !d.isAuthenticated(req) {
		t.Error("should be authenticated with valid session cookie")
	}
}

func TestIsAuthenticated_NoCreds(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	if d.isAuthenticated(req) {
		t.Error("should not be authenticated without credentials")
	}
}

// --- Auth Wrap Tests ---

func TestAuthWrap_APIUnauthorized(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["error"] != "unauthorized" {
		t.Errorf("expected unauthorized error, got %v", result["error"])
	}
}

func TestAuthWrap_BrowserRedirect(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %s", loc)
	}
}

// --- Health endpoint ---

func TestHealthEndpoint(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["status"] != "healthy" {
		t.Errorf("expected healthy, got %v", result["status"])
	}
}

// --- Stats endpoint ---

func TestStatsEndpoint(t *testing.T) {
	d := newTestDashboard(t, "mykey")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/stats", "", "mykey")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if _, ok := result["total_requests"]; !ok {
		t.Error("expected total_requests in stats")
	}
}

// --- Events endpoint ---

func TestEventsEndpoint(t *testing.T) {
	d := newTestDashboard(t, "mykey")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events?limit=10&offset=0", "", "mykey")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	// "events" key should exist (may be null for empty store)
	if _, ok := result["events"]; !ok {
		t.Error("expected events key in response")
	}
	if _, ok := result["total"]; !ok {
		t.Error("expected total key in response")
	}
}

func TestEventsEndpoint_WithFilters(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET",
		"/api/v1/events?action=block&client_ip=1.2.3.4&min_score=50&since=2025-01-01T00:00:00Z&until=2026-01-01T00:00:00Z",
		"", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetEventEndpoint_NotFound(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events/nonexistent-id", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- Config endpoints ---

func TestGetConfigEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/config", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["waf"] == nil {
		t.Error("expected waf section in config")
	}
}

func TestUpdateConfigEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"mode":"proxy","waf":{"detection":{"enabled":false},"rate_limit":{"enabled":false},"sanitizer":{"enabled":false,"max_body_size":2048,"max_url_length":512},"bot_detection":{"enabled":false,"mode":"log","user_agent":{"block_empty":true,"block_known_scanners":true},"behavior":{"rps_threshold":50,"error_rate_threshold":80}},"challenge":{"enabled":false,"difficulty":5},"ip_acl":{"enabled":false,"auto_ban":{"enabled":false}},"response":{"security_headers":{"enabled":false},"data_masking":{"enabled":false,"mask_credit_cards":true,"mask_ssn":true,"mask_api_keys":true,"strip_stack_traces":true}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateConfigEndpoint_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", "not json", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateConfigEndpoint_TLS(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"tls":{"enabled":false,"listen":":8443","cert_file":"cert.pem","key_file":"key.pem","http_redirect":true,"acme":{"enabled":false,"email":"test@test.com","cache_dir":"/tmp/acme"}}}`
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
}

// --- Upstreams endpoint ---

func TestUpstreamsEndpoint_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/upstreams", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestUpstreamsEndpoint_WithFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetUpstreamsFn(func() any {
		return []map[string]any{{"name": "backend", "healthy": true}}
	})
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/upstreams", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- IP ACL endpoints ---

func TestIPACLEndpoint_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ipacl", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddIPACL_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl", `{"list":"whitelist","ip":"1.2.3.4"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl", `{"list":"whitelist","ip":"1.2.3.4"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Bans endpoints ---

func TestBansEndpoint_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/bans", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRemoveBan_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/bans", `{"ip":"1.2.3.4"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Rules endpoints ---

func TestRulesEndpoint_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/rules", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRulesEndpoint_WithFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(
		func() any { return []map[string]any{{"id": "r1", "name": "test"}} },
		func(m map[string]any) error { return nil },
		func(id string, m map[string]any) error { return nil },
		func(id string) bool { return true },
		func(id string, enabled bool) bool { return true },
		func(ip string) (string, string) { return "US", "United States" },
	)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/rules", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddRuleEndpoint_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/rules", `{"id":"r1","name":"test"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

func TestAddRuleEndpoint_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(
		func() any { return nil },
		func(m map[string]any) error { return nil },
		func(id string, m map[string]any) error { return nil },
		func(id string) bool { return true },
		func(id string, enabled bool) bool { return true },
		nil,
	)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/rules", "bad", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateRuleEndpoint_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/rules/r1", `{"name":"updated"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", w.Code)
	}
}

func TestDeleteRuleEndpoint_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/rules/r1", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- GeoIP Lookup ---

func TestGeoIPLookup_NoIP(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/geoip/lookup", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGeoIPLookup_NoFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/geoip/lookup?ip=1.2.3.4", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["name"] != "GeoIP not configured" {
		t.Errorf("expected not configured, got %v", result["name"])
	}
}

func TestGeoIPLookup_WithFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(nil, nil, nil, nil, nil, func(ip string) (string, string) {
		return "TR", "Turkey"
	})
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/geoip/lookup?ip=5.5.5.5", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["country"] != "TR" {
		t.Errorf("expected TR, got %v", result["country"])
	}
}

// --- Logs ---

func TestLogsEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?limit=50&level=info", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- CORS ---

func TestCORSHandler(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/v1/config", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected CORS header")
	}
}

// --- Login flow ---

func TestLoginPage(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "GuardianWAF") {
		t.Error("expected login page content")
	}
}

func TestLoginPage_NoAuth(t *testing.T) {
	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect when no auth configured, got %d", w.Code)
	}
}

func TestLoginPage_AlreadyAuthenticated(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession()})
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect when already authenticated, got %d", w.Code)
	}
}

func TestLoginSubmit_Success(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect after login, got %d", w.Code)
	}
	// Check session cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie after login")
	}
}

func TestLoginSubmit_WrongKey(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid API key") {
		t.Error("expected error message in response")
	}
}

func TestLoginSubmit_NoAuth(t *testing.T) {
	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=whatever"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect when no auth configured, got %d", w.Code)
	}
}

func TestLogout(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/logout", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", w.Code)
	}
	// Check cookie was cleared
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.MaxAge != -1 {
			t.Error("expected cookie to be cleared")
		}
	}
}

// --- SSE Broadcaster ---

func TestSSEBroadcaster_ClientCount(t *testing.T) {
	b := NewSSEBroadcaster()
	if b.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", b.ClientCount())
	}

	ch := make(chan string, 64)
	b.addClient(ch)
	if b.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", b.ClientCount())
	}

	b.removeClient(ch)
	if b.ClientCount() != 0 {
		t.Errorf("expected 0 clients after remove, got %d", b.ClientCount())
	}
}

func TestSSEBroadcaster_BroadcastEvent(t *testing.T) {
	b := NewSSEBroadcaster()
	ch := make(chan string, 64)
	b.addClient(ch)
	defer b.removeClient(ch)

	event := engine.Event{
		ID:       "test-1",
		ClientIP: "1.2.3.4",
		Action:   engine.ActionBlock,
	}
	b.BroadcastEvent(event)

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "test-1") {
			t.Errorf("expected event ID in message, got %s", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for broadcast")
	}
}

// --- Routing endpoint ---

func TestGetRoutingEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/routing", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["upstreams"] == nil {
		t.Error("expected upstreams field")
	}
}

func TestUpdateRoutingEndpoint_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", "bad", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- SPA / Assets ---

func TestSPAHandler(t *testing.T) {
	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	d.Handler().ServeHTTP(w, req)
	// Should serve HTML (either React or legacy)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %s", ct)
	}
}

func TestDistAssetsHandler_NotFound(t *testing.T) {
	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/assets/nonexistent.js", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// --- Dashboard construction ---

func TestDashboard_Handler(t *testing.T) {
	d := newTestDashboard(t, "")
	if d.Handler() == nil {
		t.Error("expected non-nil handler")
	}
}

func TestDashboard_SSE(t *testing.T) {
	d := newTestDashboard(t, "")
	if d.SSE() == nil {
		t.Error("expected non-nil SSE broadcaster")
	}
}

func TestDashboard_SetRebuildFn(t *testing.T) {
	d := newTestDashboard(t, "")
	d.SetRebuildFn(func() error {
		return nil
	})
	if d.rebuildFn == nil {
		t.Error("expected rebuildFn to be set")
	}
}

// --- Helpers ---

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]any{"key": "value"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected application/json content type")
	}
}

func TestHandleCORS(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/v1/config", nil)
	handleCORS(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected CORS methods header")
	}
}

func TestLoginPageHTML(t *testing.T) {
	html := loginPage("")
	if !strings.Contains(html, "GuardianWAF") {
		t.Error("expected GuardianWAF in login page")
	}
	// No error div should be rendered when errMsg is empty
	if strings.Contains(html, `<div class="error">`) {
		t.Error("should not contain error div when no error")
	}

	html2 := loginPage("Something went wrong")
	if !strings.Contains(html2, "Something went wrong") {
		t.Error("expected error message in login page")
	}
	if !strings.Contains(html2, `<div class="error">`) {
		t.Error("expected error div when error present")
	}
}

func TestFormatFindings(t *testing.T) {
	findings := []engine.Finding{{
		DetectorName: "test",
		Category:     "sqli",
		Severity:     engine.SeverityHigh,
		Score:        80,
		Description:  "test finding",
		Location:     "query",
		Confidence:   0.9,
	}}
	result := formatFindings(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0]["detector"] != "test" {
		t.Errorf("expected 'test', got %v", result[0]["detector"])
	}
}
