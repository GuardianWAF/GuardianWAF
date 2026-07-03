package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// --- Test helpers ---

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := config.DefaultConfig()
	allowPrivate := true
	cfg.AllowPrivateUpstreams = &allowPrivate
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
	proxy.SetPrivateTargetsAllowed(true)
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	if apiKey == "" {
		apiKey = "test-api-key"
	}
	return New(eng, store, apiKey)
}

// authenticatedRequest sends a request with X-API-Key header.
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
	token := signSession("192.0.2.1")
	if token == "" {
		t.Fatal("signSession returned empty token")
	}
	if !verifySession(token, "192.0.2.1") {
		t.Error("verifySession rejected valid token")
	}
	// Different IP should fail (session hijacking prevention)
	if verifySession(token, "10.0.0.1") {
		t.Error("verifySession accepted token from different IP")
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
			if verifySession(tt.token, "192.0.2.1") {
				t.Error("expected invalid session")
			}
		})
	}
}

func TestIsAuthenticated_NoAPIKey(t *testing.T) {
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	d := New(eng, store, "") // explicitly empty — should reject
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	if _, ok := d.isAuthenticated(req); ok {
		t.Error("should NOT be authenticated when no API key configured")
	}
}

func TestIsAuthenticated_APIKeyHeader(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "secret-key")
	if _, ok := d.isAuthenticated(req); !ok {
		t.Error("should be authenticated with correct API key header")
	}
}

func TestIsAuthenticated_APIKeyQuery(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats?api_key=secret-key", nil)
	if _, ok := d.isAuthenticated(req); ok {
		t.Error("API key in query parameter should be rejected — use X-API-Key header only")
	}
}

func TestIsAuthenticated_WrongKey(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	if _, ok := d.isAuthenticated(req); ok {
		t.Error("should not be authenticated with wrong key")
	}
}

func TestIsAuthenticated_SessionCookie(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	token := signSession("192.0.2.1")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if _, ok := d.isAuthenticated(req); !ok {
		t.Error("should be authenticated with valid session cookie")
	}
}

func TestIsAuthenticated_NoCreds(t *testing.T) {
	d := newTestDashboard(t, "secret-key")
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	if _, ok := d.isAuthenticated(req); ok {
		t.Error("should not be authenticated without credentials")
	}
}

func TestHandleSPA_MCPPathReturnsJSONNotSPA(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "k")

	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for disabled MCP fallback, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected JSON response, got content-type %q body %q", got, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["error"] != "not found" {
		t.Fatalf("expected not found error, got %#v", body)
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

func TestEventsEndpoint_ReturnsRedactedEventEvidence(t *testing.T) {
	d := newTestDashboard(t, "mykey")
	rawReq := httptest.NewRequest("GET", "/login?api_key=query-secret", nil)
	rawReq.Header.Set("Referer", "https://app.example/account?password=referer-secret")
	rawReq.Header.Set("User-Agent", "guardianwaf-test")
	ctx := engine.AcquireContext(rawReq, 2, 1024)
	defer engine.ReleaseContext(ctx)
	ctx.Accumulator.Add(&engine.Finding{
		DetectorName: "secret-detector",
		Category:     "leak-test",
		Severity:     engine.SeverityHigh,
		Score:        90,
		Description:  "secret evidence redaction regression",
		MatchedValue: "Authorization: Bearer eyJheader.eyJpayload.signature Cookie: session_id=abc123 client_secret=body-secret safe=value",
		Location:     "header",
		Confidence:   1,
	})

	evt := engine.NewEvent(ctx, http.StatusForbidden)
	if err := d.eventStore.Store(evt); err != nil {
		t.Fatalf("store event: %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/api/v1/events?limit=10&offset=0"},
		{name: "detail", path: "/api/v1/events/" + evt.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest("GET", tc.path, "", "mykey")
			d.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			for _, secret := range []string{
				"query-secret",
				"referer-secret",
				"eyJheader.eyJpayload.signature",
				"abc123",
				"body-secret",
			} {
				if strings.Contains(body, secret) {
					t.Fatalf("response leaked secret %q: %s", secret, body)
				}
			}
			if !strings.Contains(body, "[REDACTED]") {
				t.Fatalf("expected redaction marker in response: %s", body)
			}
			if !strings.Contains(body, "safe=value") {
				t.Fatalf("expected non-sensitive evidence to remain visible: %s", body)
			}
		})
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

func TestEventsEndpoint_QueryAliasesFilterEvents(t *testing.T) {
	d := newTestDashboard(t, "mykey")
	base := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Second)
	stored := []engine.Event{
		{
			ID:        "evt-block",
			Timestamp: base.Add(2 * time.Minute),
			ClientIP:  "203.0.113.10",
			Path:      "/blocked",
			Action:    engine.ActionBlock,
			Score:     90,
			Findings:  []engine.Finding{{DetectorName: "rule:e2e-rule"}},
		},
		{
			ID:        "evt-pass",
			Timestamp: base.Add(3 * time.Minute),
			ClientIP:  "203.0.113.11",
			Path:      "/allowed",
			Action:    engine.ActionPass,
			Score:     0,
		},
	}
	for _, evt := range stored {
		if err := d.eventStore.Store(evt); err != nil {
			t.Fatalf("store event: %v", err)
		}
	}

	path := "/api/v1/events?action=block&ip=203.0.113.10&rule_id=e2e-rule&start=" +
		strconv.FormatInt(base.UnixMilli(), 10) +
		"&end=" + strconv.FormatInt(base.Add(5*time.Minute).UnixMilli(), 10)
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", path, "", "mykey")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	evts, ok := body["events"].([]any)
	if !ok {
		t.Fatalf("expected events array, got %#v", body["events"])
	}
	if len(evts) != 1 {
		t.Fatalf("expected one matching event, got %d: %#v", len(evts), evts)
	}
	evt, ok := evts[0].(map[string]any)
	if !ok || evt["id"] != "evt-block" {
		t.Fatalf("expected evt-block, got %#v", evts[0])
	}

	exportW := httptest.NewRecorder()
	exportReq := authenticatedRequest("GET", "/api/v1/events/export?format=json&action=block&ip=203.0.113.10&rule_id=e2e-rule&start="+
		strconv.FormatInt(base.UnixMilli(), 10)+
		"&end="+strconv.FormatInt(base.Add(5*time.Minute).UnixMilli(), 10), "", "mykey")
	d.Handler().ServeHTTP(exportW, exportReq)
	if exportW.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d body %s", exportW.Code, exportW.Body.String())
	}
	exportBody := decodeJSON(t, exportW)
	if exportBody["count"].(float64) != 1 {
		t.Fatalf("expected one exported event, got %#v", exportBody)
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
	body := `{"mode":"proxy","waf":{"detection":{"threshold":{"block":60,"log":30}},"sanitizer":{"max_body_size":2048}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestUpdateConfigEndpoint_RejectsLayerTopologyChange(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"rate_limit":{"enabled":false}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d, body: %s", w.Code, w.Body.String())
	}
	if !d.engine.Config().WAF.RateLimit.Enabled {
		t.Fatal("topology-changing config should not be applied")
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

func TestReloadConfigEndpoint(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/config/reload", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %#v", body["status"])
	}
}

func TestAnalyticsEndpoints(t *testing.T) {
	d := newTestDashboard(t, "k")
	now := time.Now()
	for _, evt := range []engine.Event{
		{ID: "evt-1", Timestamp: now, ClientIP: "192.0.2.10", Path: "/login", Action: engine.ActionBlock, Score: 90},
		{ID: "evt-2", Timestamp: now, ClientIP: "192.0.2.11", Path: "/api", Action: engine.ActionPass, Score: 0},
	} {
		if err := d.eventStore.Store(evt); err != nil {
			t.Fatalf("store event: %v", err)
		}
	}

	tests := []struct {
		path string
		keys []string
	}{
		{"/api/v1/analytics/traffic?period=1h", []string{"requests", "total", "actions"}},
		{"/api/v1/analytics/attacks?period=1h", []string{"blocks", "attacks", "top_rules"}},
		{"/api/v1/analytics/top?limit=5", []string{"top_ips", "top_paths", "top_rules", "targets"}},
		{"/api/v1/analytics/dashboard?period=1h", []string{"traffic", "attacks", "top", "metrics"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest("GET", tt.path, "", "k")
			d.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d body %s", w.Code, w.Body.String())
			}
			body := decodeJSON(t, w)
			for _, key := range tt.keys {
				if _, ok := body[key]; !ok {
					t.Fatalf("expected key %q in %#v", key, body)
				}
			}
		})
	}
}

func TestAlertCompatibilityEndpoints(t *testing.T) {
	d := newTestDashboard(t, "k")

	tests := []struct {
		method string
		path   string
		body   string
		code   int
		key    string
	}{
		{"GET", "/api/v1/alerts", "", http.StatusOK, "alerts"},
		{"GET", "/api/v1/alerts/history", "", http.StatusOK, "history"},
		{"POST", "/api/v1/alerts", `{"name":"x"}`, http.StatusBadRequest, "error"},
		{"PUT", "/api/v1/alerts/missing", `{}`, http.StatusNotFound, "error"},
		{"DELETE", "/api/v1/alerts/missing", "", http.StatusNotFound, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest(tt.method, tt.path, tt.body, "k")
			d.Handler().ServeHTTP(w, req)
			if w.Code != tt.code {
				t.Fatalf("expected %d, got %d body %s", tt.code, w.Code, w.Body.String())
			}
			body := decodeJSON(t, w)
			if _, ok := body[tt.key]; !ok {
				t.Fatalf("expected key %q in %#v", tt.key, body)
			}
		})
	}
}

func TestTenantCompatibilityEndpointsDisabled(t *testing.T) {
	d := newTestDashboard(t, "k")
	// Cross-tenant provisioning routes are admin-gated; supply an admin key so
	// requests reach the "tenant manager disabled" handler instead of 401.
	d.SetAdminKey("admin-key")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/tenants", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected tenant list 200, got %d body %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["enabled"] != false {
		t.Fatalf("expected disabled tenant list, got %#v", body)
	}

	for _, tt := range []struct {
		method string
		path   string
		body   string
		apiKey string
	}{
		{"POST", "/api/v1/tenants", `{"name":"t","domain":"example.com"}`, "admin-key"},
		{"GET", "/api/v1/tenants/t/config", "", "k"},
		{"PUT", "/api/v1/tenants/t/config", `{"block_threshold":60}`, "admin-key"},
		{"GET", "/api/v1/tenants/t/stats", "", "k"},
		{"DELETE", "/api/v1/tenants/t", "", "admin-key"},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest(tt.method, tt.path, tt.body, tt.apiKey)
			d.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d body %s", w.Code, w.Body.String())
			}
			body := decodeJSON(t, w)
			if body["enabled"] != false {
				t.Fatalf("expected disabled response, got %#v", body)
			}
		})
	}
}

func TestTenantCompatMutatingRoutesRequireAdminKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetAdminKey("admin-key")

	// The ordinary dashboard key must not be able to provision tenants via the
	// compat routes — that would bypass the admin/dashboard key separation.
	for _, tt := range []struct{ method, path, body string }{
		{"POST", "/api/v1/tenants", `{"name":"t","domain":"example.com"}`},
		{"PUT", "/api/v1/tenants/t", `{"name":"t2"}`},
		{"DELETE", "/api/v1/tenants/t", ""},
		{"PUT", "/api/v1/tenants/t/config", `{"block_threshold":60}`},
		{"POST", "/api/v1/tenants/t/apikey", ""},
	} {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest(tt.method, tt.path, tt.body, "k")
			d.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for dashboard-key provisioning, got %d body %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestConfigSubresourceEndpoints(t *testing.T) {
	d := newTestDashboard(t, "k")

	tests := []struct {
		method string
		path   string
		body   string
		code   int
		key    string
	}{
		{"GET", "/api/v1/config/ratelimit", "", http.StatusOK, "enabled"},
		{"PUT", "/api/v1/config/ratelimit", `{"enabled":true,"default_limit":100,"window":"1m"}`, http.StatusConflict, "error"},
		{"GET", "/api/v1/config/bot", "", http.StatusOK, "enabled"},
		{"PUT", "/api/v1/config/bot", `{"enabled":true,"mode":"monitor"}`, http.StatusOK, "status"},
		{"POST", "/api/v1/ssl/certificates", `{"name":"bad","cert":"%%%","key":"%%%"} `, http.StatusBadRequest, "error"},
		{"DELETE", "/api/v1/ssl/certificates/missing", "", http.StatusNotFound, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := authenticatedRequest(tt.method, tt.path, tt.body, "k")
			d.Handler().ServeHTTP(w, req)
			if w.Code != tt.code {
				t.Fatalf("expected %d, got %d body %s", tt.code, w.Code, w.Body.String())
			}
			body := decodeJSON(t, w)
			if _, ok := body[tt.key]; !ok {
				t.Fatalf("expected key %q in %#v", tt.key, body)
			}
		})
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

func TestRulesEndpoint_FiltersRules(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(
		func() any {
			return []map[string]any{
				{
					"id":         "r-sqli-block",
					"name":       "SQLi block",
					"enabled":    true,
					"action":     "block",
					"conditions": []map[string]any{{"field": "query", "op": "contains", "value": "union"}},
				},
				{
					"id":         "r-access-log",
					"name":       "Access log",
					"enabled":    false,
					"action":     "log",
					"conditions": []map[string]any{{"field": "path", "op": "starts_with", "value": "/status"}},
				},
			}
		},
		func(m map[string]any) error { return nil },
		func(id string, m map[string]any) error { return nil },
		func(id string) bool { return true },
		func(id string, enabled bool) bool { return true },
		nil,
	)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/rules?action=block&type=sqli&enabled=true", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	rules, ok := result["rules"].([]any)
	if !ok {
		t.Fatalf("expected rules array, got %#v", result["rules"])
	}
	if len(rules) != 1 {
		t.Fatalf("expected one filtered rule, got %d: %#v", len(rules), rules)
	}
	rule, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatalf("expected rule object, got %#v", rules[0])
	}
	if rule["id"] != "r-sqli-block" {
		t.Fatalf("expected r-sqli-block, got %#v", rule["id"])
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

func TestPatchRuleEndpoint_TogglesRule(t *testing.T) {
	d := newTestDashboard(t, "k")
	var toggledID string
	var toggledEnabled bool
	d.SetRulesFns(
		func() any { return nil },
		func(m map[string]any) error { return nil },
		func(id string, m map[string]any) error { return nil },
		func(id string) bool { return true },
		func(id string, enabled bool) bool {
			toggledID = id
			toggledEnabled = enabled
			return id == "r1"
		},
		nil,
	)
	w := httptest.NewRecorder()
	req := authenticatedRequest("PATCH", "/api/v1/rules/r1", `{"enabled":false}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if toggledID != "r1" || toggledEnabled {
		t.Fatalf("unexpected toggle call: id=%q enabled=%v", toggledID, toggledEnabled)
	}
}

func TestPatchRuleEndpoint_RequiresEnabled(t *testing.T) {
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
	req := authenticatedRequest("PATCH", "/api/v1/rules/r1", `{"name":"updated"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
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

func TestGeoIPLookupPost_NoIP(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/geoip/lookup", `{"ip":""}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGeoIPLookupPost_WithIP(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(nil, nil, nil, nil, nil, func(ip string) (string, string) {
		return "US", "United States"
	})
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/geoip/lookup", `{"ip":"8.8.8.8"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	result := decodeJSON(t, w)
	if result["country"] != "US" {
		t.Errorf("expected US, got %v", result["country"])
	}
	if result["ip"] != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %v", result["ip"])
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
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected CORS methods header")
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
	// Auth is always required — non-authenticated requests to non-API paths redirect to /login
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	d := New(eng, store, "") // explicitly empty
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	d.Handler().ServeHTTP(w, req)
	// Should redirect to /login since auth is required
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect to login, got %d", w.Code)
	}
}

func TestLoginSubmit_NoAuth(t *testing.T) {
	// Auth is always required — POST to /login without X-API-Key goes through authWrap
	eng := newTestEngine(t)
	store := events.NewMemoryStore(100)
	d := New(eng, store, "") // explicitly empty
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=whatever"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:9443"
	req.Header.Set("Origin", "https://localhost:9443")
	d.Handler().ServeHTTP(w, req)
	// authWrap redirects to /login when isAuthenticated returns false
	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect when auth fails, got %d", w.Code)
	}
}

func TestLoginPage_AlreadyAuthenticated(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("192.0.2.1")})
	req.RemoteAddr = "192.0.2.1:1234"
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect when already authenticated, got %d", w.Code)
	}
}

func TestAuthWrapRateLimitsAPIKeysButNotBrowserSessions(t *testing.T) {
	d := newTestDashboard(t, "secret")
	d.apiBuckets.Store("192.0.2.1", &apiBucket{
		tokens:     0,
		maxTokens:  0,
		refillRate: 0,
		lastRefill: time.Now(),
	})
	handler := d.authWrap(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	apiReq := httptest.NewRequest("GET", "/api/v1/smoke", nil)
	apiReq.RemoteAddr = "192.0.2.1:1234"
	apiReq.Header.Set("X-API-Key", "secret")
	apiResp := httptest.NewRecorder()
	handler(apiResp, apiReq)
	if apiResp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected API key request to be rate limited, got %d", apiResp.Code)
	}

	sessionReq := httptest.NewRequest("GET", "/api/v1/smoke", nil)
	sessionReq.RemoteAddr = "192.0.2.1:1234"
	sessionReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signSession("192.0.2.1")})
	sessionResp := httptest.NewRecorder()
	handler(sessionResp, sessionReq)
	if sessionResp.Code != http.StatusOK {
		t.Fatalf("expected session request to bypass API key bucket, got %d", sessionResp.Code)
	}
}

func TestLoginSubmit_Success(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:9443"
	req.Header.Set("Origin", "https://localhost:9443")
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

func TestLoginSubmit_SessionCookieSecureFlag(t *testing.T) {
	tests := []struct {
		name       string
		scheme     string
		forwarded  string
		remoteAddr string
		trusted    []string
		wantSecure bool
	}{
		{name: "plain http", scheme: "http", wantSecure: false},
		{name: "direct https", scheme: "https", wantSecure: true},
		{name: "untrusted forwarded https", scheme: "http", forwarded: "https", remoteAddr: "203.0.113.10:1234", wantSecure: false},
		{name: "trusted forwarded https", scheme: "http", forwarded: "https", remoteAddr: "10.0.0.10:1234", trusted: []string{"10.0.0.0/24"}, wantSecure: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newTestDashboard(t, "secret")
			d.SetTrustedProxies(tt.trusted)
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", tt.scheme+"://localhost:9443/login", strings.NewReader("key=secret"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tt.scheme+"://localhost:9443")
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}

			d.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusFound {
				t.Fatalf("expected redirect after login, got %d", w.Code)
			}

			var sessionCookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == sessionCookieName {
					sessionCookie = c
					break
				}
			}
			if sessionCookie == nil {
				t.Fatal("expected session cookie after login")
			}
			if sessionCookie.Secure != tt.wantSecure {
				t.Fatalf("expected Secure=%v, got %v", tt.wantSecure, sessionCookie.Secure)
			}
			if !sessionCookie.HttpOnly {
				t.Fatal("expected session cookie to be HttpOnly")
			}
			if sessionCookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("expected SameSite=Strict, got %v", sessionCookie.SameSite)
			}
			if sessionCookie.Path != "/" {
				t.Fatalf("expected Path=/, got %q", sessionCookie.Path)
			}
		})
	}
}

func TestLoginSubmit_WrongKey(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/login", strings.NewReader("key=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:9443"
	req.Header.Set("Origin", "https://localhost:9443")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid API key") {
		t.Error("expected error message in response")
	}
}

func TestLoginSubmitRejectsOversizedBody(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://localhost:9443/login", strings.NewReader("key=secret&padding="+strings.Repeat("x", maxLoginRequestBody)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://localhost:9443")
	req.RemoteAddr = "192.0.2.10:12345"

	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	if _, ok := d.loginBuckets.Load("192.0.2.10"); ok {
		t.Fatal("oversized login body should not be counted as an authentication failure")
	}
}

func TestLogout(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://localhost:9443/logout", nil)
	req.Header.Set("Origin", "https://localhost:9443")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Errorf("expected redirect, got %d", w.Code)
	}
	// Check cookie was cleared
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name != sessionCookieName {
			continue
		}
		found = true
		if c.MaxAge != -1 {
			t.Error("expected cookie to be cleared")
		}
		if !c.HttpOnly {
			t.Fatal("expected logout cookie to be HttpOnly")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Fatalf("expected logout cookie SameSite=Strict, got %v", c.SameSite)
		}
	}
	if !found {
		t.Fatal("expected logout to set session clearing cookie")
	}
}

func TestLogoutRejectsGET(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/logout", nil)
	d.handleLogout(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET logout, got %d", w.Code)
	}
}

func TestLogoutRequiresSameOrigin(t *testing.T) {
	d := newTestDashboard(t, "secret")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "https://localhost:9443/logout", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for POST logout without Origin/Referer, got %d", w.Code)
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

func TestEventsStreamAlias(t *testing.T) {
	d := newTestDashboard(t, "k")
	server := httptest.NewServer(d.Handler())
	defer server.Close()

	client := &http.Client{Timeout: 250 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-API-Key", "k")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("events stream request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream content type, got %q", ct)
	}
}

func TestDashboard_SetRebuildFn(t *testing.T) {
	d := newTestDashboard(t, "")
	called := false
	d.SetRebuildFn(func() error {
		called = true
		return nil
	})
	// Verify the setter doesn't panic (routingCtrl is set internally)
	_ = called
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
