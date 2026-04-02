package dashboard

import (
	"context"
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

// --- Mock IPACL layer for testing ---

type mockIPACL struct {
	whitelist []string
	blacklist []string
}

func (m *mockIPACL) Name() string { return "ipacl" }
func (m *mockIPACL) Process(_ *engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{Action: engine.ActionPass}
}
func (m *mockIPACL) AddWhitelist(cidr string) error {
	m.whitelist = append(m.whitelist, cidr)
	return nil
}
func (m *mockIPACL) RemoveWhitelist(cidr string) error {
	for i, c := range m.whitelist {
		if c == cidr {
			m.whitelist = append(m.whitelist[:i], m.whitelist[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}
func (m *mockIPACL) AddBlacklist(cidr string) error {
	m.blacklist = append(m.blacklist, cidr)
	return nil
}
func (m *mockIPACL) RemoveBlacklist(cidr string) error {
	for i, c := range m.blacklist {
		if c == cidr {
			m.blacklist = append(m.blacklist[:i], m.blacklist[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}
func (m *mockIPACL) WhitelistEntries() []string { return m.whitelist }
func (m *mockIPACL) BlacklistEntries() []string { return m.blacklist }

// mockBanLayer adds ban support
type mockBanIPACL struct {
	mockIPACL
	bans map[string]time.Time
}

func (m *mockBanIPACL) AddAutoBan(ip string, reason string, ttl time.Duration) {
	m.bans[ip] = time.Now().Add(ttl)
}
func (m *mockBanIPACL) RemoveAutoBan(ip string) {
	delete(m.bans, ip)
}
func (m *mockBanIPACL) ActiveBansAny() any {
	result := make([]map[string]any, 0, len(m.bans))
	for ip, exp := range m.bans {
		result = append(result, map[string]any{"ip": ip, "expires_at": exp})
	}
	return result
}

// newDashboardWithMock creates a dashboard with a mock IPACL layer.
func newDashboardWithMock(t *testing.T) (*Dashboard, *mockBanIPACL) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockBanIPACL{
		bans: make(map[string]time.Time),
	}
	eng.AddLayer(engine.OrderedLayer{Layer: mock, Order: 100})

	d := New(eng, store, "key")
	return d, mock
}

// --- IP ACL with active layer ---

func TestAddIPACL_Whitelist(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl",
		`{"list":"whitelist","ip":"10.0.0.0/8"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAddIPACL_Blacklist(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl",
		`{"list":"blacklist","ip":"192.168.0.0/16"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddIPACL_InvalidList(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl",
		`{"list":"invalid","ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAddIPACL_EmptyIP(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl",
		`{"list":"whitelist","ip":""}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_Whitelist(t *testing.T) {
	d, mock := newDashboardWithMock(t)
	mock.whitelist = []string{"10.0.0.0/8"}

	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl",
		`{"list":"whitelist","ip":"10.0.0.0/8"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRemoveIPACL_InvalidList(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl",
		`{"list":"invalid","ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_EmptyIP(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl",
		`{"list":"whitelist","ip":""}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_InvalidJSON(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl", "bad", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetIPACL_WithLayer(t *testing.T) {
	d, mock := newDashboardWithMock(t)
	mock.whitelist = []string{"10.0.0.0/8"}
	mock.blacklist = []string{"192.168.1.0/24"}

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ipacl", "", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	wl := result["whitelist"].([]any)
	if len(wl) != 1 {
		t.Errorf("expected 1 whitelist entry, got %d", len(wl))
	}
}

// --- Bans with active layer ---

func TestGetBans_WithLayer(t *testing.T) {
	d, mock := newDashboardWithMock(t)
	mock.bans["1.2.3.4"] = time.Now().Add(time.Hour)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/bans", "", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddBan_WithLayer(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans",
		`{"ip":"1.2.3.4","reason":"testing","duration":"30m"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAddBan_EmptyIP(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans",
		`{"ip":"","duration":"30m"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAddBan_InvalidDuration(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans",
		`{"ip":"1.2.3.4","duration":"invalid"}`, "key")
	d.Handler().ServeHTTP(w, req)
	// Should default to 1 hour and succeed
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddBan_NoReason(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans",
		`{"ip":"5.5.5.5","duration":"1h"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRemoveBan_WithLayer(t *testing.T) {
	d, mock := newDashboardWithMock(t)
	mock.bans["1.2.3.4"] = time.Now().Add(time.Hour)

	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/bans",
		`{"ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRemoveBan_EmptyIP(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/bans",
		`{"ip":""}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Rules with functions ---

func TestAddRule_Success(t *testing.T) {
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
	req := authenticatedRequest("POST", "/api/v1/rules",
		`{"id":"r1","name":"test","action":"block"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddRule_Error(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(
		func() any { return nil },
		func(m map[string]any) error { return fmt.Errorf("invalid rule") },
		func(id string, m map[string]any) error { return nil },
		func(id string) bool { return true },
		func(id string, enabled bool) bool { return true },
		nil,
	)

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/rules",
		`{"id":"r1"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateRule_Success(t *testing.T) {
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
	req := authenticatedRequest("PUT", "/api/v1/rules/r1",
		`{"name":"updated"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestUpdateRule_Error(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(
		func() any { return nil },
		func(m map[string]any) error { return nil },
		func(id string, m map[string]any) error { return fmt.Errorf("not found") },
		func(id string) bool { return true },
		func(id string, enabled bool) bool { return true },
		nil,
	)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/rules/r1",
		`{"name":"updated"}`, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateRule_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(nil, nil, func(id string, m map[string]any) error { return nil }, nil, nil, nil)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/rules/r1", "bad", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteRule_NotFound(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(nil, nil, nil,
		func(id string) bool { return false }, nil, nil)

	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/rules/nonexistent", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDeleteRule_Success(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRulesFns(nil, nil, nil,
		func(id string) bool { return true }, nil, nil)

	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/rules/r1", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- UpdateRouting ---

func TestUpdateRouting_ValidUpstreams(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{
		"upstreams": [
			{
				"name": "backend",
				"load_balancer": "round_robin",
				"targets": [{"url": "http://localhost:8088", "weight": 1}]
			}
		],
		"routes": [{"path": "/", "upstream": "backend"}]
	}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRouting_WithVirtualHosts(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{
		"upstreams": [
			{
				"name": "web",
				"load_balancer": "round_robin",
				"targets": [{"url": "http://localhost:3000", "weight": 1}]
			}
		],
		"virtual_hosts": [
			{
				"domains": ["example.com", "www.example.com"],
				"tls": {"cert_file": "", "key_file": ""},
				"routes": [{"path": "/", "upstream": "web", "strip_prefix": false}]
			}
		],
		"routes": [{"path": "/", "upstream": "web"}]
	}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRouting_InvalidUpstream(t *testing.T) {
	d := newTestDashboard(t, "k")
	// Route references non-existent upstream
	body := `{
		"upstreams": [{"name": "backend", "targets": [{"url": "http://localhost:8088"}]}],
		"routes": [{"path": "/", "upstream": "nonexistent"}]
	}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid upstream ref, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRouting_WithRebuildFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	rebuilt := false
	d.SetRebuildFn(func() error {
		rebuilt = true
		return nil
	})

	body := `{
		"upstreams": [
			{"name": "be", "targets": [{"url": "http://localhost:9000", "weight": 1}]}
		],
		"routes": [{"path": "/", "upstream": "be"}]
	}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !rebuilt {
		t.Error("expected rebuild function to be called")
	}
}

func TestUpdateRouting_RebuildFnError(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetRebuildFn(func() error {
		return fmt.Errorf("rebuild failed")
	})

	body := `{
		"upstreams": [
			{"name": "be", "targets": [{"url": "http://localhost:9000", "weight": 1}]}
		],
		"routes": [{"path": "/", "upstream": "be"}]
	}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- GetRouting with data ---

func TestGetRouting_WithUpstreamsAndVHosts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:         "backend",
			LoadBalancer: "round_robin",
			Targets:      []config.TargetConfig{{URL: "http://localhost:8088", Weight: 1}},
		},
	}
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"example.com"},
			Routes:  []config.RouteConfig{{Path: "/", Upstream: "backend"}},
		},
	}
	cfg.Routes = []config.RouteConfig{{Path: "/", Upstream: "backend"}}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/routing", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)

	upstreams := result["upstreams"].([]any)
	if len(upstreams) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(upstreams))
	}
	vhosts := result["virtual_hosts"].([]any)
	if len(vhosts) != 1 {
		t.Errorf("expected 1 vhost, got %d", len(vhosts))
	}
}

// --- Logs with filter ---

func TestLogs_LevelFilter(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?level=error&limit=10", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLogs_LargeLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?limit=5000", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- Dist Assets content types ---

func TestDistAssets_ContentTypes(t *testing.T) {
	d := newTestDashboard(t, "")
	paths := []struct {
		path string
		code int
	}{
		{"/assets/test.js", 404},
		{"/assets/test.css", 404},
		{"/assets/test.svg", 404},
		{"/assets/test.png", 404},
		{"/assets/test.woff2", 404},
	}

	for _, tt := range paths {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", tt.path, nil)
		d.Handler().ServeHTTP(w, req)
		// All should be 404 since assets don't exist in test,
		// but this exercises the content type detection code paths
		if w.Code != tt.code {
			t.Errorf("path %s: expected %d, got %d", tt.path, tt.code, w.Code)
		}
	}
}

// --- SPA routes ---

func TestSPARoutes(t *testing.T) {
	d := newTestDashboard(t, "")
	routes := []string{"/", "/config", "/routing", "/logs", "/rules"}
	for _, route := range routes {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", route, nil)
		d.Handler().ServeHTTP(w, req)
		ct := w.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("route %s: expected text/html, got %s", route, ct)
		}
	}
}

// --- Events with store data ---

func TestGetEvent_Found(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	// Store an event
	evt := engine.Event{
		ID:       "evt-123",
		ClientIP: "1.2.3.4",
		Method:   "GET",
		Path:     "/test",
		Action:   engine.ActionBlock,
		Score:    80,
	}
	_ = store.Store(evt)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events/evt-123", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- UpdateConfig with detection detectors ---

func TestUpdateConfig_Detectors(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"detection":{"enabled":true,"threshold":{"block":50,"log":25},"detectors":{"sqli":{"enabled":true,"multiplier":1.5}}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- CORS for routing ---

func TestCORS_Routing(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/v1/routing", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestCORS_IPACL(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/v1/ipacl", nil)
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

// --- SSE Handler Tests ---

// mockFlusher implements http.ResponseWriter and http.Flusher for SSE testing
type mockFlusher struct {
	httptest.ResponseRecorder
	flushed bool
}

func (m *mockFlusher) Flush() {
	m.flushed = true
}

func TestHandleSSE_Success(t *testing.T) {
	d := newTestDashboard(t, "")

	// Use SSE broadcaster directly to test the HandleSSE method
	w := &mockFlusher{ResponseRecorder: *httptest.NewRecorder()}
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	// Start SSE handler in goroutine
	done := make(chan struct{})
	go func() {
		d.SSE().HandleSSE(w, req)
		close(done)
	}()

	// Wait a bit for connection to establish
	time.Sleep(50 * time.Millisecond)

	// Cancel context to end the SSE stream
	cancel()

	// Wait for handler to finish
	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit")
	}

	// Check that we got SSE headers
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", w.Header().Get("Content-Type"))
	}
}

func TestSSEBroadcaster_Broadcast(t *testing.T) {
	b := NewSSEBroadcaster()

	// Add a client
	ch := make(chan string, 64)
	b.addClient(ch)

	if b.ClientCount() != 1 {
		t.Errorf("expected 1 client, got %d", b.ClientCount())
	}

	// Broadcast an event
	evt := engine.Event{
		ID:       "test-123",
		ClientIP: "1.2.3.4",
		Method:   "GET",
		Path:     "/test",
		Action:   engine.ActionBlock,
		Score:    50,
	}
	b.BroadcastEvent(evt)

	// Receive the event
	select {
	case msg := <-ch:
		if !strings.Contains(msg, "test-123") {
			t.Errorf("expected event ID in message, got: %s", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive broadcast event")
	}

	// Remove client
	b.removeClient(ch)

	if b.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", b.ClientCount())
	}
}

func TestSSEBroadcaster_BroadcastNoClients(t *testing.T) {
	b := NewSSEBroadcaster()

	// Broadcast with no clients (should not panic)
	evt := engine.Event{ID: "test"}
	b.BroadcastEvent(evt)
}

func TestSSEBroadcaster_FullChannel(t *testing.T) {
	b := NewSSEBroadcaster()

	// Create a channel with small buffer
	ch := make(chan string, 1)
	b.addClient(ch)

	// Fill the channel
	ch <- "first"

	// Broadcast should not block (default case)
	evt := engine.Event{ID: "test"}
	done := make(chan struct{})
	go func() {
		b.BroadcastEvent(evt)
		close(done)
	}()

	select {
	case <-done:
		// Good - didn't block
	case <-time.After(time.Second):
		t.Fatal("BroadcastEvent blocked on full channel")
	}

	b.removeClient(ch)
}

// --- GetEvent Not Found ---

func TestGetEvent_NotFound(t *testing.T) {
	d := newTestDashboard(t, "k")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events/nonexistent", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestGetEvent_EmptyID(t *testing.T) {
	d := newTestDashboard(t, "k")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events/", "", "k")
	d.Handler().ServeHTTP(w, req)
	// Will be handled by router (404 for missing route)
}

// --- Logs with various filters ---

func TestLogs_WithMatchingLevel(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	// Add some log entries
	eng.Logs.Add("info", "info msg")
	eng.Logs.Add("error", "error msg")
	eng.Logs.Add("error", "another error")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?level=error", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	logs := result["logs"].([]any)
	if len(logs) != 2 {
		t.Errorf("expected 2 error logs, got %d", len(logs))
	}
}

func TestLogs_InvalidLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?limit=invalid", "", "k")
	d.Handler().ServeHTTP(w, req)
	// Should use default limit
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestLogs_ZeroLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/logs?limit=0", "", "k")
	d.Handler().ServeHTTP(w, req)
	// Should use default limit
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- GetEvents with filters ---

func TestGetEvents_WithIPFilter(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	// Store events with different IPs
	_ = store.Store(engine.Event{ID: "1", ClientIP: "1.2.3.4", Action: engine.ActionBlock})
	_ = store.Store(engine.Event{ID: "2", ClientIP: "5.6.7.8", Action: engine.ActionPass})

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events?ip=1.2.3.4", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetEvents_WithActionFilter(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	_ = store.Store(engine.Event{ID: "1", Action: engine.ActionBlock})
	_ = store.Store(engine.Event{ID: "2", Action: engine.ActionPass})

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events?action=block", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- IP ACL error cases ---

func TestAddIPACL_InvalidCIDR(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl",
		`{"list":"whitelist","ip":"invalid-cidr"}`, "key")
	d.Handler().ServeHTTP(w, req)
	// Should still succeed with mock
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddIPACL_InvalidJSON(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl", "bad json", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Ban error cases ---

func TestAddBan_InvalidJSON(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans", "bad", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveBan_InvalidJSON(t *testing.T) {
	d, _ := newDashboardWithMock(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/bans", "bad", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetBans_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/bans", "", "k")
	d.Handler().ServeHTTP(w, req)
	// Should return empty list when no layer
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAddBan_NoLayer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/bans",
		`{"ip":"1.2.3.4","duration":"1h"}`, "k")
	d.Handler().ServeHTTP(w, req)
	// Should fail when no layer
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Config update edge cases ---

func TestUpdateConfig_EmptyBody(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateConfig_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", "bad", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Routing update edge cases ---

func TestUpdateRouting_EmptyBody(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUpdateRouting_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", "bad", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- getBanLayer edge case ---

func TestGetBanLayer_WrongType(t *testing.T) {
	// Create engine with a layer that isn't a BanIPACL
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)

	// Add a regular mock IPACL without Ban support
	mock := &mockIPACL{}
	eng.AddLayer(engine.OrderedLayer{Layer: mock, Order: 100})

	d := New(eng, store, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/bans", "", "k")
	d.Handler().ServeHTTP(w, req)

	// Should return empty since layer doesn't support bans
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
