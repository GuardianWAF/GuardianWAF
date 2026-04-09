package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// --- Mocks for remaining coverage gaps ---

type errorEventStore struct{ events.EventStore }

func (errorEventStore) Query(events.EventFilter) ([]engine.Event, int, error) {
	return nil, 0, fmt.Errorf("query error")
}

type errorIPACL struct{ mockIPACL }

func (m *errorIPACL) AddWhitelist(string) error  { return fmt.Errorf("add whitelist error") }
func (m *errorIPACL) AddBlacklist(string) error  { return fmt.Errorf("add blacklist error") }
func (m *errorIPACL) RemoveWhitelist(string) error {
	return fmt.Errorf("remove whitelist error")
}
func (m *errorIPACL) RemoveBlacklist(string) error {
	return fmt.Errorf("remove blacklist error")
}

// mockBanNoLister implements banLayer but NOT banLister
type mockBanNoLister struct{ mockIPACL }

func (m *mockBanNoLister) AddAutoBan(string, string, time.Duration) {}
func (m *mockBanNoLister) RemoveAutoBan(string)                     {}

func newDashboardWithErrorIPACL(t *testing.T) *Dashboard {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	mock := &errorIPACL{}
	eng.AddLayer(engine.OrderedLayer{Layer: mock, Order: 100})
	d := New(eng, store, "key")
	return d
}

func newDashboardWithBanNoLister(t *testing.T) *Dashboard {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockBanNoLister{}
	eng.AddLayer(engine.OrderedLayer{Layer: mock, Order: 100})
	d := New(eng, store, "key")
	return d
}

// --- AI handlers ---

func TestAIProviders_StandaloneCacheError(t *testing.T) {
	oldCache := catalogCache
	catalogCache = ai.NewCatalogCache("http://127.0.0.1:1/bad.json")
	defer func() { catalogCache = oldCache }()

	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/providers", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAIAnalyze_EventQueryError(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)
	d.eventStore = errorEventStore{}

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestGetEvents_QueryError(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.eventStore = errorEventStore{}

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/events", "", "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- Routing update edge cases ---

func TestUpdateRouting_TargetTypeMiss(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"upstreams":[{"name":"u","targets":["not-a-map"]}],"routes":[]}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRouting_HealthCheckPreservation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:         "backend",
			LoadBalancer: "round_robin",
			Targets:      []config.TargetConfig{{URL: "http://old:8080"}},
			HealthCheck: config.HealthCheckConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
				Timeout:  5 * time.Second,
				Path:     "/health",
			},
		},
	}
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, _ := engine.NewEngine(cfg, store, bus)
	d := New(eng, store, "k")

	body := `{"upstreams":[{"name":"backend","targets":[{"url":"http://new:8080"}]}],"routes":[]}`
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated := d.engine.Config().Upstreams[0]
	if !updated.HealthCheck.Enabled || updated.HealthCheck.Path != "/health" {
		t.Error("expected health check config to be preserved")
	}
}

func TestUpdateRouting_VirtualHostRouteTypeMiss(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"virtual_hosts":[{"domains":["example.com"],"routes":[123]}],"upstreams":[],"routes":[]}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateRouting_StripPrefix(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"upstreams":[{"name":"be","targets":[{"url":"http://localhost:8080"}]}],"routes":[{"path":"/api/","upstream":"be","strip_prefix":true}]}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	routes := d.engine.Config().Routes
	if len(routes) != 1 || !routes[0].StripPrefix {
		t.Error("expected strip_prefix to be true")
	}
}

func TestUpdateRouting_SaveFnError(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetSaveFn(func() error { return fmt.Errorf("disk full") })

	body := `{"upstreams":[{"name":"be","targets":[{"url":"http://localhost:8080"}]}],"routes":[{"path":"/","upstream":"be"}]}`
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/routing", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (graceful degradation), got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	msg, _ := result["message"].(string)
	if !strings.Contains(msg, "disk sync pending") {
		t.Errorf("expected save failure message, got %s", msg)
	}
}

// --- IP ACL error returns ---

func TestAddIPACL_WhitelistError(t *testing.T) {
	d := newDashboardWithErrorIPACL(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl", `{"list":"whitelist","ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAddIPACL_BlacklistError(t *testing.T) {
	d := newDashboardWithErrorIPACL(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ipacl", `{"list":"blacklist","ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_WhitelistError(t *testing.T) {
	d := newDashboardWithErrorIPACL(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl", `{"list":"whitelist","ip":"1.2.3.4"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestRemoveIPACL_BlacklistError(t *testing.T) {
	d := newDashboardWithErrorIPACL(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("DELETE", "/api/v1/ipacl", `{"list":"blacklist","ip":"5.6.7.8"}`, "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Bans: layer implements banLayer but not banLister ---

func TestGetBans_NonLister(t *testing.T) {
	d := newDashboardWithBanNoLister(t)
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/bans", "", "key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	bans, ok := result["bans"].([]any)
	if !ok || len(bans) != 0 {
		t.Errorf("expected empty bans, got %v", result["bans"])
	}
}

// --- applyWAFPatch detector non-map skip ---

func TestApplyWAFPatch_DetectorNonMap(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"detection":{"detectors":{"sqli":"not-a-map"}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- SPA fallbacks ---

func TestHandleSPA_DistFallback(t *testing.T) {
	oldDist := distFS
	distFS = embed.FS{}
	defer func() { distFS = oldDist }()

	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "test-api-key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 fallback to static, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %s", ct)
	}
}

func TestHandleSPA_BothMissing(t *testing.T) {
	oldDist := distFS
	oldStatic := staticFiles
	distFS = embed.FS{}
	staticFiles = embed.FS{}
	defer func() {
		distFS = oldDist
		staticFiles = oldStatic
	}()

	d := newTestDashboard(t, "")
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "test-api-key")
	d.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when both dist and static missing, got %d", w.Code)
	}
}

// --- SSE message receive loop ---

func TestHandleSSE_ReceiveMessage(t *testing.T) {
	b := NewSSEBroadcaster()
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	done := make(chan struct{})
	go func() {
		b.HandleSSE(w, req)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	b.BroadcastEvent(engine.Event{ID: "sse-test", Action: engine.ActionBlock})

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE handler did not exit")
	}

	body := w.Body.String()
	if !strings.Contains(body, "sse-test") {
		t.Errorf("expected event ID in SSE output, got: %s", body)
	}
}
