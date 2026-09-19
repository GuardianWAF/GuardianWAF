package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// TestMetricsAdminListenerAuthGate verifies the round-13/25 /metrics
// remediation: the Prometheus exposition is served only from the dashboard
// (admin) listener behind the system admin API key. Unauthenticated requests
// must receive 401 and an authenticated scrape must receive the full
// exposition. The data-plane mux no longer registers /metrics at all (see the
// removed registerMetricsHandlerWithDeps calls in main.go).
func TestMetricsAdminListenerAuthGate(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	deps := metricsDependencies{
		Router: func() *proxy.Router { return nil }, // nil-safe metric writers
	}

	dash := dashboard.New(eng, events.NewMemoryStore(10), "dash-key")
	dash.SetAdminKey("admin-secret")
	dash.SetMetricsHandler(metricsHandlerFunc(eng, deps))

	srv := httptest.NewServer(dash.Handler())
	defer srv.Close()

	// 1. Unauthenticated scrape → 401 with the admin-key error.
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("unauthenticated GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("FAIL: unauthenticated /metrics returned %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(string(body), "admin API key required") {
		t.Fatalf("FAIL: unauthenticated /metrics body %q missing admin-key error", string(body))
	}

	// 2. Wrong key → 401.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-API-Key", "wrong-key")
	respWrong, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("wrong-key GET /metrics: %v", err)
	}
	bodyWrong, _ := io.ReadAll(io.LimitReader(respWrong.Body, 1<<20))
	respWrong.Body.Close()
	if respWrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("FAIL: wrong-key /metrics returned %d, want 401", respWrong.StatusCode)
	}
	if strings.Contains(string(bodyWrong), "guardianwaf_requests_total") {
		t.Fatalf("FAIL: wrong-key /metrics leaked exposition content")
	}

	// 3. Correct admin key → 200 with the full exposition.
	reqOK, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	reqOK.Header.Set("X-API-Key", "admin-secret")
	respOK, err := http.DefaultClient.Do(reqOK)
	if err != nil {
		t.Fatalf("authenticated GET /metrics: %v", err)
	}
	bodyOK, _ := io.ReadAll(io.LimitReader(respOK.Body, 1<<20))
	respOK.Body.Close()
	exposition := string(bodyOK)
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("FAIL: authenticated /metrics returned %d, want 200", respOK.StatusCode)
	}
	if ct := respOK.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("FAIL: authenticated /metrics content-type %q, want text/plain exposition", ct)
	}
	for _, want := range []string{
		"# HELP guardianwaf_requests_total",
		"# TYPE guardianwaf_requests_total counter",
		"guardianwaf_requests_total ",
		"guardianwaf_request_duration_seconds_bucket",
		"guardianwaf_layer_duration_seconds",
		"guardianwaf_event_store_errors_total",
		"guardianwaf_event_bus_published_total",
		"guardianwaf_alert_manager_sent_total",
		"guardianwaf_docker_discovery_enabled",
		"guardianwaf_ai_enabled",
	} {
		if !strings.Contains(exposition, want) {
			t.Fatalf("FAIL: authenticated /metrics exposition missing %q", want)
		}
	}

	// 4. Every method on /metrics is gated: POST without a key → 401 (the
	// admin gate owns the whole path — the SPA catch-all must not pick it up).
	reqPost, err := http.NewRequest(http.MethodPost, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	respPost, err := http.DefaultClient.Do(reqPost)
	if err != nil {
		t.Fatalf("POST /metrics: %v", err)
	}
	bodyPost, _ := io.ReadAll(io.LimitReader(respPost.Body, 1<<20))
	respPost.Body.Close()
	if respPost.StatusCode != http.StatusUnauthorized {
		t.Fatalf("FAIL: POST /metrics returned %d, want 401", respPost.StatusCode)
	}
	if strings.Contains(string(bodyPost), "guardianwaf_requests_total") {
		t.Fatalf("FAIL: POST /metrics leaked exposition content")
	}

	// 5. POST with the admin key → 200 with the exposition (the gate owns the
	// path for all methods; the exposition itself is method-agnostic).
	reqPostOK, err := http.NewRequest(http.MethodPost, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	reqPostOK.Header.Set("X-API-Key", "admin-secret")
	respPostOK, err := http.DefaultClient.Do(reqPostOK)
	if err != nil {
		t.Fatalf("authenticated POST /metrics: %v", err)
	}
	bodyPostOK, _ := io.ReadAll(io.LimitReader(respPostOK.Body, 1<<20))
	respPostOK.Body.Close()
	if respPostOK.StatusCode != http.StatusOK {
		t.Fatalf("FAIL: authenticated POST /metrics returned %d, want 200", respPostOK.StatusCode)
	}
	if !strings.Contains(string(bodyPostOK), "guardianwaf_requests_total") {
		t.Fatalf("FAIL: authenticated POST /metrics missing exposition content")
	}
}

// TestMetricsLegacyFallbackAdminGated pins the dispatcher's fallback branch:
// with an admin key configured but no full-exposition handler installed, the
// legacy stats-only exposition is served — still behind the admin key.
func TestMetricsLegacyFallbackAdminGated(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	dash := dashboard.New(eng, events.NewMemoryStore(10), "dash-key")
	dash.SetAdminKey("admin-secret") // no SetMetricsHandler → legacy content

	srv := httptest.NewServer(dash.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-API-Key", "admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics legacy fallback: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FAIL: legacy /metrics returned %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "guardianwaf_requests_total") {
		t.Fatalf("FAIL: legacy /metrics missing requests_total")
	}
	if strings.Contains(string(body), "guardianwaf_request_duration_seconds_bucket") {
		t.Fatalf("FAIL: legacy fallback served the full exposition (duration histogram present)")
	}
}

// TestMetricsAdminListenerFailClosedWithoutAdminKey pins the fail-closed
// property: when no admin key is configured, the metrics exposition is
// unreachable for everyone rather than falling back to unauthenticated access.
func TestMetricsAdminListenerFailClosedWithoutAdminKey(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	dash := dashboard.New(eng, events.NewMemoryStore(10), "dash-key")
	dash.SetMetricsHandler(metricsHandlerFunc(eng, metricsDependencies{}))

	srv := httptest.NewServer(dash.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics without admin key configured: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("FAIL: /metrics with no admin key configured returned %d, want 401 (fail closed)", resp.StatusCode)
	}
	if strings.Contains(string(body), "guardianwaf_") {
		t.Fatalf("FAIL: /metrics leaked exposition content with no admin key configured")
	}
}

// stubClusterMetrics is a minimal clusterMetricsSource for the exposition
// tests: fixed values that make every cluster_* series assertion exact.
type stubClusterMetrics struct{}

func (stubClusterMetrics) Role() string { return "leader" }
func (stubClusterMetrics) Peers() []dashboard.ClusterPeerInfo {
	return make([]dashboard.ClusterPeerInfo, 2)
}
func (stubClusterMetrics) StoreStats() dashboard.ClusterStoreStats {
	return dashboard.ClusterStoreStats{Bans: 3, Rules: 5, Counters: 7}
}
func (stubClusterMetrics) CurrentTerm() uint64 { return 4 }
func (stubClusterMetrics) CommitIndex() uint64 { return 42 }
func (stubClusterMetrics) LastApplied() uint64 { return 40 }
func (stubClusterMetrics) LogLength() uint64   { return 44 }

// TestMetricsClusterSeriesInExposition verifies that the admin-gated /metrics
// exposition re-emits the cluster_* series (member count, Raft leadership and
// progress, replicated store sizes) when a cluster status source is available
// — the series the legacy dashboard /metrics handler served.
func TestMetricsClusterSeriesInExposition(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	deps := metricsDependencies{
		ClusterStatus: func() clusterMetricsSource { return stubClusterMetrics{} },
	}

	dash := dashboard.New(eng, events.NewMemoryStore(10), "dash-key")
	dash.SetAdminKey("admin-secret")
	dash.SetMetricsHandler(metricsHandlerFunc(eng, deps))

	srv := httptest.NewServer(dash.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-API-Key", "admin-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("FAIL: /metrics returned %d, want 200", resp.StatusCode)
	}
	exposition := string(body)

	for _, want := range []string{
		"# HELP guardianwaf_cluster_member_count",
		"# TYPE guardianwaf_cluster_member_count gauge",
		"guardianwaf_cluster_member_count 3",
		"# HELP guardianwaf_cluster_is_leader",
		"guardianwaf_cluster_is_leader 1",
		"guardianwaf_cluster_raft_term 4",
		"guardianwaf_cluster_raft_commit_index 42",
		"guardianwaf_cluster_raft_last_applied 40",
		"guardianwaf_cluster_raft_log_length 44",
		"guardianwaf_cluster_store_bans 3",
		"guardianwaf_cluster_store_rules 5",
		"guardianwaf_cluster_store_counters 7",
	} {
		if !strings.Contains(exposition, want) {
			t.Fatalf("FAIL: cluster-mode /metrics exposition missing %q", want)
		}
	}
}
