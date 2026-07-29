package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

type metricsTestLayer struct {
	name string
}

func (l metricsTestLayer) Name() string { return l.name }
func (l metricsTestLayer) Order() int   { return 1 }
func (l metricsTestLayer) Process(*engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{Action: engine.ActionPass}
}

func TestRegisterMetricsHandler_ExportsPrometheusContract(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	eng.SetGeoIPStatus(true, 42)
	eng.Check(httptest.NewRequest(http.MethodGet, "/metrics-test", nil))

	mux := http.NewServeMux()
	registerMetricsHandler(mux, eng)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
	body := rr.Body.String()
	for _, metric := range prometheusMetricsContract {
		if !strings.Contains(body, fmt.Sprintf("# HELP %s ", metric.Name)) {
			t.Fatalf("missing HELP line for %s in:\n%s", metric.Name, body)
		}
		if !strings.Contains(body, fmt.Sprintf("# TYPE %s %s", metric.Name, metric.Type)) {
			t.Fatalf("missing TYPE line for %s in:\n%s", metric.Name, body)
		}
		if !strings.Contains(body, metric.Name+" ") {
			t.Fatalf("missing value line for %s in:\n%s", metric.Name, body)
		}
	}
	if !strings.Contains(body, "guardianwaf_geoip_ready 1\n") {
		t.Fatalf("expected GeoIP readiness gauge, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_geoip_ranges 42\n") {
		t.Fatalf("expected GeoIP range gauge, got:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE guardianwaf_request_duration_seconds histogram\n") {
		t.Fatalf("expected latency histogram type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_request_duration_seconds_bucket{le=\"0.001\"}") {
		t.Fatalf("expected latency histogram bucket, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_request_duration_seconds_bucket{le=\"+Inf\"} 1\n") {
		t.Fatalf("expected latency +Inf bucket count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_request_duration_seconds_count 1\n") {
		t.Fatalf("expected latency histogram count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_request_duration_seconds_sum ") {
		t.Fatalf("expected latency histogram sum, got:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE guardianwaf_event_store_errors_total counter\n") {
		t.Fatalf("expected event store errors counter type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_event_store_errors_total 0\n") {
		t.Fatalf("expected event store errors counter value, got:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE guardianwaf_event_store_dropped_total counter\n") {
		t.Fatalf("expected event store dropped counter type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_event_store_dropped_total 0\n") {
		t.Fatalf("expected event store dropped counter value, got:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE guardianwaf_dashboard_audit_persistence_failures_total counter\n") {
		t.Fatalf("expected dashboard audit persistence counter type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_dashboard_audit_persistence_failures_total ") {
		t.Fatalf("expected dashboard audit persistence counter value, got:\n%s", body)
	}
	for _, want := range []string{
		"# TYPE guardianwaf_event_bus_subscribers gauge\n",
		"guardianwaf_event_bus_subscribers 0\n",
		"# TYPE guardianwaf_event_bus_max_subscribers gauge\n",
		"guardianwaf_event_bus_max_subscribers 1024\n",
		"# TYPE guardianwaf_event_bus_published_total counter\n",
		"guardianwaf_event_bus_published_total 1\n",
		"# TYPE guardianwaf_event_bus_dropped_total counter\n",
		"guardianwaf_event_bus_dropped_total 0\n",
		"# TYPE guardianwaf_event_bus_rejected_subscriptions_total counter\n",
		"guardianwaf_event_bus_rejected_subscriptions_total 0\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected event bus metric %q, got:\n%s", want, body)
		}
	}
}

func TestRegisterMetricsHandler_ExportsLayerTimingHistogram(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	eng.AddLayer(engine.OrderedLayer{Layer: metricsTestLayer{name: "test\"layer"}, Order: 1})
	eng.Check(httptest.NewRequest(http.MethodGet, "/layer-timing", nil))

	mux := http.NewServeMux()
	registerMetricsHandler(mux, eng)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "# TYPE guardianwaf_layer_duration_seconds histogram\n") {
		t.Fatalf("expected layer timing histogram type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_layer_duration_seconds_bucket{layer=\"test\\\"layer\",le=\"+Inf\"} 1\n") {
		t.Fatalf("expected layer timing +Inf bucket, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_layer_duration_seconds_count{layer=\"test\\\"layer\"} 1\n") {
		t.Fatalf("expected layer timing count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_layer_duration_seconds_sum{layer=\"test\\\"layer\"} ") {
		t.Fatalf("expected layer timing sum, got:\n%s", body)
	}
}

func TestRegisterMetricsHandlerWithDeps_ExportsUpstreamMetrics(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	proxy.SetPrivateTargetsAllowed(true)
	defer proxy.SetPrivateTargetsAllowed(false)
	targetA, err := proxy.NewTarget("http://127.0.0.1:1", 1)
	if err != nil {
		t.Fatalf("NewTarget targetA error: %v", err)
	}
	targetB, err := proxy.NewTarget("http://127.0.0.1:2", 1)
	if err != nil {
		t.Fatalf("NewTarget targetB error: %v", err)
	}
	targetB.SetHealthy(false)
	router := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/api\"v1",
		Balancer:   proxy.NewBalancer([]*proxy.Target{targetA, targetB}, proxy.StrategyRoundRobin),
	}})

	mux := http.NewServeMux()
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{
		Router: func() *proxy.Router { return router },
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "# TYPE guardianwaf_upstream_targets_total gauge\n") {
		t.Fatalf("expected upstream target metric type, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_upstream_targets_total{upstream=\"/api\\\"v1\"} 2\n") {
		t.Fatalf("expected upstream target total, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_upstream_targets_healthy{upstream=\"/api\\\"v1\"} 1\n") {
		t.Fatalf("expected upstream healthy count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_upstream_active_connections{upstream=\"/api\\\"v1\"} 0\n") {
		t.Fatalf("expected active connection count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_upstream_circuit_state{upstream=\"/api\\\"v1\",state=\"closed\"} 2\n") {
		t.Fatalf("expected closed circuit state count, got:\n%s", body)
	}
	if !strings.Contains(body, "guardianwaf_upstream_circuit_state{upstream=\"/api\\\"v1\",state=\"open\"} 0\n") {
		t.Fatalf("expected open circuit state count, got:\n%s", body)
	}
}

func TestRegisterMetricsHandlerWithDeps_ExportsAlertingMetrics(t *testing.T) {
	alerting.ResetEmailStats()
	defer alerting.ResetEmailStats()

	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	alertMgr := alerting.NewManagerWithEmail(nil, []config.EmailConfig{{
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "guardian@example.com",
		To:       []string{"ops@example.com"},
	}})

	mux := http.NewServeMux()
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{
		AlertManager: func() *alerting.Manager { return alertMgr },
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE guardianwaf_alert_manager_sent_total counter\n",
		"guardianwaf_alert_manager_sent_total 0\n",
		"# TYPE guardianwaf_alert_manager_failed_total counter\n",
		"guardianwaf_alert_manager_failed_total 0\n",
		"# TYPE guardianwaf_alert_manager_dropped_total counter\n",
		"guardianwaf_alert_manager_dropped_total 0\n",
		"# TYPE guardianwaf_alert_manager_max_dispatch gauge\n",
		"guardianwaf_alert_manager_max_dispatch 32\n",
		"# TYPE guardianwaf_alert_email_sent_total counter\n",
		"guardianwaf_alert_email_sent_total 0\n",
		"# TYPE guardianwaf_alert_email_failed_total counter\n",
		"guardianwaf_alert_email_failed_total 0\n",
		"# TYPE guardianwaf_alert_targets_configured gauge\n",
		"guardianwaf_alert_targets_configured{type=\"webhook\"} 0\n",
		"guardianwaf_alert_targets_configured{type=\"email\"} 1\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected alerting metric %q, got:\n%s", want, body)
		}
	}
}

func TestRegisterMetricsHandlerWithDeps_ExportsDockerDiscoveryMetrics(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	watcher := dkr.NewWatcher(nil, "gwaf", "bridge", 0)

	mux := http.NewServeMux()
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{
		DockerEnabled: func() bool { return true },
		DockerWatcher: func() *dkr.Watcher { return watcher },
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE guardianwaf_docker_discovery_enabled gauge\n",
		"guardianwaf_docker_discovery_enabled 1\n",
		"# TYPE guardianwaf_docker_discovery_running gauge\n",
		"guardianwaf_docker_discovery_running 0\n",
		"# TYPE guardianwaf_docker_discovered_services gauge\n",
		"guardianwaf_docker_discovered_services 0\n",
		"# TYPE guardianwaf_docker_discovery_last_sync_success gauge\n",
		"guardianwaf_docker_discovery_last_sync_success 0\n",
		"# TYPE guardianwaf_docker_discovery_event_stream_connected gauge\n",
		"guardianwaf_docker_discovery_event_stream_connected 0\n",
		"# TYPE guardianwaf_docker_discovery_sync_failures_total counter\n",
		"guardianwaf_docker_discovery_sync_failures_total 0\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected Docker discovery metric %q, got:\n%s", want, body)
		}
	}
}

func TestRegisterMetricsHandlerWithDeps_ExportsAIUsageMetrics(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	aiStore := ai.NewStore(t.TempDir())
	aiStore.TrackUsage(123)
	if err := aiStore.AddResult(ai.AnalysisResult{
		TokensUsed: 123,
		CostUSD:    0.0042,
		Verdicts: []ai.Verdict{
			{Action: "block"},
			{Action: "monitor"},
		},
	}); err != nil {
		t.Fatalf("AddResult error: %v", err)
	}
	analyzer := ai.NewAnalyzer(ai.AnalyzerConfig{}, aiStore, "")

	mux := http.NewServeMux()
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{
		AIEnabled:  func() bool { return true },
		AIAnalyzer: func() *ai.Analyzer { return analyzer },
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"# TYPE guardianwaf_ai_enabled gauge\n",
		"guardianwaf_ai_enabled 1\n",
		"# TYPE guardianwaf_ai_tokens_used_total counter\n",
		"guardianwaf_ai_tokens_used_total 123\n",
		"# TYPE guardianwaf_ai_tokens_used_current gauge\n",
		"guardianwaf_ai_tokens_used_current{window=\"hour\"} 123\n",
		"guardianwaf_ai_tokens_used_current{window=\"day\"} 123\n",
		"# TYPE guardianwaf_ai_requests_total counter\n",
		"guardianwaf_ai_requests_total 1\n",
		"# TYPE guardianwaf_ai_requests_current gauge\n",
		"guardianwaf_ai_requests_current{window=\"hour\"} 1\n",
		"guardianwaf_ai_requests_current{window=\"day\"} 1\n",
		"# TYPE guardianwaf_ai_pending_events gauge\n",
		"guardianwaf_ai_pending_events 0\n",
		"# TYPE guardianwaf_ai_cost_usd_total counter\n",
		"guardianwaf_ai_cost_usd_total 0.004200\n",
		"# TYPE guardianwaf_ai_verdicts_total counter\n",
		"guardianwaf_ai_verdicts_total{action=\"block\"} 1\n",
		"guardianwaf_ai_verdicts_total{action=\"monitor\"} 1\n",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected AI usage metric %q, got:\n%s", want, body)
		}
	}
}
