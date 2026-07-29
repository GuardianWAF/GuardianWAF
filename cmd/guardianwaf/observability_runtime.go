package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

type prometheusMetric struct {
	Name  string
	Help  string
	Type  string
	Value func(engine.Stats) int64
}

var prometheusMetricsContract = []prometheusMetric{
	{
		Name:  "guardianwaf_requests_total",
		Help:  "Total number of requests processed.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.TotalRequests },
	},
	{
		Name:  "guardianwaf_requests_blocked_total",
		Help:  "Total number of blocked requests.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.BlockedRequests },
	},
	{
		Name:  "guardianwaf_requests_challenged_total",
		Help:  "Total number of challenged requests.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.ChallengedRequests },
	},
	{
		Name:  "guardianwaf_requests_logged_total",
		Help:  "Total number of logged suspicious requests.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.LoggedRequests },
	},
	{
		Name:  "guardianwaf_requests_passed_total",
		Help:  "Total number of passed requests.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.PassedRequests },
	},
	{
		Name:  "guardianwaf_latency_avg_microseconds",
		Help:  "Average request latency in microseconds.",
		Type:  "gauge",
		Value: func(s engine.Stats) int64 { return s.AvgLatencyUs },
	},
	{
		Name: "guardianwaf_geoip_ready",
		Help: "GeoIP database readiness status, 1 for ready and 0 for not ready.",
		Type: "gauge",
		Value: func(s engine.Stats) int64 {
			if s.GeoIPReady {
				return 1
			}
			return 0
		},
	},
	{
		Name:  "guardianwaf_geoip_ranges",
		Help:  "Number of GeoIP ranges loaded.",
		Type:  "gauge",
		Value: func(s engine.Stats) int64 { return s.GeoIPRanges },
	},
	{
		Name: "guardianwaf_tracing_enabled",
		Help: "Tracing runtime status, 1 when enabled and 0 when disabled.",
		Type: "gauge",
		Value: func(s engine.Stats) int64 {
			if s.TracingEnabled {
				return 1
			}
			return 0
		},
	},
	{
		Name:  "guardianwaf_tracing_spans_created_total",
		Help:  "Total number of tracing spans created.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.TracingSpans },
	},
	{
		Name:  "guardianwaf_tracing_spans_exported_total",
		Help:  "Total number of tracing spans handed to the configured exporter.",
		Type:  "counter",
		Value: func(s engine.Stats) int64 { return s.TracingExported },
	},
}

type metricsDependencies struct {
	Router        func() *proxy.Router
	AlertManager  func() *alerting.Manager
	DockerEnabled func() bool
	DockerWatcher func() *dkr.Watcher
	AIEnabled     func() bool
	AIAnalyzer    func() *ai.Analyzer
}

func setupAccessLogging(eng *engine.Engine, cfg *config.Config) {
	if !cfg.Logging.LogBlocked && !cfg.Logging.LogAllowed {
		return
	}
	logBlocked := cfg.Logging.LogBlocked
	logAllowed := cfg.Logging.LogAllowed
	if cfg.Logging.LogBody {
		eng.Logs.Warn("logging.log_body=true requested; request body logging can expose credentials/PII and the current structured access log does not include request bodies")
	}
	eng.SetAccessLog(func(entry engine.AccessLogEntry) {
		isBlocked := entry.Action == "block" || entry.Action == "challenge"
		if isBlocked && !logBlocked {
			return
		}
		if !isBlocked && !logAllowed {
			return
		}
		if cfg.Logging.Format == "json" {
			_ = json.NewEncoder(os.Stdout).Encode(struct {
				Timestamp  string `json:"ts"`
				ClientIP   string `json:"ip"`
				Method     string `json:"method"`
				Path       string `json:"path"`
				StatusCode int    `json:"status"`
				Action     string `json:"action"`
				Score      int    `json:"score"`
				Duration   string `json:"dur_us"`
				UserAgent  string `json:"ua"`
				Findings   int    `json:"findings"`
				RequestID  string `json:"request_id"`
				TenantID   string `json:"tenant_id,omitempty"`
			}{
				Timestamp:  entry.Timestamp,
				ClientIP:   entry.ClientIP,
				Method:     entry.Method,
				Path:       entry.Path,
				StatusCode: entry.StatusCode,
				Action:     entry.Action,
				Score:      entry.Score,
				Duration:   entry.Duration,
				UserAgent:  entry.UserAgent,
				Findings:   entry.Findings,
				RequestID:  entry.RequestID,
				TenantID:   entry.TenantID,
			})
		} else {
			fmt.Fprintf(os.Stdout, "%s %s %s %s %d %s score=%d dur=%sus findings=%d\n",
				entry.Timestamp, sanitizeLogField(entry.ClientIP), entry.Method, sanitizeLogField(entry.Path),
				entry.StatusCode, entry.Action, entry.Score, entry.Duration, entry.Findings)
		}
	})
	eng.Logs.Infof("Access logging enabled (blocked=%v, allowed=%v, format=%s)", logBlocked, logAllowed, cfg.Logging.Format)
}

func registerMetricsHandler(mux *http.ServeMux, eng *engine.Engine) {
	registerMetricsHandlerWithDeps(mux, eng, metricsDependencies{})
}

func registerMetricsHandlerWithDeps(mux *http.ServeMux, eng *engine.Engine, deps metricsDependencies) {
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s := eng.Stats()
		for _, metric := range prometheusMetricsContract {
			fmt.Fprintf(w, "# HELP %s %s\n", metric.Name, metric.Help)
			fmt.Fprintf(w, "# TYPE %s %s\n", metric.Name, metric.Type)
			fmt.Fprintf(w, "%s %d\n", metric.Name, metric.Value(s))
		}
		writeLatencyHistogram(w, s)
		writeLayerTimingHistogram(w, s)
		writeEventStoreMetrics(w, eng)
		writeDashboardAuditMetrics(w)
		writeEventBusMetrics(w, eng.EventBus())
		if deps.Router != nil {
			if router := deps.Router(); router != nil {
				writeUpstreamMetrics(w, router.AllUpstreamStatus())
			}
		}
		var alertMgr *alerting.Manager
		if deps.AlertManager != nil {
			alertMgr = deps.AlertManager()
		}
		writeAlertingMetrics(w, alertMgr)
		dockerEnabled := false
		if deps.DockerEnabled != nil {
			dockerEnabled = deps.DockerEnabled()
		}
		var dockerWatcher *dkr.Watcher
		if deps.DockerWatcher != nil {
			dockerWatcher = deps.DockerWatcher()
		}
		writeDockerDiscoveryMetrics(w, dockerEnabled, dockerWatcher)
		aiEnabled := false
		if deps.AIEnabled != nil {
			aiEnabled = deps.AIEnabled()
		}
		var aiAnalyzer *ai.Analyzer
		if deps.AIAnalyzer != nil {
			aiAnalyzer = deps.AIAnalyzer()
		}
		writeAIMetrics(w, aiEnabled, aiAnalyzer)
	})
}

func writeLatencyHistogram(w http.ResponseWriter, s engine.Stats) {
	const metricName = "guardianwaf_request_duration_seconds"
	fmt.Fprintf(w, "# HELP %s Request processing duration in seconds.\n", metricName)
	fmt.Fprintf(w, "# TYPE %s histogram\n", metricName)
	for _, bucket := range s.LatencyBuckets {
		fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", metricName, prometheusSecondsLabel(bucket.UpperBoundMicros), bucket.Count)
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", metricName, s.TotalRequests)
	fmt.Fprintf(w, "%s_sum %.6f\n", metricName, float64(s.LatencySumUs)/1_000_000)
	fmt.Fprintf(w, "%s_count %d\n", metricName, s.TotalRequests)
}

func writeLayerTimingHistogram(w http.ResponseWriter, s engine.Stats) {
	const metricName = "guardianwaf_layer_duration_seconds"
	fmt.Fprintf(w, "# HELP %s WAF pipeline layer processing duration in seconds.\n", metricName)
	fmt.Fprintf(w, "# TYPE %s histogram\n", metricName)
	for _, layer := range s.LayerTiming {
		layerName := prometheusLabelValue(layer.Layer)
		for _, bucket := range layer.LatencyBuckets {
			fmt.Fprintf(w, "%s_bucket{layer=\"%s\",le=\"%s\"} %d\n", metricName, layerName, prometheusSecondsLabel(bucket.UpperBoundMicros), bucket.Count)
		}
		fmt.Fprintf(w, "%s_bucket{layer=\"%s\",le=\"+Inf\"} %d\n", metricName, layerName, layer.Count)
		fmt.Fprintf(w, "%s_sum{layer=\"%s\"} %.6f\n", metricName, layerName, float64(layer.DurationSumUs)/1_000_000)
		fmt.Fprintf(w, "%s_count{layer=\"%s\"} %d\n", metricName, layerName, layer.Count)
	}
}

func prometheusSecondsLabel(micros int64) string {
	switch micros {
	case 100:
		return "0.0001"
	case 500:
		return "0.0005"
	case 1_000:
		return "0.001"
	case 5_000:
		return "0.005"
	case 10_000:
		return "0.01"
	case 50_000:
		return "0.05"
	case 100_000:
		return "0.1"
	case 500_000:
		return "0.5"
	case 1_000_000:
		return "1"
	case 5_000_000:
		return "5"
	default:
		return fmt.Sprintf("%.6f", float64(micros)/1_000_000)
	}
}

func writeEventStoreMetrics(w http.ResponseWriter, eng *engine.Engine) {
	stats := eng.Stats()
	dropped := int64(0)
	if reporter, ok := eng.EventStore().(interface{ DroppedEvents() int64 }); ok {
		dropped = reporter.DroppedEvents()
	}
	fmt.Fprintln(w, "# HELP guardianwaf_event_store_errors_total Total event store write errors observed by the engine.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_store_errors_total counter")
	fmt.Fprintf(w, "guardianwaf_event_store_errors_total %d\n", stats.EventStoreErrors)
	fmt.Fprintln(w, "# HELP guardianwaf_event_store_dropped_total Total events dropped or not persisted by the event store.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_store_dropped_total counter")
	fmt.Fprintf(w, "guardianwaf_event_store_dropped_total %d\n", dropped)
}

func writeDashboardAuditMetrics(w http.ResponseWriter) {
	fmt.Fprintln(w, "# HELP guardianwaf_dashboard_audit_persistence_failures_total Total dashboard mutation audit records that could not be durably persisted.")
	fmt.Fprintln(w, "# TYPE guardianwaf_dashboard_audit_persistence_failures_total counter")
	fmt.Fprintf(w, "guardianwaf_dashboard_audit_persistence_failures_total %d\n", dashboard.AuditPersistenceFailures())
}

func writeEventBusMetrics(w http.ResponseWriter, bus engine.EventPublisher) {
	stats := events.EventBusStats{}
	if reporter, ok := bus.(interface {
		Stats() events.EventBusStats
	}); ok {
		stats = reporter.Stats()
	}
	fmt.Fprintln(w, "# HELP guardianwaf_event_bus_subscribers Current event bus subscriber count.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_bus_subscribers gauge")
	fmt.Fprintf(w, "guardianwaf_event_bus_subscribers %d\n", stats.Subscribers)
	fmt.Fprintln(w, "# HELP guardianwaf_event_bus_max_subscribers Maximum event bus subscriber count before new subscribers are rejected.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_bus_max_subscribers gauge")
	fmt.Fprintf(w, "guardianwaf_event_bus_max_subscribers %d\n", stats.MaxSubscribers)
	fmt.Fprintln(w, "# HELP guardianwaf_event_bus_published_total Total events published to the event bus.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_bus_published_total counter")
	fmt.Fprintf(w, "guardianwaf_event_bus_published_total %d\n", stats.PublishedEvents)
	fmt.Fprintln(w, "# HELP guardianwaf_event_bus_dropped_total Total event bus deliveries dropped because subscribers were full.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_bus_dropped_total counter")
	fmt.Fprintf(w, "guardianwaf_event_bus_dropped_total %d\n", stats.DroppedEvents)
	fmt.Fprintln(w, "# HELP guardianwaf_event_bus_rejected_subscriptions_total Total event bus subscriptions rejected because the subscriber cap was reached.")
	fmt.Fprintln(w, "# TYPE guardianwaf_event_bus_rejected_subscriptions_total counter")
	fmt.Fprintf(w, "guardianwaf_event_bus_rejected_subscriptions_total %d\n", stats.RejectedSubscriptions)
}

func writeUpstreamMetrics(w http.ResponseWriter, statuses []proxy.UpstreamStatus) {
	fmt.Fprintln(w, "# HELP guardianwaf_upstream_targets_total Number of configured targets per upstream route.")
	fmt.Fprintln(w, "# TYPE guardianwaf_upstream_targets_total gauge")
	fmt.Fprintln(w, "# HELP guardianwaf_upstream_targets_healthy Number of healthy targets per upstream route.")
	fmt.Fprintln(w, "# TYPE guardianwaf_upstream_targets_healthy gauge")
	fmt.Fprintln(w, "# HELP guardianwaf_upstream_active_connections Active proxied connections per upstream route.")
	fmt.Fprintln(w, "# TYPE guardianwaf_upstream_active_connections gauge")
	fmt.Fprintln(w, "# HELP guardianwaf_upstream_circuit_state Number of targets per upstream route in each circuit-breaker state.")
	fmt.Fprintln(w, "# TYPE guardianwaf_upstream_circuit_state gauge")

	for _, status := range statuses {
		upstream := prometheusLabelValue(status.Name)
		activeConns := int64(0)
		circuitStates := map[string]int{
			"closed":    0,
			"open":      0,
			"half-open": 0,
			"unknown":   0,
		}
		for _, target := range status.Targets {
			activeConns += target.ActiveConns
			state := target.CircuitState
			if _, ok := circuitStates[state]; !ok {
				state = "unknown"
			}
			circuitStates[state]++
		}

		fmt.Fprintf(w, "guardianwaf_upstream_targets_total{upstream=\"%s\"} %d\n", upstream, status.TotalCount)
		fmt.Fprintf(w, "guardianwaf_upstream_targets_healthy{upstream=\"%s\"} %d\n", upstream, status.HealthyCount)
		fmt.Fprintf(w, "guardianwaf_upstream_active_connections{upstream=\"%s\"} %d\n", upstream, activeConns)
		for _, state := range []string{"closed", "open", "half-open", "unknown"} {
			fmt.Fprintf(w, "guardianwaf_upstream_circuit_state{upstream=\"%s\",state=\"%s\"} %d\n", upstream, state, circuitStates[state])
		}
	}
}

func writeAlertingMetrics(w http.ResponseWriter, mgr *alerting.Manager) {
	stats := alerting.Stats{}
	if mgr != nil {
		stats = mgr.GetStats()
	}

	fmt.Fprintln(w, "# HELP guardianwaf_alert_manager_sent_total Total alert deliveries marked sent by the alerting manager.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_manager_sent_total counter")
	fmt.Fprintf(w, "guardianwaf_alert_manager_sent_total %d\n", stats.Sent)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_manager_failed_total Total alert deliveries marked failed by the alerting manager.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_manager_failed_total counter")
	fmt.Fprintf(w, "guardianwaf_alert_manager_failed_total %d\n", stats.Failed)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_manager_dropped_total Total alert deliveries dropped before dispatch because alert backpressure was active.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_manager_dropped_total counter")
	fmt.Fprintf(w, "guardianwaf_alert_manager_dropped_total %d\n", stats.Dropped)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_manager_max_dispatch Maximum concurrent alert deliveries allowed before dispatch backpressure is active.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_manager_max_dispatch gauge")
	fmt.Fprintf(w, "guardianwaf_alert_manager_max_dispatch %d\n", stats.MaxDispatch)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_email_sent_total Total SMTP email alerts sent.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_email_sent_total counter")
	fmt.Fprintf(w, "guardianwaf_alert_email_sent_total %d\n", stats.Email.Sent)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_email_failed_total Total SMTP email alerts that failed to send.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_email_failed_total counter")
	fmt.Fprintf(w, "guardianwaf_alert_email_failed_total %d\n", stats.Email.Failed)
	fmt.Fprintln(w, "# HELP guardianwaf_alert_targets_configured Number of configured alert targets by type.")
	fmt.Fprintln(w, "# TYPE guardianwaf_alert_targets_configured gauge")
	fmt.Fprintf(w, "guardianwaf_alert_targets_configured{type=\"webhook\"} %d\n", stats.WebhookCount)
	fmt.Fprintf(w, "guardianwaf_alert_targets_configured{type=\"email\"} %d\n", stats.EmailCount)
}

func writeDockerDiscoveryMetrics(w http.ResponseWriter, enabled bool, watcher *dkr.Watcher) {
	stats := dkr.WatcherStats{}
	if watcher != nil {
		stats = watcher.Stats()
	}

	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovery_enabled Docker auto-discovery configuration status, 1 when enabled.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovery_enabled gauge")
	fmt.Fprintf(w, "guardianwaf_docker_discovery_enabled %d\n", boolGauge(enabled))
	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovery_running Docker auto-discovery watcher runtime status, 1 when running.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovery_running gauge")
	fmt.Fprintf(w, "guardianwaf_docker_discovery_running %d\n", boolGauge(stats.Running))
	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovered_services Number of Docker services currently discovered.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovered_services gauge")
	fmt.Fprintf(w, "guardianwaf_docker_discovered_services %d\n", stats.ServiceCount)
	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovery_last_sync_success Docker auto-discovery last sync status, 1 when successful.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovery_last_sync_success gauge")
	fmt.Fprintf(w, "guardianwaf_docker_discovery_last_sync_success %d\n", boolGauge(stats.LastSyncOK))
	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovery_event_stream_connected Docker event stream connection status, 1 when connected.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovery_event_stream_connected gauge")
	fmt.Fprintf(w, "guardianwaf_docker_discovery_event_stream_connected %d\n", boolGauge(stats.EventStreamConnected))
	fmt.Fprintln(w, "# HELP guardianwaf_docker_discovery_sync_failures_total Total Docker auto-discovery sync failures.")
	fmt.Fprintln(w, "# TYPE guardianwaf_docker_discovery_sync_failures_total counter")
	fmt.Fprintf(w, "guardianwaf_docker_discovery_sync_failures_total %d\n", stats.SyncFailures)
}

func writeAIMetrics(w http.ResponseWriter, enabled bool, analyzer *ai.Analyzer) {
	usage := ai.UsageStats{}
	if analyzer != nil {
		if store := analyzer.GetStore(); store != nil {
			usage = store.GetUsage()
		}
	}

	fmt.Fprintln(w, "# HELP guardianwaf_ai_enabled AI analysis configuration status, 1 when enabled.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_enabled gauge")
	fmt.Fprintf(w, "guardianwaf_ai_enabled %d\n", boolGauge(enabled))
	fmt.Fprintln(w, "# HELP guardianwaf_ai_tokens_used_total Total AI provider tokens used.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_tokens_used_total counter")
	fmt.Fprintf(w, "guardianwaf_ai_tokens_used_total %d\n", usage.TotalTokensUsed)
	fmt.Fprintln(w, "# HELP guardianwaf_ai_tokens_used_current AI provider tokens used in the current bounded window.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_tokens_used_current gauge")
	fmt.Fprintf(w, "guardianwaf_ai_tokens_used_current{window=\"hour\"} %d\n", usage.TokensUsedHour)
	fmt.Fprintf(w, "guardianwaf_ai_tokens_used_current{window=\"day\"} %d\n", usage.TokensUsedDay)
	fmt.Fprintln(w, "# HELP guardianwaf_ai_requests_total Total AI provider requests made.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_requests_total counter")
	fmt.Fprintf(w, "guardianwaf_ai_requests_total %d\n", usage.TotalRequests)
	fmt.Fprintln(w, "# HELP guardianwaf_ai_requests_current AI provider requests made in the current bounded window.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_requests_current gauge")
	fmt.Fprintf(w, "guardianwaf_ai_requests_current{window=\"hour\"} %d\n", usage.RequestsHour)
	fmt.Fprintf(w, "guardianwaf_ai_requests_current{window=\"day\"} %d\n", usage.RequestsDay)
	pendingEvents := 0
	if analyzer != nil {
		pendingEvents = analyzer.PendingEvents()
	}
	fmt.Fprintln(w, "# HELP guardianwaf_ai_pending_events Current suspicious events waiting in the bounded AI batch.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_pending_events gauge")
	fmt.Fprintf(w, "guardianwaf_ai_pending_events %d\n", pendingEvents)
	fmt.Fprintln(w, "# HELP guardianwaf_ai_cost_usd_total Estimated total AI provider cost in USD.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_cost_usd_total counter")
	fmt.Fprintf(w, "guardianwaf_ai_cost_usd_total %.6f\n", usage.TotalCostUSD)
	fmt.Fprintln(w, "# HELP guardianwaf_ai_verdicts_total Total AI verdict actions applied by type.")
	fmt.Fprintln(w, "# TYPE guardianwaf_ai_verdicts_total counter")
	fmt.Fprintf(w, "guardianwaf_ai_verdicts_total{action=\"block\"} %d\n", usage.BlocksTriggered)
	fmt.Fprintf(w, "guardianwaf_ai_verdicts_total{action=\"monitor\"} %d\n", usage.MonitorsTriggered)
}

func boolGauge(v bool) int {
	if v {
		return 1
	}
	return 0
}

func prometheusLabelValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

// sanitizeLogField strips control characters (0x00-0x1F, 0x7F) from a string
// to prevent log injection via ANSI escape sequences or other control chars
// in user-controlled fields (path, user-agent, etc.).
func sanitizeLogField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}
