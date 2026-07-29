# Metrics Contract

GuardianWAF exposes Prometheus-compatible text metrics at `GET /metrics` on the proxy listener. The endpoint is intended for internal scraping only; do not expose it directly to the public internet.

## Stable Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `guardianwaf_requests_total` | counter | none | Total requests processed by the engine. |
| `guardianwaf_requests_blocked_total` | counter | none | Requests blocked by WAF policy. |
| `guardianwaf_requests_challenged_total` | counter | none | Requests answered with a challenge action. |
| `guardianwaf_requests_logged_total` | counter | none | Suspicious requests logged without blocking. |
| `guardianwaf_requests_passed_total` | counter | none | Requests allowed to pass upstream. |
| `guardianwaf_latency_avg_microseconds` | gauge | none | Average engine processing latency in microseconds. |
| `guardianwaf_request_duration_seconds` | histogram | `le` | Request processing duration in seconds. Bucket labels are fixed and bounded. |
| `guardianwaf_layer_duration_seconds` | histogram | `layer`, `le` | WAF pipeline layer processing duration in seconds. Bucket labels are fixed; layer values come from the active built-in pipeline layer names. |
| `guardianwaf_upstream_targets_total` | gauge | `upstream` | Number of configured targets for each upstream route. |
| `guardianwaf_upstream_targets_healthy` | gauge | `upstream` | Number of healthy targets for each upstream route. |
| `guardianwaf_upstream_active_connections` | gauge | `upstream` | Active proxied connections for each upstream route. |
| `guardianwaf_upstream_circuit_state` | gauge | `upstream`, `state` | Number of targets in each circuit-breaker state for each upstream route. |
| `guardianwaf_event_store_errors_total` | counter | none | Event store write errors observed by the engine while processing requests. |
| `guardianwaf_dashboard_audit_persistence_failures_total` | counter | none | Dashboard mutation audit records that could not be durably persisted. |
| `guardianwaf_event_store_dropped_total` | counter | none | Events rejected, dropped, or not persisted by the configured event store. |
| `guardianwaf_event_bus_subscribers` | gauge | none | Current event bus subscriber count. |
| `guardianwaf_event_bus_max_subscribers` | gauge | none | Maximum event bus subscribers accepted before new subscribers are rejected. |
| `guardianwaf_event_bus_published_total` | counter | none | Events published to the event bus. |
| `guardianwaf_event_bus_dropped_total` | counter | none | Event bus deliveries dropped because a subscriber channel was full. |
| `guardianwaf_event_bus_rejected_subscriptions_total` | counter | none | Event bus subscriptions rejected because the subscriber cap was reached. |
| `guardianwaf_alert_manager_sent_total` | counter | none | Alert deliveries marked sent by the alerting manager. |
| `guardianwaf_alert_manager_failed_total` | counter | none | Alert deliveries marked failed by the alerting manager. |
| `guardianwaf_alert_manager_dropped_total` | counter | none | Alert deliveries dropped before dispatch because alert backpressure was active. |
| `guardianwaf_alert_manager_max_dispatch` | gauge | none | Maximum concurrent alert deliveries allowed before dispatch backpressure is active. |
| `guardianwaf_alert_email_sent_total` | counter | none | SMTP email alerts sent. |
| `guardianwaf_alert_email_failed_total` | counter | none | SMTP email alerts that failed to send. |
| `guardianwaf_alert_targets_configured` | gauge | `type` | Configured alert target count by fixed type: `webhook` or `email`. |
| `guardianwaf_docker_discovery_enabled` | gauge | none | `1` when Docker auto-discovery is enabled in configuration, otherwise `0`. |
| `guardianwaf_docker_discovery_running` | gauge | none | `1` when the Docker discovery watcher is running, otherwise `0`. |
| `guardianwaf_docker_discovered_services` | gauge | none | Number of Docker services currently discovered. |
| `guardianwaf_docker_discovery_last_sync_success` | gauge | none | `1` when the last Docker discovery sync succeeded, otherwise `0`. |
| `guardianwaf_docker_discovery_event_stream_connected` | gauge | none | `1` when the Docker event stream is connected, otherwise `0`. |
| `guardianwaf_docker_discovery_sync_failures_total` | counter | none | Total Docker discovery sync failures. |
| `guardianwaf_ai_enabled` | gauge | none | `1` when AI analysis is enabled in configuration, otherwise `0`. |
| `guardianwaf_ai_tokens_used_total` | counter | none | Total AI provider tokens used. |
| `guardianwaf_ai_tokens_used_current` | gauge | `window` | AI provider tokens used in the current fixed window: `hour` or `day`. |
| `guardianwaf_ai_requests_total` | counter | none | Total AI provider requests made. |
| `guardianwaf_ai_requests_current` | gauge | `window` | AI provider requests made in the current fixed window: `hour` or `day`. |
| `guardianwaf_ai_pending_events` | gauge | none | Suspicious events currently waiting in the bounded AI batch. |
| `guardianwaf_ai_cost_usd_total` | counter | none | Estimated total AI provider cost in USD. |
| `guardianwaf_ai_verdicts_total` | counter | `action` | Total AI verdict actions by fixed action: `block` or `monitor`. |
| `guardianwaf_geoip_ready` | gauge | none | `1` when GeoIP data is loaded and ready, otherwise `0`. |
| `guardianwaf_geoip_ranges` | gauge | none | Number of GeoIP ranges loaded. |
| `guardianwaf_tracing_enabled` | gauge | none | `1` when the engine-local tracing runtime is enabled, otherwise `0`. |
| `guardianwaf_tracing_spans_created_total` | counter | none | Tracing spans created by the engine. |
| `guardianwaf_tracing_spans_exported_total` | counter | none | Tracing spans handed to the configured exporter. |

Backup/restore automation can additionally emit `guardianwaf_backup_last_success_timestamp_seconds`, `guardianwaf_backup_archive_bytes`, `guardianwaf_backup_files`, and `guardianwaf_backup_rpo_target_seconds` to a node-exporter textfile-collector path. These host-level metrics are produced by `scripts/backup-state.sh`, not by the GuardianWAF `/metrics` endpoint.

The baseline exporter avoids unbounded labels. The request-duration and layer-duration histograms use the fixed Prometheus `le` bucket label with these bucket boundaries: `0.0001`, `0.0005`, `0.001`, `0.005`, `0.01`, `0.05`, `0.1`, `0.5`, `1`, `5`, and `+Inf` seconds. Layer-duration metrics also use the active pipeline layer name as `layer`; this value is bounded by configured built-in layer names. Upstream metrics use the configured route path as the `upstream` label and the fixed circuit `state` values `closed`, `open`, `half-open`, and `unknown`. Alert target metrics use only the fixed `type` values `webhook` and `email`. AI window metrics use only the fixed `window` values `hour` and `day`; AI verdict metrics use only the fixed `action` values `block` and `monitor`. Future metrics that add labels must document the allowed label values before release.

## Prometheus Scrape

```yaml
scrape_configs:
  - job_name: guardianwaf
    metrics_path: /metrics
    static_configs:
      - targets:
          - guardianwaf:8088
```

## Useful Queries

```promql
# Block rate over 5 minutes
rate(guardianwaf_requests_blocked_total[5m])

# Percentage of requests blocked
100 * rate(guardianwaf_requests_blocked_total[5m])
  / clamp_min(rate(guardianwaf_requests_total[5m]), 1)

# Average WAF processing latency
guardianwaf_latency_avg_microseconds

# P95 WAF processing latency in seconds
histogram_quantile(0.95, sum(rate(guardianwaf_request_duration_seconds_bucket[5m])) by (le))

# P99 WAF processing latency in milliseconds
histogram_quantile(0.99, sum(rate(guardianwaf_request_duration_seconds_bucket[5m])) by (le)) * 1000

# P95 latency per WAF layer in milliseconds
histogram_quantile(0.95, sum(rate(guardianwaf_layer_duration_seconds_bucket[5m])) by (layer, le)) * 1000

# Upstream groups with no healthy targets
guardianwaf_upstream_targets_total > 0
  and guardianwaf_upstream_targets_healthy == 0

# Open upstream circuits
guardianwaf_upstream_circuit_state{state="open"} > 0

# Event store drops in the last 5 minutes
increase(guardianwaf_event_store_dropped_total[5m])

# Event store write errors in the last 5 minutes
increase(guardianwaf_event_store_errors_total[5m])

# Event bus delivery drops in the last 5 minutes
increase(guardianwaf_event_bus_dropped_total[5m])

# Alert manager delivery failures in the last 5 minutes
increase(guardianwaf_alert_manager_failed_total[5m])

# Alert manager backpressure drops in the last 5 minutes
increase(guardianwaf_alert_manager_dropped_total[5m])

# SMTP email alert failures in the last 5 minutes
increase(guardianwaf_alert_email_failed_total[5m])

# Configured alert targets
guardianwaf_alert_targets_configured

# Docker discovery enabled but watcher is not running
guardianwaf_docker_discovery_enabled == 1
  and guardianwaf_docker_discovery_running == 0

# Docker discovery sync failures in the last 5 minutes
increase(guardianwaf_docker_discovery_sync_failures_total[5m])

# Docker event stream disconnected while discovery is running
guardianwaf_docker_discovery_running == 1
  and guardianwaf_docker_discovery_event_stream_connected == 0

# AI token usage in the current hour
guardianwaf_ai_tokens_used_current{window="hour"}

# AI estimated cost increase in the last day
increase(guardianwaf_ai_cost_usd_total[1d])

# AI provider requests in the current hour
guardianwaf_ai_requests_current{window="hour"}

# AI analyzer pending batch size
guardianwaf_ai_pending_events

# GeoIP readiness
guardianwaf_geoip_ready == 1

# Tracing configured but no spans exported in the last five minutes
guardianwaf_tracing_enabled == 1
  and increase(guardianwaf_tracing_spans_exported_total[5m]) == 0
```

## Planned Metrics

The production readiness roadmap should add new metrics here before release when new operational surfaces are introduced. Dashboards and alerts should use only the stable metrics above.
