# GuardianWAF Grafana Dashboard

Production-ready Grafana dashboard for monitoring GuardianWAF.

## Dashboard Panels

### Overview Section
- **Instances Up**: Current number of healthy GuardianWAF instances
- **Passed Request Rate**: Requests allowed through GuardianWAF
- **Block Rate**: Percentage of requests blocked by the WAF
- **P99 WAF Latency**: 99th percentile request processing latency from the stable histogram
- **Blocked Request Rate**: Blocked requests per second
- **Total Requests**: Total processed request counter

### Detection Layer Performance
- **WAF Latency Quantiles**: P95 and P99 request processing latency
- **Slowest Layer P95**: Maximum P95 layer processing latency across the active WAF pipeline
- **Blocked Request Rate**: Blocked requests per second

### Rate Limiting & IP Management
- **Blocked Requests**: Total blocked request counters
- **Pass Rate**: Ratio of passed requests to total requests
- **Event Store Drops**: Events rejected, dropped, or not persisted by the configured event store

### Cluster & Upstream Health
- **Healthy Upstream Targets**: Total healthy upstream targets across configured routes
- **Open Upstream Circuits**: Targets whose circuit breaker is currently open
- **GeoIP Ready**: GeoIP readiness status
- **GeoIP Status**: Number of loaded GeoIP ranges
- **Alert Delivery Failures**: Alert manager and SMTP email failures over the last 5 minutes
- **Alert Targets**: Configured webhook and email alert targets
- **Docker Discovery Sync Failures**: Docker auto-discovery sync failures over the last 5 minutes
- **Docker Discovered Services**: Current Docker service discovery count

### Geographic Distribution
- **GeoIP Ranges Loaded**: Loaded GeoIP range count
- **GeoIP Ready**: GeoIP readiness status

### AI Analysis & Threat Intelligence
- **Logged Requests**: Suspicious requests logged without blocking
- **Challenges**: Challenge actions over the last hour
- **Block Rate**: Blocked request ratio
- **Logged Requests (1h)**: Logged suspicious requests over the last hour
- **AI Tokens (1h)**: AI provider tokens used in the current hour
- **AI Cost Total**: Estimated total AI provider cost in USD

## Installation

### Option 1: Grafana UI

1. Navigate to **Dashboards** → **Import**
2. Upload `dashboard.json` or paste contents
3. Select your Prometheus datasource
4. Click **Import**

### Option 2: Grafana API

```bash
# Set your Grafana credentials
export GRAFANA_URL="http://localhost:3000"
export GRAFANA_API_KEY="your-api-key"

# Import dashboard
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_API_KEY" \
  -d @dashboard.json \
  "$GRAFANA_URL/api/dashboards/db"
```

### Option 3: Kubernetes (Grafana Operator)

```yaml
apiVersion: grafana.integreatly.org/v1beta1
kind: GrafanaDashboard
metadata:
  name: guardianwaf
  namespace: monitoring
spec:
  folder: "Security"
  datasources:
    - name: datasource
      value: prometheus
  url: https://raw.githubusercontent.com/guardianwaf/guardianwaf/main/contrib/grafana/dashboard.json
```

## Required Metrics

This dashboard uses the stable GuardianWAF metrics documented in `docs/metrics.md`:

| Metric | Description |
|--------|-------------|
| `guardianwaf_requests_total` | Total requests processed |
| `guardianwaf_requests_blocked_total` | Blocked request count |
| `guardianwaf_requests_challenged_total` | Challenged request count |
| `guardianwaf_requests_logged_total` | Logged suspicious request count |
| `guardianwaf_requests_passed_total` | Passed request count |
| `guardianwaf_latency_avg_microseconds` | Average engine processing latency |
| `guardianwaf_request_duration_seconds` | Request latency histogram for P95/P99 panels |
| `guardianwaf_layer_duration_seconds` | Pipeline layer latency histogram for per-layer P95 panels |
| `guardianwaf_upstream_targets_total` | Configured target count by upstream route |
| `guardianwaf_upstream_targets_healthy` | Healthy target count by upstream route |
| `guardianwaf_upstream_active_connections` | Active proxied connections by upstream route |
| `guardianwaf_upstream_circuit_state` | Target count by upstream route and circuit-breaker state |
| `guardianwaf_event_store_dropped_total` | Event store drop/persistence failure counter |
| `guardianwaf_alert_manager_sent_total` | Alert deliveries marked sent by the alerting manager |
| `guardianwaf_alert_manager_failed_total` | Alert deliveries marked failed by the alerting manager |
| `guardianwaf_alert_email_sent_total` | SMTP email alerts sent |
| `guardianwaf_alert_email_failed_total` | SMTP email alerts that failed to send |
| `guardianwaf_alert_targets_configured` | Configured alert target count by type |
| `guardianwaf_docker_discovery_enabled` | Docker auto-discovery configuration status |
| `guardianwaf_docker_discovery_running` | Docker auto-discovery watcher runtime status |
| `guardianwaf_docker_discovered_services` | Current Docker discovered service count |
| `guardianwaf_docker_discovery_last_sync_success` | Last Docker discovery sync status |
| `guardianwaf_docker_discovery_event_stream_connected` | Docker event stream connection status |
| `guardianwaf_docker_discovery_sync_failures_total` | Docker discovery sync failure counter |
| `guardianwaf_ai_enabled` | AI analysis configuration status |
| `guardianwaf_ai_tokens_used_total` | Total AI provider tokens used |
| `guardianwaf_ai_tokens_used_current` | AI provider tokens used by current fixed window |
| `guardianwaf_ai_requests_total` | Total AI provider requests made |
| `guardianwaf_ai_requests_current` | AI provider requests by current fixed window |
| `guardianwaf_ai_cost_usd_total` | Estimated total AI provider cost in USD |
| `guardianwaf_ai_verdicts_total` | AI verdict actions by type |
| `guardianwaf_geoip_ready` | GeoIP readiness status |
| `guardianwaf_geoip_ranges` | Loaded GeoIP range count |

## Variables

| Variable | Description |
|----------|-------------|
| `datasource` | Prometheus datasource selector |
| `instance` | GuardianWAF instance filter (multi-select) |

## Alerts (Recommended)

Configure these alerts in Grafana:

```yaml
# Example alert rules
groups:
  - name: guardianwaf
    rules:
      - alert: HighBlockRate
        expr: rate(guardianwaf_requests_blocked_total[5m]) / rate(guardianwaf_requests_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High block rate detected"

      - alert: HighLatency
        expr: histogram_quantile(0.99, sum(rate(guardianwaf_request_duration_seconds_bucket[5m])) by (le)) > 1
        for: 5m
        annotations:
          summary: "P99 WAF latency above 1 second"

      - alert: InstanceDown
        expr: up{job="guardianwaf"} == 0
        for: 1m
        annotations:
          summary: "GuardianWAF instance is down"

      - alert: UpstreamUnavailable
        expr: guardianwaf_upstream_targets_total > 0 and guardianwaf_upstream_targets_healthy == 0
        for: 2m
        annotations:
          summary: "GuardianWAF upstream route has no healthy targets"

      - alert: EventStoreDroppingEvents
        expr: increase(guardianwaf_event_store_dropped_total[5m]) > 0
        for: 1m
        annotations:
          summary: "GuardianWAF event store is dropping or failing to persist events"

      - alert: AlertDeliveryFailures
        expr: increase(guardianwaf_alert_manager_failed_total[5m]) + increase(guardianwaf_alert_email_failed_total[5m]) > 0
        for: 1m
        annotations:
          summary: "GuardianWAF alert delivery failures detected"

      - alert: DockerDiscoveryNotRunning
        expr: guardianwaf_docker_discovery_enabled == 1 and guardianwaf_docker_discovery_running == 0
        for: 2m
        annotations:
          summary: "GuardianWAF Docker discovery is enabled but not running"

      - alert: DockerDiscoverySyncFailures
        expr: increase(guardianwaf_docker_discovery_sync_failures_total[5m]) > 0
        for: 1m
        annotations:
          summary: "GuardianWAF Docker discovery sync failures detected"

      - alert: AIHourlyTokenBudgetHigh
        expr: guardianwaf_ai_tokens_used_current{window="hour"} > 40000
        for: 5m
        annotations:
          summary: "GuardianWAF AI hourly token usage is high"

      - alert: AIDailyCostIncrease
        expr: increase(guardianwaf_ai_cost_usd_total[1d]) > 10
        for: 5m
        annotations:
          summary: "GuardianWAF AI estimated daily cost increased above threshold"

      - alert: GeoIPNotReady
        expr: guardianwaf_geoip_ready == 0
        for: 10m
        annotations:
          summary: "GuardianWAF GeoIP data is not ready"
```

## Screenshots

_Screenshots to be added after deployment_

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-05 | Initial production dashboard |
