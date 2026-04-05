# GuardianWAF Grafana Dashboard

Production-ready Grafana dashboard for monitoring GuardianWAF.

## Dashboard Panels

### Overview Section
- **Instances Up**: Current number of healthy GuardianWAF instances
- **Request Rate by Status**: HTTP status code distribution over time
- **Block Rate**: Percentage of requests blocked by the WAF
- **P99 Latency**: 99th percentile request latency
- **Threats by Type**: Time series of detected threats by category
- **Memory Usage**: Per-instance memory consumption

### Detection Layer Performance
- **Detection Latency by Detector (P95)**: Performance of each detection engine
- **Detections by Type & Action**: Breakdown of detections and actions taken

### Rate Limiting & IP Management
- **Rate Limited IPs**: Currently rate-limited IP addresses
- **Blacklisted IPs**: Active IP blacklist size
- **Rate Limit Hits**: Hits per rate limit rule
- **Cache Hit Rate**: Performance of various internal caches

### Cluster & Upstream Health
- **Upstream Health Status**: Health status of all upstream targets
- **Cluster Status**: Node count and leader election status

### Geographic Distribution
- **Requests by Country**: World map visualization of request origins
- **Top Countries by Request Rate**: Table of top 20 countries

### AI Analysis & Threat Intelligence
- **AI Queue Depth**: Pending AI analysis requests
- **AI Cost (USD/hour)**: Real-time cost tracking
- **AI Detection Rate**: Threats detected per analysis
- **Threat Intel Hits by Feed**: Reputation feed effectiveness
- **AI Verdict Distribution**: Breakdown of AI classifications

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

This dashboard expects the following Prometheus metrics:

| Metric | Description |
|--------|-------------|
| `guardianwaf_up` | Instance health status |
| `guardianwaf_requests_total` | Total HTTP requests |
| `guardianwaf_requests_blocked_total` | Blocked request count |
| `guardianwaf_request_duration_seconds_*` | Request latency histogram |
| `guardianwaf_threats_total` | Threats by type |
| `guardianwaf_detection_duration_seconds_*` | Detection latency histogram |
| `guardianwaf_detections_total` | Detection events |
| `guardianwaf_rate_limit_blocked_ips` | Active rate-limited IPs |
| `guardianwaf_ipacl_blacklist_size` | Blacklist size |
| `guardianwaf_rate_limit_hits_total` | Rate limit hits |
| `guardianwaf_cache_hits_total` / `guardianwaf_cache_misses_total` | Cache statistics |
| `guardianwaf_upstream_healthy` | Upstream health status |
| `guardianwaf_cluster_nodes_total` | Cluster node count |
| `guardianwaf_cluster_leader` | Leader election status |
| `guardianwaf_requests_by_country_total` | Geographic distribution |
| `guardianwaf_ai_analysis_queue_depth` | AI analysis queue |
| `guardianwaf_ai_analysis_cost_usd` | AI analysis cost |
| `guardianwaf_ai_threats_detected_total` | AI-detected threats |
| `guardianwaf_ai_analysis_completed_total` | Completed AI analyses |
| `guardianwaf_ai_analysis_verdict_total` | AI verdicts by category |
| `guardianwaf_threat_intel_hits_total` | Threat intel hits |
| `guardianwaf_memory_usage_bytes` | Memory usage |

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
        expr: histogram_quantile(0.99, rate(guardianwaf_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        annotations:
          summary: "P99 latency above 1 second"

      - alert: InstanceDown
        expr: up{job="guardianwaf"} == 0
        for: 1m
        annotations:
          summary: "GuardianWAF instance is down"

      - alert: AIQueueBacklog
        expr: guardianwaf_ai_analysis_queue_depth > 100
        for: 10m
        annotations:
          summary: "AI analysis queue backlog detected"
```

## Screenshots

_Screenshots to be added after deployment_

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-05 | Initial production dashboard |
