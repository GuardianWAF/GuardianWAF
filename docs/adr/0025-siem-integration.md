# ADR 0025: SIEM Integration

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF generates rich security events: blocked requests, detection findings, rate limit violations, ATO alerts, DLP matches. These events are stored in the internal event ring buffer and streamed to the dashboard via SSE. However, enterprises already operate Security Information and Event Management (SIEM) systems (Splunk, IBM QRadar, Microsoft Sentinel, Elastic SIEM) as their centralized security monitoring platform.

GuardianWAF events must flow into these existing platforms for:
- **Correlation** — WAF events correlated with endpoint, network, and identity logs
- **Alerting** — SIEM-managed alert rules and on-call workflows
- **Compliance** — audit evidence collection in a tamper-resistant central store
- **Retention** — SIEM manages log retention per policy; GuardianWAF's ring buffer is ephemeral

Without native SIEM export, operators must build custom log forwarders (rsyslog, Logstash) that parse GuardianWAF's raw output — fragile and requiring ongoing maintenance.

## Decision

Implement a SIEM exporter (`internal/layers/siem/`) that:

1. Subscribes to the internal event bus
2. Normalizes events into multiple industry-standard formats
3. Batches and ships events to configured endpoints asynchronously
4. Provides back-pressure handling and retry logic

### Supported Formats

| Format | Standard | Target Systems |
|--------|----------|---------------|
| `json` | Custom JSON | Generic webhooks, HTTP collectors |
| `cef` | Common Event Format (ArcSight) | ArcSight, IBM QRadar |
| `leef` | Log Event Extended Format | IBM QRadar (preferred) |
| `syslog` | RFC 5424 structured syslog | Any syslog receiver |
| `splunk` | Splunk HEC JSON | Splunk (HTTP Event Collector) |
| `elastic` | Elasticsearch Bulk API | Elastic SIEM, OpenSearch |

All formats use the same normalized `Event` struct — format selection controls the serializer used at export time. Adding a new format requires only a new serializer function, not changes to the event model.

### Normalized Event Schema

```go
type Event struct {
    Timestamp   time.Time
    EventType   string           // block, allow, challenge, alert, dlp, ato
    Severity    Severity         // 1 (low), 5 (medium), 8 (high), 10 (critical)
    SourceIP    string
    SourcePort  int
    DestIP      string
    DestPort    int
    Method      string           // HTTP method
    Path        string
    UserAgent   string
    Host        string
    RequestID   string
    Action      string           // block | allow | challenge | log
    Reason      string           // Human-readable reason
    RuleID      string           // Triggering rule/CVE ID
    Score       int              // WAF threat score
    TenantID    string
    NodeID      string
    Fields      map[string]string // Custom enrichment fields from config
}
```

### Format Examples

**CEF (ArcSight):**
```
CEF:0|GuardianWAF|WAF|1.0|BLOCK|SQL Injection Detected|8|src=203.0.113.1 spt=49152 dst=10.0.0.1 dpt=443 request=/search cs1=SQLI-001 cs1Label=RuleID cn1=75 cn1Label=Score
```

**Splunk HEC:**
```json
{"time": 1234567890.123, "host": "gwaf-node-a", "source": "guardianwaf", "sourcetype": "waf:block", "event": { "src_ip": "203.0.113.1", "rule_id": "SQLI-001", "score": 75, ... }}
```

**Elasticsearch Bulk:**
```json
{"index": {"_index": "gwaf-events-2026.04", "_id": "req_abc123"}}
{"@timestamp": "2026-04-15T10:30:00.123Z", "event.type": "block", "source.ip": "203.0.113.1", ...}
```

### Async Export Pipeline

Events must never block WAF request processing. The exporter uses a buffered channel:

```
WAF Event Bus
     │
     ▼ (non-blocking send)
eventChan (buffered: 10,000)
     │
     ▼ (background worker)
Batcher
  - Collects up to batch_size events
  - Or flushes after flush_interval (whichever comes first)
     │
     ▼
HTTP POST → SIEM endpoint
  - Retry with exponential backoff (max 3 retries)
  - On persistent failure: drop oldest events, emit metric gwaf_siem_dropped_total
```

If `eventChan` is full (exporter falling behind), new events are dropped with a counter increment — WAF performance is never sacrificed for SIEM export.

### Multiple Destinations

A single GuardianWAF instance can export to multiple SIEM endpoints simultaneously:

```yaml
siem:
  exporters:
    - name: splunk-prod
      enabled: true
      endpoint: "https://splunk.internal:8088/services/collector"
      format: splunk
      api_key: "${SPLUNK_HEC_TOKEN}"
      batch_size: 500
      flush_interval: 5s

    - name: elastic-archive
      enabled: true
      endpoint: "https://elastic.internal:9200"
      format: elastic
      index: "gwaf-events"
      batch_size: 1000
      flush_interval: 10s

    - name: soc-webhook
      enabled: true
      endpoint: "https://soc.internal/waf-events"
      format: json
      batch_size: 1
      flush_interval: 0s       # Immediate send (low volume, high-severity only)
      filter:
        min_severity: 8         # Only critical/high events
```

### Event Filtering

Each exporter can define a filter to export only relevant events:

```yaml
filter:
  min_severity: 5              # Minimum severity level
  event_types: [block, ato]    # Specific event types only
  min_score: 50                # Minimum WAF threat score
  tenants: [tenant001]         # Multi-tenant: export only for these tenants
```

### Custom Field Enrichment

Operators can inject static fields into every exported event for SIEM correlation:

```yaml
siem:
  exporters:
    - name: qradar
      fields:
        environment: production
        datacenter: us-east-1
        team: secops
        app_id: "gwaf-prod-001"
```

### TLS and Authentication

| Auth Method | Config Key |
|-------------|------------|
| API key (header) | `api_key: "Bearer ..."` |
| Basic auth | `username` + `password` |
| mTLS client cert | `client_cert` + `client_key` |
| No auth (internal) | (omit) |

TLS verification is on by default (`skip_verify: false`). Self-signed SIEM endpoints can set `skip_verify: true` with a warning logged at startup.

## Consequences

### Positive
- Native multi-format support eliminates custom log shipper maintenance
- Async pipeline with back-pressure ensures zero WAF performance impact
- Multiple simultaneous exporters support split workflows (real-time SOC + bulk archive)
- Filter expressions reduce noise in downstream SIEM (only actionable events)

### Negative
- Buffered channel caps at 10,000 events — sustained high-volume attacks generating >10K events/s before flush will cause drops
- No guaranteed delivery: network partitions that exceed the retry window cause data loss (acceptable for most compliance frameworks which tolerate short gaps)
- CEF/LEEF formats have field length limits; long User-Agent strings or paths are truncated to fit
- `skip_verify: true` is a common misconfiguration that silently disables TLS verification in production

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/siem/exporter.go` | Async export pipeline, HTTP delivery, retry logic |
| `internal/layers/siem/formatter.go` | Format serializers (CEF, LEEF, JSON, Syslog, Splunk, Elastic) |
| `internal/config/config.go` | `SIEMConfig` struct |

## References

- [ArcSight Common Event Format (CEF)](https://community.microfocus.com/cyberres/arcsight/documentation/w/arcsight-documentation/3408/arcsight-cef-field-dictionary)
- [IBM LEEF Format](https://www.ibm.com/docs/en/dsm?topic=leef-overview)
- [Splunk HEC Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [Elasticsearch Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html)
- [RFC 5424: The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424)
- [ADR 0015: Distributed Event Store](./0015-distributed-event-store.md)
