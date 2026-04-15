# ADR 0009: OpenTelemetry Integration

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF currently lacks distributed tracing support. While it has:
- Request IDs via `X-GuardianWAF-RequestID` header
- Prometheus metrics (`/metrics`)
- Structured JSON logging
- pprof endpoints

It does not have OpenTelemetry integration, which would enable:
- End-to-end request tracing across all WAF layers
- Correlation between logs, metrics, and traces
- Integration with external tracing systems (Jaeger, Zipkin, Tempo)
- Context propagation to upstreams

## Decision

Add OpenTelemetry tracing support to GuardianWAF with the following principles:

1. **Zero new dependencies** — Use only the OpenTelemetry SDK, no external trace exporters bundled
2. **Opt-in** — Tracing disabled by default, enabled via config
3. **Non-blocking** — Tracing adds minimal overhead (<1µs per span)
4. **Layer-based spans** — Each WAF layer creates a span with relevant attributes

## Design

### Configuration

```yaml
tracing:
  enabled: true
  service_name: guardianwaf
  exporter: otlp
  endpoint: http://localhost:4317
  sampling_rate: 0.1  # 10% of requests
  export_interval: 5s
```

### Span Structure

Each WAF layer creates a span:
```
guardianwaf.request
├── ip_acl
├── threat_intel
├── cors
├── custom_rules
├── rate_limit
├── ato_protection
├── api_security
├── api_validation
├── sanitizer
├── crs
├── detection (6 sub-spans: sqli, xss, lfi, cmdi, xxe, ssrf)
├── virtual_patch
├── dlp
├── bot_detection
├── client_side
├── response
└── proxy
```

### Span Attributes

Per-span attributes:
- `waf.layer`: layer name
- `waf.action`: pass/block/challenge
- `waf.score`: cumulative threat score
- `waf.rule_id`: triggered rule (if any)
- `waf.tenant_id`: tenant identifier (for multi-tenant)

Root span attributes:
- `http.method`, `http.url`, `http.host`, `http.user_agent`
- `client.ip`: client IP address
- `waf.blocked`: boolean
- `waf.latency_ms`: total processing time

### Exporters

Support multiple exporters (build tags):
- **OTLP gRPC** (default): `otlpgrpc` — recommended for production
- **OTLP HTTP**: `otlphttp` — alternative to gRPC
- **Jaeger**: `jaeger` — for existing Jaeger deployments
- **Stdout**: `stdout` — for debugging, JSON format
- **Noop**: default, minimal overhead

### Implementation Locations

| File | Purpose |
|------|---------|
| `internal/tracing/tracer.go` | Tracer singleton, config, shutdown |
| `internal/tracing/spans.go` | Span helpers, attribute constants |
| `internal/tracing/exporter.go` | Exporter factory |
| `internal/engine/pipeline.go` | Add root span around pipeline |
| `internal/engine/layer.go` | Add child span per layer |

## Consequences

### Positive
- Full request visibility across all WAF layers
- Correlate WAF events with upstream traces
- Production debugging with trace context
- Standard format accepted by most observability platforms

### Negative
- Additional config complexity
- Small performance overhead (span creation, attribute setting)
- Build complexity with exporter options

### Trade-offs
- Sampling rate can be tuned to balance visibility vs overhead
- Disabled by default to maintain zero-dependency principle for basic builds
- Exporter abstracted to avoid bundling specific observability libraries

## Alternatives Considered

1. **Manual trace context propagation** — Too much boilerplate, no standard format
2. **Only use existing pprof** — pprof is for profiling, not distributed tracing
3. **Vendor-specific SDK (Datadog, New Relic)** — Vendor lock-in, additional dependencies

## Implementation Notes

- Use `go.opentelemetry.io/otel` v1.x
- Use `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc` for gRPC
- Support build tags to include/exclude exporters: `-tags otel_grpc,otel_jaeger`
- Graceful shutdown: flush traces on `Close()`
- Context propagation: extract/inject trace context from HTTP headers

## References

- [OpenTelemetry Go SDK](https://opentelemetry.io/docs/go/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [GuardianWAF Pipeline Architecture](../ARCHITECTURE.md#pipeline)
