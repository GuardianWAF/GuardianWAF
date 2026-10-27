# ADR 0039: Zero-Dependency Distributed Tracing

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Production WAF deployments require visibility into request flow across the active WAF pipeline. Without tracing:

- Diagnosing false positives requires manually correlating logs with detector scores
- Performance regression in a specific layer is hard to pinpoint from aggregate metrics
- Multi-node cluster deployments have no way to trace a request across nodes

OpenTelemetry is the standard, but importing the Go OTel SDK would violate the zero-dependency constraint (ADR 0001). The full OTel SDK pulls in ~40 transitive dependencies.

## Decision

Implement a minimal, zero-dependency tracing package (`internal/tracing/`) with an OpenTelemetry-compatible API surface:

1. **Span model** — TraceID (128-bit hex), SpanID (64-bit hex), parent-child links, attributes, events
2. **Exporter interface** — `Exporter` interface with `Export(Span)` and `Shutdown()`. Built-in exporters: `NoopExporter`, `StdoutExporter`. Pluggable for OTel bridge or custom backends.
3. **Configurable sampling** — `SamplingRate` (0.0–1.0) determines which traces are kept; each engine uses an isolated deterministic sampling counter
4. **Pipeline integration** — Root span created per request in `engine.Check()` and `engine.Middleware()`; `ctx.TraceSpan` on `RequestContext` carries the span through the pipeline
5. **Layer spans** — Each layer can create child spans with WAF-specific attributes (action, score, detector name)
6. **Configuration** — `tracing.enabled`, `tracing.service_name`, `tracing.sampling_rate`, `tracing.exporter_type` in config or `GWAF_TRACING_*` env vars

### Key design choices

- **Engine-local ownership** — Every engine owns its tracer and exporter. Reload
  reconfigures that tracer, and engine shutdown closes it; engines in the same
  process cannot overwrite each other's tracing configuration.
- **Validated IDs and config** — Root trace IDs are 128-bit random hex values,
  span IDs are 64-bit random hex values, and non-finite/out-of-range sampling
  rates or unsupported exporter names fail validation.

- **OTLP/HTTP JSON wire format** — `exporter_type: otlp` batches spans to an
  OpenTelemetry collector over HTTP with the OTLP JSON mapping, hand-encoded with
  the stdlib. gRPC and protobuf transports are out of scope.
- **W3C Trace Context, local sampling** — A valid incoming `traceparent` is
  joined and the upstream receives one naming the WAF span. The sampling
  decision stays local so clients cannot force tracing. Baggage is not
  interpreted; cluster RPCs carry `X-Correlation-ID` only.
- **Sync export, buffered delivery** — Exporters are called synchronously on
  span end. The `StdoutExporter` writes inline and is for development only; the
  OTLP exporter only copies the span into a bounded queue and drops (and counts)
  spans rather than blocking the request.

## Consequences

**Positive:**
- Full pipeline visibility without any external dependencies
- The built-in OTLP exporter delivers spans to any OpenTelemetry collector, Tempo or Jaeger without an SDK
- Sampling prevents overhead on high-traffic deployments
- Per-layer spans with WAF attributes enable targeted performance analysis

**Negative:**
- The `waf.request` span ends when inspection finishes, so it measures WAF time only. Upstream latency appears in the application's own child spans.
- No automatic context propagation across HTTP boundaries (only correlation ID header)
- The stdout exporter writes inline and can add latency (mitigated by sampling); the OTLP exporter drops spans instead

Operational counters are exposed as `guardianwaf_tracing_enabled`,
`guardianwaf_tracing_spans_created_total`,
`guardianwaf_tracing_spans_exported_total`, and
`guardianwaf_tracing_spans_dropped_total`.

## References

- ADR 0001: Zero External Dependencies
- ADR 0009: OpenTelemetry Integration (original design, deferred)
- `internal/tracing/tracing.go` — Implementation
- `internal/engine/context.go` — `TraceSpan` field
