# ADR 0039: Zero-Dependency Distributed Tracing

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Production WAF deployments require visibility into request flow across the 29-layer pipeline. Without tracing:

- Diagnosing false positives requires manually correlating logs with detector scores
- Performance regression in a specific layer is hard to pinpoint from aggregate metrics
- Multi-node cluster deployments have no way to trace a request across nodes

OpenTelemetry is the standard, but importing the Go OTel SDK would violate the zero-dependency constraint (ADR 0001). The full OTel SDK pulls in ~40 transitive dependencies.

## Decision

Implement a minimal, zero-dependency tracing package (`internal/tracing/`) with an OpenTelemetry-compatible API surface:

1. **Span model** — TraceID (128-bit hex), SpanID (64-bit hex), parent-child links, attributes, events
2. **Exporter interface** — `Exporter` interface with `Export(Span)` and `Shutdown()`. Built-in exporters: `NoopExporter`, `StdoutExporter`. Pluggable for OTel bridge or custom backends.
3. **Configurable sampling** — `SamplingRate` (0.0–1.0) determines which traces are kept; `ShouldSample()` uses TraceID for deterministic sampling
4. **Pipeline integration** — Root span created per request in `engine.Check()` and `engine.Middleware()`; `ctx.TraceSpan` on `RequestContext` carries the span through the pipeline
5. **Layer spans** — Each layer can create child spans with WAF-specific attributes (action, score, detector name)
6. **Configuration** — `tracing.enabled`, `tracing.service_name`, `tracing.sampling_rate`, `tracing.exporter_type` in config or `GWAF_TRACING_*` env vars

### Key design choices

- **No wire format** — Spans are exported in-process, not serialized over gRPC/HTTP. A bridge exporter can translate to OTLP if needed.
- **No baggage propagation** — Only `X-Correlation-ID` (not full W3C Trace Context) is propagated to upstream backends and cluster nodes. Full trace context propagation would require a wire format.
- **Sync export** — Exporters are called synchronously on span end. The `StdoutExporter` is for development only; production exporters should be buffered.

## Consequences

**Positive:**
- Full pipeline visibility without any external dependencies
- OpenTelemetry-compatible API means a bridge exporter can forward to Jaeger/Zipkin/Tempo
- Sampling prevents overhead on high-traffic deployments
- Per-layer spans with WAF attributes enable targeted performance analysis

**Negative:**
- Not wire-compatible with W3C Trace Context out of the box (requires bridge exporter)
- No automatic context propagation across HTTP boundaries (only correlation ID header)
- Sync export model may add latency if exporter is slow (mitigated by sampling)

## References

- ADR 0001: Zero External Dependencies
- ADR 0009: OpenTelemetry Integration (original design, deferred)
- `internal/tracing/tracing.go` — Implementation
- `internal/engine/context.go` — `TraceSpan` field
