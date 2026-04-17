# ADR 0042: Correlation ID Propagation

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

In a multi-tier architecture where GuardianWAF sits between clients and backend services, debugging request flow requires a way to correlate:

- The incoming request (seen by the WAF)
- The forwarded request (seen by the backend)
- The WAF event (stored in the ring buffer / dashboard)
- Logs on the WAF node and backend service

Each WAF request already gets a UUID v4 `RequestID`, but this ID is internal to the WAF. Backend services have no way to link their logs to WAF events.

## Decision

Propagate a correlation ID header (`X-Correlation-ID`) through the proxy and across cluster nodes:

1. **Proxy propagation** — In `proxy/target.go`, the Director function sets `X-Correlation-ID` on the forwarded request:
   - If the incoming request already has `X-Correlation-ID`, preserve it (respecting upstream correlation chains)
   - Otherwise, use the WAF's `X-GuardianWAF-RequestID` value (the internal RequestID)
2. **Cluster propagation** — Cluster gossip messages include the correlation ID so that distributed ban events can be traced back to the originating request.
3. **Event linkage** — The WAF event already carries `RequestID`, which matches the `X-Correlation-ID` sent to the backend. Dashboard and API consumers can search events by this ID.

### Why not W3C Trace Context

W3C Trace Context (`traceparent` + `tracestate`) is the standard for distributed tracing. However:

- It requires parsing and generating the `traceparent` header format
- It implies OTel integration (ADR 0039 provides a compatible API but not wire format)
- The simpler `X-Correlation-ID` header is widely supported by backend frameworks (Express, Django, Spring)

The correlation ID approach provides 80% of the debugging value at 20% of the complexity. Full W3C Trace Context can be added later via a bridge exporter (ADR 0039).

## Consequences

**Positive:**
- Backend services can link their logs to WAF events via a shared header
- Preserves existing correlation chains (doesn't overwrite upstream IDs)
- Zero overhead — single header injection in the proxy Director
- Compatible with any backend framework that reads `X-Correlation-ID`

**Negative:**
- Not W3C Trace Context compatible — cannot participate in OTel trace trees without a bridge
- Single string ID — no structured trace context (span ID, sampled flag, etc.)

## References

- ADR 0039: Zero-Dependency Distributed Tracing
- `internal/proxy/target.go` — Director function
- `internal/engine/engine.go` — RequestID generation
