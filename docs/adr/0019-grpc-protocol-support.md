# ADR 0019: gRPC Protocol Support

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF currently supports HTTP/1.1, HTTP/2, HTTP/3, and WebSocket traffic. However, microservice architectures increasingly use **gRPC** — an RPC framework layered on HTTP/2 with Protocol Buffers (protobuf) encoding. gRPC traffic is structurally different from REST:

- Binary framing with length-prefixed protobuf messages (not JSON)
- Method routing via URL path (`/ServiceName/MethodName`) rather than RESTful resources
- Four call types: unary, server-streaming, client-streaming, bidirectional-streaming
- Metadata carried in HTTP/2 headers and trailers, not body

GuardianWAF's existing HTTP/2 proxy forwards gRPC traffic but cannot inspect message content, enforce method-level policies, or detect gRPC-specific abuse patterns (oversized streaming messages, reflection abuse). AWS WAF and F5 both offer gRPC-aware WAF modes.

## Decision

Add a gRPC inspection mode that:

1. **Detects gRPC traffic** automatically via `Content-Type: application/grpc*`
2. **Parses protobuf frames** to extract message size and structure (without requiring `.proto` files)
3. **Enforces method-level policies** (allow/deny list per `ServiceName/MethodName`)
4. **Detects gRPC-specific abuse** (reflection abuse, excessive streaming, oversized messages)
5. **Proxies transparently** — no changes visible to client or server when not blocking

### gRPC Detection & Framing

gRPC uses a 5-byte frame header before each protobuf message:

```
Byte 0:    Compressed flag (0 = uncompressed, 1 = gzip)
Bytes 1-4: Message length (big-endian uint32)
Bytes 5+:  Protobuf payload
```

The gRPC layer reads the body buffer already populated by `RequestContext` (up to `body_limit` bytes) and parses frame headers without decoding protobuf field content. For the purposes of WAF inspection, **field-level content decoding is not required** — message size, field count, and nesting depth are sufficient anomaly signals.

For reflection traffic (`/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`), the response body is decoded to extract exposed service names — these are logged as a `Finding` event without blocking unless reflection is explicitly denied.

### Method-Level Policy

Routes are matched against a method allow/deny list:

```
/ServiceName/MethodName
/ServiceName/*          (all methods on a service)
/*                      (all gRPC traffic)
```

Policy resolution order: explicit deny > explicit allow > default action.

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Request Flow                                │
│                                                               │
│  HTTP/2 Request (Content-Type: application/grpc)             │
│       │                                                       │
│       ▼                                                       │
│  [Layer 275 - API Security]                                   │
│  - gRPC metadata auth (Authorization header)                  │
│  - Service-level JWT / API key enforcement                    │
│       │                                                       │
│       ▼                                                       │
│  [gRPC Inspection Layer — Order 285]                          │
│  - Parse 5-byte frame header                                  │
│  - Enforce method allow/deny list                             │
│  - Check message size limits                                  │
│  - Detect reflection abuse                                    │
│  - Count frames in streaming calls                            │
│       │                                                       │
│       ▼                                                       │
│  [Proxy — transparent HTTP/2 forwarding]                      │
└──────────────────────────────────────────────────────────────┘
```

### Streaming Abuse Detection

For server-streaming and bidirectional calls, GuardianWAF inspects the **first N frames** (configurable) of the request stream. If frame count exceeds `max_streaming_frames` within a time window, the connection is terminated with `RST_STREAM`.

Client streaming inspection is best-effort: the proxy may not buffer all frames if the stream is long-lived; in that case, the policy limits are enforced on the frames received within the `stream_inspect_window`.

### Configuration

```yaml
grpc:
  enabled: true                  # Auto-detected from Content-Type if not set
  order: 285                     # Between APIValidation (280) and Sanitizer (300)

  method_policy:
    default: allow               # allow | block | log
    rules:
      - method: "/grpc.reflection.v1alpha.ServerReflection/*"
        action: block
        reason: "gRPC reflection disabled"
      - method: "/admin.AdminService/*"
        action: allow
        require_auth: true       # Must have valid JWT from APISecurityLayer

  message_limits:
    max_message_bytes: 4194304   # 4MB per message
    max_streaming_frames: 1000   # Per stream, within inspect_window
    stream_inspect_window: 60s

  compression:
    allow_gzip: true
    allow_identity: true

  score_on_violation:
    oversized_message: 40
    reflection_abuse: 25
    denied_method: 75
```

### Metrics

The existing Prometheus exporter gains gRPC-specific counters:

```
gwaf_grpc_requests_total{service, method, action}
gwaf_grpc_message_bytes_total{service, direction}
gwaf_grpc_stream_frames_total{service}
gwaf_grpc_violations_total{violation_type}
```

### Protobuf Schema-Aware Mode (Future)

When `.proto` files are provided, a future enhancement can decode field values for content inspection (SQLi/XSS in string fields). This is opt-in and requires schema registration via the dashboard. It is **out of scope** for this ADR.

## Consequences

### Positive
- gRPC-native WAF inspection without requiring proto schema files
- Method-level allow/deny provides fine-grained access control beyond IP/auth checks
- Reflection abuse is a common reconnaissance technique; blocking it reduces information disclosure
- Transparent proxy mode means zero client changes required

### Negative
- Binary protobuf inspection without schema is limited to structural anomalies; string-level attack detection (SQLi in a proto string field) requires schema-aware mode
- Streaming calls are inspected on a best-effort basis — very long-lived bidirectional streams cannot be fully buffered
- Order 285 places gRPC inspection after APIValidation but before Sanitizer; if a gRPC request somehow passes a custom content-type, it may be processed by the wrong path

## Implementation Locations

**Note**: `internal/layers/grpc/` exists with `layer.go`, `grpc.go`, `handler.go`. Order 285 is planned but not yet defined in `layer.go` and the layer is not registered in the main pipeline. The files below (`frame.go`, `policy.go`, `stream.go`, `reflection.go`) are planned but do not exist yet.

| File | Purpose |
|------|---------|
| `internal/layers/grpc/layer.go` | Pipeline layer (Order 285) (exists — not yet registered in pipeline) |
| `internal/layers/grpc/frame.go` | 5-byte gRPC frame header parser (planned) |
| `internal/layers/grpc/policy.go` | Method allow/deny policy engine (planned) |
| `internal/layers/grpc/stream.go` | Streaming frame counter and limiter (planned) |
| `internal/layers/grpc/reflection.go` | Reflection response decoder (planned) |
| `internal/config/config.go` | `GRPCConfig` struct addition |

## References

- [gRPC Protocol Specification](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
- [Protocol Buffers Encoding](https://protobuf.dev/programming-guides/encoding/)
- [gRPC Security Best Practices](https://grpc.io/docs/guides/security/)
- [GuardianWAF Layer Order](../ARCHITECTURE.md#layer-order)
- [ADR 0012: Enhanced GraphQL Protection](./0012-graphql-protection.md)
