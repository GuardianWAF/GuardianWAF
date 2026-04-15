# ADR 0035: WebSocket Proxy

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

WebSocket connections begin as HTTP/1.1 with an `Upgrade: websocket` handshake and then switch to a persistent bidirectional binary framing protocol. GuardianWAF's reverse proxy must handle this transparently:

- The proxy must forward the `Upgrade` and `Connection` headers unchanged
- After the upgrade, the connection is no longer HTTP — WAF layers that inspect HTTP request/response fields do not apply to subsequent frames
- Security controls (origin validation, message rate limiting, message size limits) must be applied at the WebSocket layer specifically

Without WebSocket support, GuardianWAF would return 400 or drop WebSocket connections, breaking real-time applications (chat, notifications, live dashboards).

## Decision

Implement a WebSocket proxy layer (`internal/layers/websocket/`) that:

1. **Detects WebSocket upgrades** — `Upgrade: websocket` header present
2. **Validates the handshake** — origin check, protocol negotiation, key verification
3. **Proxies frames bidirectionally** — transparent copy-loop between client and backend
4. **Enforces security limits** — max message size, max frame rate, per-connection idle timeout

### Handshake Validation

Before upgrading, the layer validates:

| Check | RFC | Behaviour on Failure |
|-------|-----|---------------------|
| `Upgrade: websocket` present | RFC 6455 §4.1 | Skip layer (not a WS request) |
| `Connection: Upgrade` present | RFC 6455 §4.1 | 400 Bad Request |
| `Sec-WebSocket-Key` present and valid (base64, 16 bytes) | RFC 6455 §4.1 | 400 |
| `Sec-WebSocket-Version: 13` | RFC 6455 §4.1 | 426 Upgrade Required |
| Origin allowed (if configured) | App policy | 403 Forbidden |

The `Sec-WebSocket-Accept` response header is computed as:
```
base64(SHA-1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

This is implemented in pure Go (`crypto/sha1`, `encoding/base64`) with no external dependency.

### Bidirectional Proxy Loop

After a successful upgrade, two goroutines copy frames:

```
Client ──── frames ────→ GuardianWAF ──── frames ────→ Backend
Client ←─── frames ──── GuardianWAF ←─── frames ──── Backend
```

Each goroutine uses `io.Copy` with a pre-allocated buffer (reused via `sync.Pool`). The connection is closed when either side closes or an idle timeout fires.

**Frame inspection** is optional. When enabled, the layer reads frame headers to:
- Enforce `max_message_size` — close with code 1009 (message too big) if exceeded
- Detect text frames containing known attack patterns (configurable regex list)
- Count frame rate and close with 1008 (policy violation) if exceeded

Full frame payload inspection is not performed by default because:
- WebSocket messages may be fragmented across multiple frames
- Many WebSocket applications use binary protocols (not inspectable without schema)
- The overhead of reassembling and inspecting every frame would add unacceptable latency to real-time applications

### Origin Validation

If `allowed_origins` is configured, the `Origin` header of the handshake request is validated against the same wildcard-regex matching used by the CORS layer (ADR 0031). An upgrade request from a disallowed origin is rejected with 403 before the upgrade is processed.

### Configuration

```yaml
websocket:
  enabled: true
  allowed_origins:
    - "https://app.example.com"
    - "https://*.example.com"

  limits:
    max_message_size: 65536      # 64KB per message
    max_frame_rate: 100          # Max frames/second per connection
    idle_timeout: 5m             # Close if no frames for this duration
    handshake_timeout: 10s

  inspect:
    enabled: false               # Frame payload inspection (opt-in)
    patterns: []                 # Regex list applied to text frame content

  proxy:
    buffer_size: 4096            # Copy buffer size (bytes)
    dial_timeout: 10s
```

### Metrics

```
gwaf_websocket_connections_active
gwaf_websocket_connections_total
gwaf_websocket_upgrades_rejected_total{reason}
gwaf_websocket_messages_total{direction}
gwaf_websocket_bytes_total{direction}
gwaf_websocket_closed_total{code}
```

## Consequences

### Positive
- WebSocket connections are handled transparently — existing WAF rules (applied during the HTTP handshake) still protect the initial connection
- Frame rate and size limits prevent WebSocket-based DoS (message flooding, oversized payload)
- Origin validation reuses CORS layer logic — consistent policy across HTTP and WebSocket

### Negative
- After the upgrade, WAF detection layers do not inspect frame content (by default) — a SQL injection payload sent over WebSocket frames is not detected unless `inspect.enabled: true`
- Frame inspection requires message reassembly for fragmented messages, which buffers content in memory; large fragmented messages can exhaust memory if `max_message_size` is not set
- WebSocket connections are long-lived; a single attacker connection consumes a goroutine pair and file descriptors for its duration — resource exhaustion requires connection count limits at the proxy level

## Implementation Locations

**Note**: `internal/layers/websocket/` package exists. The layer is not yet registered in the
main engine pipeline (`main.go`/`guardianwaf.go`). `Order 76` is not defined in
`internal/engine/layer.go`. Registration in the pipeline is pending.

| File | Purpose |
|------|---------|
| `internal/layers/websocket/websocket.go` | Handshake validation, `Sec-WebSocket-Accept` computation |
| `internal/layers/websocket/handler.go` | Bidirectional proxy loop, frame inspection |
| `internal/layers/websocket/layer.go` | WAF pipeline layer integration |
| `internal/config/config.go` | `WebSocketConfig` struct |

## References

- [RFC 6455: The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [ADR 0031: CORS Validation Layer](./0031-cors-layer.md)
