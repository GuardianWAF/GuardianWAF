# ADR 0036: Canary Deployment Layer

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Canary deployments route a small percentage of live traffic to a new backend version while the majority continues to hit the stable version. This enables:

- **Risk-reduced rollouts** — a bug in the new version affects only the canary percentage
- **Real traffic testing** — synthetic tests cannot reproduce all production traffic patterns
- **Gradual confidence** — the canary percentage can be increased as metrics validate the new version

Traditional canary setups require changes to the load balancer configuration (nginx, HAProxy, AWS ALB weighted target groups). GuardianWAF sits in front of the load balancer and can implement canary routing transparently at the WAF layer, requiring no changes to backend infrastructure.

The canary layer runs at **Order 95** — before the IP ACL (100) — so that canary routing decisions are made before any other layer can short-circuit the request. This ensures the canary percentage is applied to all traffic, including from IPs that might be blocked later.

## Decision

Implement a canary layer (`internal/layers/canary/`, Order 95) that:

1. Routes a configurable **percentage** of requests to a "canary" upstream
2. Supports **sticky sessions** — a client assigned to canary always hits canary (cookie-based)
3. Provides **header-based override** — operators can force canary with `X-Canary: true`
4. Compares **response codes** between canary and stable to detect regressions

### Traffic Splitting

The layer uses a deterministic hash of the client IP (and optionally a session cookie value) to assign traffic consistently:

```go
hash = fnv32a(ip + session_cookie)
if hash % 100 < canary_percentage {
    → route to canary upstream
} else {
    → route to stable upstream
}
```

FNV-32a is chosen for its speed and distribution properties. The hash is deterministic — the same client IP always maps to the same bucket, ensuring sticky routing without explicit session tracking (until the canary percentage changes).

When `sticky: true`, the assignment is written to a cookie (`gwaf-canary=1` or `gwaf-canary=0`) on the first request. Subsequent requests read the cookie value, bypassing the hash computation.

### Header Override

Operators and automated test suites can bypass percentage-based routing:

```
X-Canary: true   → force canary upstream
X-Canary: false  → force stable upstream
```

The `X-Canary` header is stripped before forwarding to the backend (to prevent clients from self-routing).

### Shadow Mode

In shadow mode, all traffic goes to the stable upstream **and** a copy is simultaneously sent to the canary upstream. Canary responses are discarded — only metrics and logs are collected. This enables regression testing with zero user impact:

```yaml
canary:
  mode: shadow    # "split" (default) | "shadow"
```

Shadow mode doubles the backend load on the canary upstream but is the safest way to validate a new version.

### Response Comparison (Split Mode)

When `compare_responses: true`, the layer logs the HTTP status code of both the canary and stable response for the same request bucket. Divergence (stable returns 200, canary returns 500) is emitted as a WAF event of type `canary_regression` and increments `gwaf_canary_divergences_total`.

Full response body comparison is not implemented — it would require the layer to buffer and diff potentially large response bodies, adding latency and memory pressure.

### Configuration

```yaml
canary:
  enabled: false
  canary_upstream: "canary-v2"     # Upstream name in proxy config
  stable_upstream: "prod-v1"

  mode: split                      # split | shadow
  percentage: 5                    # % of traffic to canary (0-100)

  sticky:
    enabled: true
    cookie_name: gwaf-canary
    cookie_ttl: 24h

  header_override:
    enabled: true
    header: X-Canary

  compare_responses: true
  regression_alert_threshold: 1    # Alert after N divergences per minute
```

### Rollout Workflow

```
1. Deploy canary backend version
2. Set canary.percentage = 1
3. Monitor gwaf_canary_divergences_total and canary upstream error rate
4. Increase percentage: 1 → 5 → 20 → 50 → 100
5. When percentage = 100, disable canary layer, make canary the new stable
```

## Consequences

### Positive
- Canary routing at the WAF layer requires no load balancer changes — single configuration point
- Deterministic hash ensures the same client consistently hits the same upstream (no flicker)
- Shadow mode enables zero-risk regression testing with live traffic
- Header override allows QA to test the canary version without affecting production traffic split

### Negative
- Order 95 (before IP ACL) means canary routing runs even for eventually-blocked IPs — wasted canary capacity for malicious traffic; acceptable given the typically small canary percentage
- Sticky cookie requires cookie support — API clients without cookie handling always use the hash-based assignment
- Response comparison only compares status codes; subtle functional regressions (same status, different body) are undetected
- Shadow mode doubles backend load — must ensure the canary upstream is provisioned for 100% traffic before enabling shadow mode

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/canary/canary.go` | Traffic splitting, sticky sessions, shadow mode |
| `internal/layers/canary/layer.go` | WAF pipeline layer (Order 95) |
| `internal/config/config.go` | `CanaryConfig` struct |

## References

- [Martin Fowler: Canary Release](https://martinfowler.com/bliki/CanaryRelease.html)
- [FNV Hash](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function)
- [ADR 0004: Pipeline Architecture](./0004-pipeline-architecture.md)
