# ADR 0029: Rate Limiting with Token Bucket

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

Rate limiting is essential to protect backend services from:
- **Volumetric DoS** — a single IP flooding a resource
- **Credential brute force** — rapid login attempts (handled more specifically by ATO layer, but rate limiting provides a first defence)
- **API abuse** — excessive API calls by scrapers or misbehaving clients
- **Scraping** — high-rate read traffic that harms backend performance

The rate limiter must:
- Support per-IP and per-IP+path scopes
- Support burst allowances (e.g., 100 req/min average, 20 req burst)
- Scale to hundreds of thousands of concurrent tracked keys (one per active IP or IP+path pair) without lock contention
- Automatically ban repeat violators to reduce overhead of re-checking

Alternative algorithms considered:

| Algorithm | Pros | Cons |
|-----------|------|------|
| Fixed window counter | Simple, O(1) | Burst at window boundary (2× limit possible) |
| Sliding window log | Accurate | O(n) memory per client |
| Sliding window counter | Accurate, O(1) | Slightly complex |
| **Token bucket** | Smooth burst control, O(1) | Slightly harder to explain to users |
| Leaky bucket | Strict output rate | No burst; harsh for legitimate spikes |

**Token bucket** was selected: it allows natural bursting while enforcing a long-term average rate, is O(1) per check, and is the industry standard (used by nginx, Envoy, AWS API Gateway).

## Decision

Implement token bucket rate limiting (`internal/layers/ratelimit/`) where:

1. Each unique **key** (IP or IP+path) has its own bucket
2. Buckets are stored in a `sync.Map` for lock-free concurrent access
3. Tokens refill continuously (approximated lazily at check time)
4. Violations trigger configurable actions (block, log, auto-ban)

### Token Bucket Algorithm

```
Bucket state: { tokens float64, last_refill time.Time }

On request:
  elapsed = now - last_refill
  tokens  = min(tokens + elapsed * (limit / window), burst)
  last_refill = now

  if tokens >= 1.0:
    tokens -= 1.0
    → PASS
  else:
    → violation
```

`last_refill` and `tokens` are stored together in a single `uint64` using bit-packing to enable atomic compare-and-swap — no per-bucket mutex is needed.

### Bucket Lifecycle

Buckets are created lazily on first request from a key. A background goroutine sweeps the `sync.Map` every `window` duration and removes buckets that have not been accessed in the last 2× window. This bounds memory: a bucket for an IP that stopped sending requests is freed within 2 windows.

The hard cap `maxBuckets = 500,000` prevents memory exhaustion under a coordinated attack that rotates IPs rapidly. When the cap is reached, new keys are rejected with a score increment (not a hard block) — the WAF degrades gracefully.

### Rule Matching

Multiple rules can be active simultaneously. Rules are evaluated in definition order; the first matching rule applies:

```yaml
rate_limit:
  rules:
    - id: login_brute
      scope: ip+path
      paths: ["/api/login", "/api/auth/*"]
      limit: 10
      window: 1m
      burst: 5
      action: block
      auto_ban_after: 3      # Auto-ban IP after 3 violations

    - id: api_global
      scope: ip
      paths: []              # All paths
      limit: 1000
      window: 1m
      burst: 200
      action: log            # Log only, no block

    - id: search_scraper
      scope: ip+path
      paths: ["/search", "/api/products"]
      limit: 60
      window: 1m
      burst: 20
      action: block
```

**Path matching** uses glob patterns: `*` matches a single segment, `**` matches any number of segments. Patterns are compiled at startup.

### Auto-Ban Integration

When a key accumulates `auto_ban_after` violations on a rule, the rate limiter calls `OnAutoBan(ip, reason)` — the callback wired to the IP ACL layer's `AddAutoBan`. The violating IP is then blocked at Order 100 on all subsequent requests, eliminating the overhead of running rate limit checks for a known-bad source.

### Per-Tenant Rules

Each tenant can define additional rate limit rules via the dashboard. Tenant rules are stored in `RequestContext.TenantWAFConfig.RateLimit.Rules` and evaluated after global rules. Tenant rules cannot relax global limits (a global block takes precedence).

### Configuration

```yaml
rate_limit:
  enabled: true
  rules:
    - id: default_ip
      scope: ip
      limit: 10000
      window: 1m
      burst: 1000
      action: log

    - id: login_protection
      scope: ip+path
      paths: ["/*/login", "/*/auth", "/*/signin"]
      limit: 20
      window: 5m
      burst: 5
      action: block
      auto_ban_after: 5
```

### Metrics

```
gwaf_ratelimit_allowed_total{rule_id}
gwaf_ratelimit_blocked_total{rule_id}
gwaf_ratelimit_autobans_total{rule_id}
gwaf_ratelimit_buckets_active
gwaf_ratelimit_buckets_evicted_total
```

## Consequences

### Positive
- Token bucket with atomic CAS provides per-key rate limiting with no mutex contention
- `sync.Map` is optimized for high-read, low-write workloads — exactly the rate check pattern
- Auto-ban integration offloads repeat offenders to the IP ACL layer (O(1) hash lookup vs. O(rules) rule scan)
- Hard bucket cap prevents memory exhaustion under IP-rotation attacks

### Negative
- Lazy token refill uses wall-clock time — system clock adjustments (NTP corrections, DST) can cause brief rate limit inaccuracies
- `sync.Map` has higher per-read overhead than a plain `map` with `RWMutex` at low concurrency; the tradeoff pays off at >8 concurrent goroutines
- Rate limits are per-node; in a cluster without shared state (ADR 0023), a distributed attacker sending 1 req/node stays under single-node limits (mitigated by integrating with Raft-replicated counters)
- Path glob matching at rule evaluation time adds O(rules × path_length) overhead per request; keep the rule list short

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/ratelimit/bucket.go` | Token bucket state, atomic CAS refill |
| `internal/layers/ratelimit/ratelimit.go` | Layer, rule matching, auto-ban callback |
| `internal/config/config.go` | `RateLimitConfig` struct |

## References

- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [nginx limit_req_zone](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
- [ADR 0028: IP ACL with Radix Tree](./0028-ip-acl-radix-tree.md)
- [ADR 0023: High Availability / Raft](./0023-high-availability-raft.md)
