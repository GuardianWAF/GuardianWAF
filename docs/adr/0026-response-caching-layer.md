# ADR 0026: Response Caching Layer

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF operates as a reverse proxy in front of backend application servers. Every request that passes WAF checks is forwarded to the backend, which incurs:
- Network round-trip latency (typically 5–50ms)
- Backend CPU/memory for request processing
- Database load for dynamic content generation

For public-facing content that is identical across users (marketing pages, product listings, public API responses), this backend load is unnecessary — the response can be served from a cache on subsequent requests.

WAF vendors like Imperva, AWS WAF, and CloudFlare bundle CDN/caching functionality alongside WAF checks. Users currently must deploy a separate caching layer (Varnish, Nginx proxy_cache, Redis) in front of or behind GuardianWAF, adding operational complexity. An integrated cache reduces architecture complexity and eliminates the extra network hop to a separate cache tier.

## Decision

Implement a response caching layer (`internal/layers/cache/`) that:

1. Caches backend responses in memory or Redis
2. Respects HTTP caching semantics (Cache-Control, Vary, ETag)
3. Supports stale-while-revalidate for zero-latency cache refreshes
4. Isolates cache namespaces per tenant

### Cache Key

The cache key encodes all dimensions that determine response uniqueness:

```
{tenant_id}:{method}:{host}:{path}:{query}
```

Query parameters are sorted before hashing to normalize `?a=1&b=2` and `?b=2&a=1` to the same key. The `Vary` response header extends the key: if the backend returns `Vary: Accept-Encoding`, the `Accept-Encoding` request header value is appended to the key.

Authenticated responses (requests with a `session`, `auth`, or `Authorization` header in the `skip_cookies`/`skip_headers` list) are never cached — the presence of these signals bypasses the layer entirely.

### Cache Eligibility

A response is cacheable only if:

| Condition | Detail |
|-----------|--------|
| Method is `GET` or `HEAD` | POST/PUT/DELETE responses are never cached |
| Status code in `cache_status` | Defaults: 200, 301, 302, 404 |
| No `Set-Cookie` header | Personalized responses must not be cached |
| No `Authorization` in request | Authenticated content is excluded |
| No `Cache-Control: no-store` in response | Respect backend opt-out |
| Path not in `skip_paths` | Operator-defined exclusions |

### Backends

**Memory backend** (`internal/layers/cache/memory.go`)

An in-process LRU cache with a configurable maximum size (default 100MB). Cache entries are serialized to JSON (`CachedResponse` struct containing status code, headers, and body bytes). The LRU eviction policy removes the least recently used entries when the size limit is reached.

The memory backend is zero-latency (in-process) but:
- Does not survive GuardianWAF restarts
- Is not shared across cluster nodes (each node has its own cache)
- Is bounded by the process's memory limit

**Redis backend** (`internal/layers/cache/redis.go`)

A Redis-backed cache using `SETEX` for TTL-aware storage. The response is serialized to JSON and stored with the cache key as the Redis key and `prefix:` namespace prepended.

The Redis backend:
- Survives restarts (responses are persisted in Redis)
- Is shared across cluster nodes (cache miss on one node may be a hit on another)
- Requires an external Redis instance (accepted as an optional operational dependency, unlike the Raft consensus case in ADR 0023 where Redis was rejected as required infrastructure)

**Backend selection** is a configuration choice:

```yaml
cache:
  backend: memory    # "memory" (default) | "redis"
```

### Stale-While-Revalidate

When `stale_while_revalidate: true`, the cache serves the stale response immediately while triggering a background refresh:

```
Request arrives → Cache hit (stale)
                    │
                    ├─ Serve stale response immediately (0ms extra latency)
                    │
                    └─ Background goroutine fetches fresh response from backend
                         │
                         └─ On success: update cache entry
                            On failure: keep serving stale (until absolute TTL expiry)
```

Background refreshes are deduplicated — only one goroutine refreshes a given key at a time (using a `singleflight`-style mutex per key). This prevents thundering herd when a popular cached resource expires.

### Cache Invalidation

Manual invalidation via dashboard or API:

```
DELETE /api/v1/cache/key?path=/product/123&host=example.com    # Single key
DELETE /api/v1/cache/all                                        # Flush all (admin only)
DELETE /api/v1/cache/path?prefix=/products/                    # Prefix-based purge
```

For Redis backend, prefix-based purge uses Redis `SCAN` + `DEL` to avoid blocking the server with `KEYS *`.

Automatic invalidation:
- `Cache-Control: max-age=N` sets TTL to min(configured_ttl, max-age)
- `Expires` header sets absolute expiry
- Cache busting: requests with `Cache-Control: no-cache` bypass the cache and trigger a fresh fetch (but the fresh response is still cached)

### Metrics

```
gwaf_cache_hits_total{backend, tenant}
gwaf_cache_misses_total{backend, tenant}
gwaf_cache_evictions_total{backend}
gwaf_cache_size_bytes{backend}
gwaf_cache_entries_total{backend}
gwaf_cache_stale_revalidations_total
```

### Configuration

```yaml
cache:
  enabled: false                 # Off by default
  backend: memory                # memory | redis
  ttl: 5m
  max_size: 100                  # MB (memory backend only)

  redis_addr: "redis.internal:6379"
  redis_password: "${REDIS_PASS}"
  redis_db: 2
  prefix: "gwaf:cache"

  cache_methods: [GET, HEAD]
  cache_status: [200, 301, 302, 404]

  skip_paths:
    - /api/login
    - /api/logout
    - /healthz
    - /gwaf/*

  skip_cookies: [session, auth, sid]

  stale_while_revalidate: false

  per_tenant: true               # Namespace cache per tenant_id
```

## Consequences

### Positive
- Eliminates a separate caching tier (Varnish/Nginx) for many deployments
- Redis backend enables cache sharing across cluster nodes — reduces backend load proportionally to cluster size
- Stale-while-revalidate delivers cached responses with zero extra latency even during cache refresh
- Cache metrics are integrated into the existing Prometheus exporter

### Negative
- Memory backend is not shared across nodes — in a 3-node cluster, popular content may be cached 3 times consuming 3× the memory
- Redis backend reintroduces an external dependency for caching (acceptable as optional; not required for WAF correctness)
- Incorrect `skip_cookies` configuration can cause authenticated responses to be cached and served to wrong users — a security misconfiguration with serious implications
- `Cache-Control: no-store` on the response is respected, but `Cache-Control: no-store` on the request is not — this is a deliberate simplification (backend has authority over cacheability, not the client)

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/cache/cache.go` | `Backend` interface, `Cache` wrapper, configuration |
| `internal/layers/cache/memory.go` | In-process LRU cache backend |
| `internal/layers/cache/redis.go` | Redis backend |
| `internal/layers/cache/layer.go` | WAF pipeline layer — eligibility checks, key computation, hit/miss logic |

## References

- [RFC 9111: HTTP Caching](https://datatracker.ietf.org/doc/html/rfc9111)
- [RFC 5861: HTTP Cache-Control Extensions (stale-while-revalidate)](https://datatracker.ietf.org/doc/html/rfc5861)
- [Varnish Cache](https://varnish-cache.org/docs/)
- [ADR 0023: High Availability with Raft](./0023-high-availability-raft.md)
- [ADR 0013: Multi-Region Support](./0013-multi-region-support.md)
