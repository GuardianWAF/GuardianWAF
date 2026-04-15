# ADR 0006: Multi-Tenant Isolation

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF supports multi-tenant deployments where different organizations (tenants) share the same WAF instance and binary but maintain isolated configurations and billing. Each tenant has:

- **Own domain(s)** — `tenant-a.example.com`, `tenant-b.example.com`
- **Own WAF config overrides** — different block thresholds, custom rules, detector settings
- **Own rate limits** — independent rate tracking per tenant
- **Own alerting** — separate webhook and email targets per tenant
- **Own billing records** — per-tenant usage tracking

Tenant isolation must be **race-free** under high concurrency. When two tenants' requests are being processed simultaneously by different goroutines, one goroutine must never observe another tenant's configuration or rate limit state. Shared mutable state accessed without synchronization is a data race; shared mutable state accessed with a single global lock is a bottleneck.

## Decision

Each request carries its tenant context in `RequestContext.TenantWAFConfig`. Layers read this field directly — no shared map lookup, no lock acquisition per request.

### Tenant Resolution

At request entry, the WAF resolves the tenant from the `Host` header using a pre-built domain→tenant map:

```go
// VirtualHostConfig maps a domain (Host header value) to a WAF config override.
// Loaded at startup and on config hot-reload.
type VirtualHostConfig struct {
    Domain    string     `yaml:"domain"`     // e.g., "tenant-a.example.com"
    TenantID  string     `yaml:"tenant_id"`  // e.g., "tenant_a"
    WAF       *WAFConfig `yaml:"waf"`        // per-tenant override (nil = use global)
}
```

The config loader builds a `domainMap map[string]*VirtualHostConfig` at startup. Resolution is `O(1)` map lookup per request:

```go
// ResolveTenant returns the TenantWAFConfig for the given Host header.
// Returns nil if no tenant is found (single-tenant / global mode).
func (c *Config) ResolveTenant(host string) *WAFConfig {
    if vh, ok := c.domainMap[host]; ok {
        return vh.WAF
    }
    // Check wildcard patterns (e.g., "*.example.com")
    for _, vh := range c.virtualHosts {
        if matchWildcard(host, vh.Domain) {
            return vh.WAF
        }
    }
    return nil // global defaults
}
```

The resolved `TenantWAFConfig` is stored directly in `RequestContext.TenantWAFConfig` before any layer runs. From that point on, layers read `ctx.TenantWAFConfig` — no map lookup, no lock, no shared state.

### Race-Free Per-Request Config

```go
type RequestContext struct {
    // TenantID is set once at request entry and never modified.
    TenantID string

    // TenantWAFConfig is the resolved per-tenant config override.
    // Each layer reads this directly — no synchronization needed.
    // nil means no tenant override; use global defaults.
    TenantWAFConfig *WAFConfig

    // ... other fields
}
```

Because each `RequestContext` is allocated from a `sync.Pool` and is never shared between goroutines (one context per request, returned to the pool after the request completes), reading `ctx.TenantWAFConfig` inside a layer is inherently race-free.

### Configuration Priority (with Tenant Override)

```
Global defaults
    ↓
YAML config (global)
    ↓
Tenant WAFConfig override (from VirtualHostConfig[tenant].WAF)
    ↓
Environment variables (GWAF_*)
    ↓
CLI flags
```

For a tenant with `TenantWAFConfig.BlockThreshold = 40`, the global `BlockThreshold = 50` is replaced entirely — not merged. The tenant override replaces the global value.

### Billing Isolation

Rate counters and event counters are namespaced by `TenantID`:

```go
// In the rate limit layer:
func (r *RateLimitRule) Allow(ctx *engine.RequestContext) bool {
    key := ctx.TenantID + ":" + ctx.ClientIP.String() + ":" + r.Scope
    // ^^^^^^^^ — namespaced per tenant; no cross-tenant contamination
    return r.bucket.Allow()
}
```

### Hot-Reload Behavior

When the operator reloads the config via SIGHUP or the dashboard:

1. The new config is loaded into a temporary `Config` struct
2. A new `domainMap` is built from the new config
3. `domainMap` is atomically swapped into the engine's field
4. In-flight requests continue with the old `domainMap` (safe, they complete)
5. New requests use the new `domainMap`

The swap is a single atomic pointer assignment — no locking required for read paths.

## Consequences

### Positive

- **Race-free by design** — `ctx.TenantWAFConfig` is per-request memory; no shared map lookup or lock acquisition in the hot path
- **Zero overhead for single-tenant** — when no virtual host matches, `TenantWAFConfig` is `nil`; layers check `if ctx.TenantWAFConfig == nil` once and skip tenant-specific logic
- **Hot-reload without lock** — the atomic pointer swap pattern means reload does not block request processing
- **Layers are tenant-agnostic** — a layer does `ctx.TenantWAFConfig.BlockThreshold` without caring whether it is the global value or a tenant override; no `if tenant != nil` branching within layer logic
- **Independent scaling** — per-tenant rate limits, rules, and alerts are isolated by key namespacing; no noisy-neighbor effect from shared counters

### Negative

- **Memory proportional to concurrency × tenants** — each concurrent request holds its own `TenantWAFConfig` pointer; in a 10,000-concurrent-request scenario with 100 tenants, memory usage reflects 10,000 pointers (negligible; a pointer is 8 bytes)
- **Tenant lookup on every request** — `O(1)` map lookup is fast but not free; mitigated by a domain name cache that avoids repeated lookups for the same `Host` header value within a time window
- **Eventually consistent config reloads** — in-flight requests use the config that was active when they started; a new tenant added via reload will not protect in-flight requests for that tenant's domain until the next request arrives

### Comparison: Per-Tenant Pipeline vs Per-Request Config

| Approach | Memory | Hot-Reload | Complexity |
|----------|--------|------------|------------|
| Per-tenant pipeline instances | High (N pipelines × M layers) | Reject all, rebuild all | High — must coordinate state across instances |
| Global map + per-request lookup | Low — one map, O(1) lookup | Single lock or atomic swap | Medium — shared map access |
| Per-request config via context (GuardianWAF) | Low — pointer per request | Atomic swap, no lock | Low — no shared mutable state |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/engine/context.go` | `RequestContext.TenantID`, `RequestContext.TenantWAFConfig` |
| `internal/config/config.go` | `VirtualHostConfig`, `TenantWAFConfig` structs |
| `internal/config/findvh_test.go` | Virtual host → tenant resolution tests |
| `internal/tenant/manager.go` | Tenant registry, billing, rate tracking per tenant |
| `internal/engine/engine.go` | Tenant resolution at request entry (called once per request) |
| `internal/layers/ratelimit/ratelimit.go` | Per-tenant rate limit bucket namespacing (`tenantID:key`) |
| `internal/layers/ipacl/ipacl.go` | Per-tenant IP ban list namespacing |

## References

- [ADR 0004: Pipeline Architecture](./0004-pipeline-architecture.md)
- [OWASP WAF Taxonomy: Multi-Tenant WAF Deployments](https://owasp.org/www-project-web-security-testing-guide/)
