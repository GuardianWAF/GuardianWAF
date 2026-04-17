# ADR 0040: Config-Driven Feature Flags

**Date:** 2026-04-17
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF has 29 pipeline layers and growing functionality. Not all features are appropriate for all deployments:

- Enterprise tenants may want ML anomaly detection while smaller deployments do not
- Canary releases of new detection rules need gradual rollout
- Emergency kill switches for individual layers (e.g., disable AI remediation if provider has an outage)
- Per-tenant feature differentiation for billing tiers

Without feature flags, enabling/disabling features requires config changes and restarts, or complex conditional logic scattered across the codebase.

## Decision

Implement a lightweight, config-driven feature flag system (`internal/feature/`):

1. **Global flags** — Set via YAML `features:` map or `GWAF_FEATURE_<NAME>=true` env vars
2. **Per-tenant overrides** — `feature.SetTenant(tenantID, name, enabled)` for tenant-specific toggling
3. **Thread-safe registry** — `sync.RWMutex` protects the flag maps; read-heavy workloads use `RLock`
4. **API surface**:
   - `feature.IsEnabled(name)` — global check
   - `feature.IsEnabledFor(tenantID, name)` — tenant-aware check (tenant override → global fallback)
   - `feature.Set(name, enabled)` / `feature.SetTenant(tenantID, name, enabled)` — runtime updates
   - `feature.LoadFromMap(map)` — bulk load from YAML config
   - `feature.LoadFromEnv()` — scan `GWAF_FEATURE_*` env vars
   - `feature.All()` — return all flags (for dashboard display)

### Key design choices

- **No percentages or rollout rules** — Flags are boolean on/off. Gradual rollout is handled by the canary layer (ADR 0036), not the flag system.
- **No persistence** — Flags are loaded from config on startup and can be toggled at runtime via API. They reset to config defaults on restart.
- **No dependencies** — Pure stdlib, consistent with ADR 0001.

## Consequences

**Positive:**
- Runtime feature toggling without restart
- Per-tenant differentiation for multi-tenant deployments
- Simple boolean model — easy to reason about
- Config-driven — flags can be version-controlled in YAML

**Negative:**
- No gradual rollout (percentage-based) — must use canary layer for that
- No persistence — runtime changes lost on restart (by design; config is source of truth)
- Manual flag name management — no schema validation on flag names

## References

- ADR 0001: Zero External Dependencies
- ADR 0036: Canary Deployments
- ADR 0006: Multi-Tenant Isolation
- `internal/feature/feature.go` — Implementation
