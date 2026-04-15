# ADR 0017: API Discovery & Schema Validation

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF proxies HTTP traffic but has no awareness of the API surface it is protecting. This creates several gaps:

- **Shadow APIs** — endpoints that exist in the backend but are unknown to the security team receive no extra scrutiny
- **Schema drift** — if a backend changes its API without updating WAF rules, malformed or malicious requests may slip through parameter validation
- **Manual rule burden** — operators must hand-craft parameter validation rules; there is no automatic derivation from actual traffic or an OpenAPI spec

Signal Sciences and AWS WAF both offer passive API discovery. Adding this capability closes a meaningful feature gap and enables automatic schema-based blocking without custom rule writing.

## Decision

Implement a two-phase API intelligence system:

1. **Passive API Discovery** — background traffic analysis to build an inventory of observed endpoints
2. **Schema Validation** — active request/response validation against OpenAPI 3.0 schemas (imported or auto-generated from discovery)

### Phase 1: Passive Discovery

A background goroutine reads from a bounded channel fed by the response layer. For each completed request it records:

```go
type ObservedEndpoint struct {
    Method          string
    PathTemplate    string            // /users/{id} — inferred by clustering
    StatusCodes     map[int]uint64    // 200→1500, 404→12
    ContentTypes    map[string]uint64
    AvgBodyBytes    float64
    ParamNames      []string          // Query params seen
    HeadersPresent  []string
    FirstSeen       time.Time
    LastSeen        time.Time
    RequestCount    uint64
}
```

**Path clustering** merges `/users/123` and `/users/456` into `/users/{id}` using a simple heuristic:
- Segment is numeric → replace with `{id}`
- Segment is a UUID → replace with `{uuid}`
- Segment appears in <5% of paths at that position → treat as variable `{param}`

The inventory is persisted as `api_inventory/endpoints.json` and exposed via the dashboard API.

### Phase 2: Schema Validation (Layer 280 — existing `apivalidation`)

Schema sources (priority order):

| Source | How loaded |
|--------|------------|
| Manual upload | Dashboard / `PUT /api/v1/schemas/{name}` |
| Auto-generated from discovery | `POST /api/v1/schemas/generate` |
| OpenAPI 3.0 import | Dashboard upload or `--openapi` flag |

Validation checks per request:
- Path matches a known route (configurable: warn vs. block for unknown paths)
- HTTP method allowed for that route
- Required query parameters present
- Request body matches JSON Schema (type, format, required fields)
- Response body matches schema (in monitoring mode — never blocks)

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Request Flow                               │
│                                                               │
│  [Layer 280 - APIValidation]                                  │
│       │                                                       │
│       ├─ Schema exists?                                       │
│       │     Yes → validate → Finding if violation             │
│       │     No  → pass (optionally log as "unvalidated")      │
│       │                                                       │
│  [Response Layer 600]                                         │
│       │                                                       │
│       └──→  Discovery channel (non-blocking send)            │
│                  │                                            │
│             ┌────▼──────────────────────┐                    │
│             │  Discovery Worker (async) │                    │
│             │  - Cluster path template  │                    │
│             │  - Update inventory       │                    │
│             │  - Persist to JSON        │                    │
│             └───────────────────────────┘                    │
└──────────────────────────────────────────────────────────────┘
```

### Configuration

```yaml
api_discovery:
  enabled: true
  sample_rate: 1.0               # Analyze every response (1.0 = 100%)
  path_clustering:
    numeric_segments: true       # /users/123 → /users/{id}
    uuid_segments: true
    variable_threshold: 0.05     # Segment seen in <5% of paths → variable
  persist_path: api_inventory/

api_validation:
  enabled: true
  schema_dir: /etc/guardianwaf/schemas/
  unknown_path_action: log       # log | block | pass
  unknown_method_action: block
  body_validation: true
  response_validation: false     # Monitoring only, never blocks
  score_on_violation: 30         # Score added per violation (not automatic block)
```

### Dashboard Integration

- **API Inventory page** — table of discovered endpoints with traffic stats, schema coverage badge
- **Schema editor** — upload/edit OpenAPI YAML, diff view against discovered traffic
- **Coverage heatmap** — which endpoints have schema coverage, which are unvalidated
- **Anomaly alerts** — endpoints receiving traffic outside normal parameter patterns

### OpenAPI Import/Export

```bash
# Import existing OpenAPI spec
guardianwaf validate --openapi ./api.yaml

# Export discovered inventory as OpenAPI
GET /api/v1/schemas/export?format=openapi3
```

The exported spec uses `x-guardian-*` extensions to carry traffic statistics.

## Consequences

### Positive
- Shadow API detection without any manual configuration
- Automatic schema generation reduces operator burden
- Schema violations produce structured `Finding` entries, feeding existing scoring and alerting
- OpenAPI import/export integrates with existing API design tooling

### Negative
- Discovery worker adds CPU and memory overhead proportional to API surface size
- Path clustering heuristics produce false path templates for non-REST APIs (e.g., `/cmd/ls` clustered with `/cmd/pwd`)
- Schema validation requires keeping schemas synchronized with backend deployments — stale schemas cause false positives
- Response body validation (even monitoring-only) doubles the amount of body buffering

## Implementation Locations

**Note**: API Validation layer exists at `internal/layers/apivalidation/` with `layer.go`, `schema.go`, `yaml.go`.
Discovery is being built at `internal/discovery/` (analyzer, clustering, collector, engine, manager, schema, storage).

| File | Purpose |
|------|---------|
| `internal/layers/apivalidation/validator.go` | JSON Schema validation against `RequestContext` (planned) |
| `internal/layers/apivalidation/openapi.go` | OpenAPI 3.0 parser and schema loader (planned) |
| `internal/discovery/worker.go` | Background discovery goroutine (planned) |
| `internal/discovery/cluster.go` | Path template clustering (planned) |
| `internal/discovery/inventory.go` | Endpoint inventory store (JSON-backed) (planned) |
| `internal/dashboard/api_inventory.go` | REST handlers for inventory and schema CRUD |

## References

- [OpenAPI 3.0 Specification](https://spec.openapis.org/oas/v3.0.3)
- [JSON Schema Validation](https://json-schema.org/draft/2020-12)
- [Signal Sciences API Discovery](https://docs.signalsciences.net/using-signal-sciences/features/api-discovery/)
- [GuardianWAF API Validation Layer](../ARCHITECTURE.md#layer-order)
- [ADR 0010: Dynamic Rules API](./0010-dynamic-rules-api.md)
