# ADR 0012: Enhanced GraphQL Protection

**Date:** 2026-04-15
**Status:** Implemented
**Deciders:** GuardianWAF Team

---

## Context

GraphQL APIs face unique attack vectors that traditional WAF rules miss:

- **Query complexity attacks** — Intentionally complex queries that exhaust server resources
- **Batch query attacks** — Large batches of queries in one request
- **Alias abuse** — Multiple aliases with heavy operations
- **Introspection abuse** — Excessive introspection queries
- **Field suggestion DoS** — Exploiting typo tolerance in fields
- **Query depth attacks** — Intentionally deep nesting that exhausts resolvers

GuardianWAF's `internal/layers/graphql/` provides foundational GraphQL protection including depth limiting, field validation, and introspection controls.

## Decision

Enhance GraphQL protection with comprehensive security controls.

### Current Implementation (`internal/layers/graphql/`)

The existing layer provides:
- Query depth limiting (`QueryDepthLimit`)
- Field validation (`FieldLimit`)
- Basic introspection controls

### Proposed Enhancements

#### 1. Query Complexity Analysis

Assign complexity scores to fields and reject queries exceeding threshold:

```yaml
graphql:
  complexity:
    enabled: true
    max_complexity: 1000
    field_weights:
      user: 1
      posts: 5
      comments: 3
      friends: 10
      deepNested: 15
```

#### 2. Batch Query Limits

```yaml
graphql:
  batch:
    max_operations: 10        # Max operations per request
    max_batch_size: 100kb     # Max total request size
```

#### 3. Alias Abuse Prevention

```yaml
graphql:
  aliases:
    max_aliases: 15
    max_alias_depth: 5
```

#### 4. Introspection Controls

```yaml
graphql:
  introspection:
    enabled: false            # Disable in production
    allow_schema: false
    allow_type: false
```

#### 5. Rate Limiting

```yaml
graphql:
  rate_limit:
    queries_per_minute: 60
    mutations_per_minute: 30
    subscriptions_per_minute: 10
```

### Detection Actions

| Threat Type | Action | Score |
|-------------|--------|-------|
| Query too deep | Block | +30 |
| Query too complex | Block | +40 |
| Too many aliases | Block | +25 |
| Introspection in prod | Log/Challenge | +15 |
| Batch size exceeded | Block | +35 |
| Rate limit exceeded | Block | +50 |

## Consequences

### Positive

- Comprehensive GraphQL attack surface coverage
- Prevents resource exhaustion attacks
- Production-safe introspection controls
- Query complexity management

### Negative

- Configuration complexity increases
- False positives possible with complex legitimate queries
- Performance overhead for complexity analysis

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/layers/graphql/layer.go` | GraphQL security layer |
| `internal/layers/graphql/parser.go` | GraphQL query parser and validator |
| `internal/layers/graphql/layer_test.go` | Layer tests |

Enhancements (complexity, batch limits, alias abuse) are planned future work — corresponding files do not yet exist.

## References

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security](https://graphql.org/learn/queries/)
