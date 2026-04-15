# ADR 0012: Enhanced GraphQL Protection

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF has a GraphQL protection layer (`internal/layers/graphql/`) but it may need enhancement. Current implementation covers:
- Query depth limiting
- Basic field validation

However, GraphQL APIs face additional attack vectors:
- **Query complexity attacks** — Intentionally complex queries that exhaust server resources
- **Batch query attacks** — Large batches of queries in one request
- **Alias abuse** — Multiple aliases with heavy operations
- **Introspection abuse** — Excessive introspection queries
- **Field suggestion DoS** — Exploiting typo tolerance in fields

## Decision

Enhance GraphQL protection with comprehensive security controls.

### Current Implementation Review

```go
// internal/layers/graphql/graphql.go (existing)
- QueryDepthLimit: max nesting depth
- FieldLimit: max fields per query
```

### Proposed Enhancements

### 1. Query Complexity Analysis

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

### 2. Batch Query Limits

Limit number of operations per request:

```yaml
graphql:
  batch:
    max_operations: 10        # Max operations per request
    max_batch_size: 100kb     # Max total request size
```

### 3. Alias Abuse Prevention

Detect excessive aliases with heavy operations:

```yaml
graphql:
  aliases:
    max_aliases: 15
    max_alias_depth: 5
```

### 4. Introspection Controls

Restrict introspection in production:

```yaml
graphql:
  introspection:
    enabled: false            # Disable in production
    allow_schema: false        # Allow __schema queries
    allow_type: false          # Allow __type queries
```

### 5. Rate Limiting

Apply per-client GraphQL-specific limits:

```yaml
graphql:
  rate_limit:
    queries_per_minute: 60
    mutations_per_minute: 30
    subscriptions_per_minute: 10
```

### 6. Field Suggestion DoS Mitigation

Prevent exploitation of GraphQL's field suggestion (typo tolerance):

```yaml
graphql:
  suggestion:
    enabled: true
    max_suggestions: 3        # Limit typo suggestions
    similarity_threshold: 0.8 # Minimum similarity to suggest
```

### 7. Query Whitelisting

Allow only approved queries (operations) in production:

```yaml
graphql:
  whitelist:
    enabled: false
    operations:
      - "GetUser(id: ID!): User"
      - "ListPosts(limit: Int): [Post]"
      - "CreatePost(input: CreatePostInput!): Post"
```

### Detection Actions

| Threat Type | Action | Score |
|-------------|--------|-------|
| Query too deep | Block | +30 |
| Query too complex | Block | +40 |
| Too many aliases | Block | +25 |
| Introspection in prod | Log/Challegne | +15 |
| Batch size exceeded | Block | +35 |
| Rate limit exceeded | Block | +50 |
| Field suggestion DoS | Block | +30 |

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
| `internal/layers/graphql/complexity.go` | Query complexity analysis |
| `internal/layers/graphql/batch.go` | Batch operation limiting |
| `internal/layers/graphql/alias.go` | Alias abuse detection |
| `internal/layers/graphql/introspection.go` | Introspection controls |
| `internal/layers/graphql/suggestion.go` | Field suggestion DoS |
| `internal/layers/graphql/whitelist.go` | Query whitelisting |

## References

- [GraphQL Security](https://graphql.org/learn/queries/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GuardianWAF GraphQL Layer](../ARCHITECTURE.md#layer-order)
