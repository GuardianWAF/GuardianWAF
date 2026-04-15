# ADR 0015: Distributed Event Store

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF currently supports two event storage modes:
1. **Memory store** — Ring buffer in-process, fastest but not durable
2. **JSONL file store** — Appends to files, durable but single-node

For multi-node deployments, each GuardianWAF instance has its own isolated event store. This means:
- Events are not shared between instances
- No unified event query API across the cluster
- Events from failed nodes may be lost
- No event aggregation for analytics

## Decision

Implement a distributed event store that provides:
1. **Shared event storage** across all cluster nodes
2. **Durable storage** with configurable retention
3. **Unified query API** for events across all nodes
4. **Real-time subscriptions** for dashboard SSE
5. **Aggregation support** for analytics

### Supported Backends

| Backend | Use Case | Durability | Performance |
|---------|----------|------------|-------------|
| Redis | Production | High | ~1ms write |
| PostgreSQL | Enterprise | Highest | ~5ms write |
| S3 | Archival | Highest | ~100ms write |
| In-Memory + Redis | Hybrid | High | ~0.1ms local |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GuardianWAF Nodes                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Node A  │    │  Node B  │    │  Node C  │              │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘              │
│       │               │               │                     │
│       └───────────────┼───────────────┘                     │
│                       │                                      │
│              ┌────────▼────────┐                            │
│              │  Event Store    │                            │
│              │  Adapter        │                            │
│              └────────┬────────┘                            │
│                       │                                      │
│              ┌────────▼────────┐                            │
│              │     Redis       │                            │
│              │  (or Postgres)   │                            │
│              └─────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

### Configuration

```yaml
events:
  store:
    driver: redis              # redis, postgres, s3, memory
    redis:
      endpoints:
        - redis.internal:6379
      password: "${REDIS_PASSWORD}"
      database: 1
      pool_size: 50
      ssl: true

    postgres:
      dsn: "${POSTGRES_DSN}"
      max_conns: 20
      ssl_mode: require

    s3:
      bucket: guardian-events
      region: us-east-1
      prefix: "events/"
      flush_interval: 10s

  retention:
    max_events: 1000000        # Per node, if local cache
    max_age: 30d               # Delete events older than 30 days
    max_size: 10gb             # Max total storage

  aggregation:
    enabled: true
    interval: 1m               # Aggregate every minute
    metrics:
      - requests_per_minute
      - blocks_per_minute
      - top_attack_types
      - top_source_ips
```

### Event Schema

```json
{
  "id": "evt_01HX5K7B...",
  "timestamp": "2026-04-15T10:30:00.123Z",
  "tenant_id": "tenant_001",
  "node_id": "node-us-east-1a",
  "type": "block",
  "action": "block",
  "rule_id": "SQLI-001",
  "score": 75,
  "request": {
    "method": "GET",
    "path": "/search",
    "query": "q=' OR 1=1--",
    "headers": {...},
    "body": ""
  },
  "response": {
    "status": 403,
    "latency_ms": 2.5
  },
  "client": {
    "ip": "203.0.113.50",
    "country": "US",
    "asn": 12345,
    "user_agent": "curl/7.68.0"
  },
  "waf": {
    "version": "1.0.0",
    "layer": "detection",
    "detector": "sqli"
  }
}
```

### Query API

```bash
# Get recent events
GET /api/v1/events?limit=100&offset=0

# Filter by action
GET /api/v1/events?action=block&since=1h

# Filter by rule
GET /api/v1/events?rule_id=SQLI-001&limit=50

# Aggregate statistics
GET /api/v1/analytics/attacks?period=24h&group_by=rule_id

# Real-time subscription
GET /api/v1/events/stream (SSE)
```

### Sharding Strategy

For Redis/Postgres, events are sharded by `tenant_id` for multi-tenant isolation:

```
Shard Key = hash(tenant_id) % num_shards
```

This ensures:
- All events for a tenant are on same shard
- Queries for single tenant are efficient
- Cross-tenant analytics require scatter-gather

### Implementation Phases

**Phase 1: Redis Adapter**
- Implement Redis event store adapter
- Pub/sub for real-time event streaming
- Event aggregation pipeline

**Phase 2: PostgreSQL Adapter**
- Add Postgres adapter for enterprise
- Schema migrations
- Connection pooling

**Phase 3: S3 Archival**
- Batch upload to S3
- Archive old events to S3
- Query from S3 for historical analysis

**Phase 4: Hybrid Mode**
- Local in-memory cache for hot events
- Background sync to backend store
- Seamless failover if backend unavailable

## Consequences

### Positive
- Unified event view across cluster
- Durable storage for compliance
- Real-time event streaming to dashboards
- Analytics aggregation built-in
- No event loss on node failure

### Negative
- Additional infrastructure dependency (Redis/Postgres)
- Network latency for event writes (~1-5ms)
- Storage costs for long-term retention
- Complexity in multi-region setup

## Implementation Locations

**Note**: This ADR describes a proposed feature. The current event store (`internal/events/`) supports memory and JSONL file backends. Redis, PostgreSQL, and S3 adapters (`store_redis.go`, `store_postgres.go`, `store_s3.go`) do not yet exist.

| File | Purpose |
|------|---------|
| `internal/events/store_redis.go` | Redis event store adapter (planned) |
| `internal/events/store_postgres.go` | PostgreSQL adapter (planned) |
| `internal/events/store_s3.go` | S3 archival adapter (planned) |
| `internal/events/aggregator.go` | Event aggregation (planned) |
| `internal/events/stream.go` | Real-time SSE streaming (planned) |
| `internal/config/events.go` | Configuration schema |

## References

- [GuardianWAF Event Layer](../ARCHITECTURE.md#event-store)
- [Redis Streams](https://redis.io/topics/streams-intro/)
- [GuardianWAF Cluster Mode](./0013-multi-region-support.md)
