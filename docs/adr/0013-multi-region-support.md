# ADR 0013: Multi-Region Support

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF has cluster mode (`internal/cluster/`) but needs production hardening for multi-region deployments. Current limitations:
- Event store is local (memory or file) — not shared across regions
- No cross-region failover
- GeoIP-based routing exists but limited
- TLS certificates not shared across regions

## Decision

Enhance cluster mode for multi-region production deployments.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Global Load Balancer                       │
│              (Cloudflare, AWS Global Accelerator)            │
└───────────────┬─────────────────────┬───────────────────────┘
                │                     │
        ┌───────▼──────┐      ┌──────▼──────┐
        │  us-east-1   │      │  eu-west-1  │
        │ ┌──────────┐ │      │ ┌──────────┐ │
        │ │ Guardian │ │◀────▶│ │ Guardian │ │
        │ │  Node A  │ │ Gossip│ │  Node C  │ │
        │ └──────────┘ │      │ └──────────┘ │
        │ ┌──────────┐ │      │ ┌──────────┐ │
        │ │ Guardian │ │      │ │ Guardian │ │
        │ │  Node B  │ │      │ │  Node D  │ │
        │ └──────────┘ │      │ └──────────┘ │
        └──────────────┘      └──────────────┘
                │                     │
        ┌───────▼──────┐      ┌──────▼──────┐
        │   Redis/A3   │      │  Redis/S3   │
        │ (Event Store)│      │(Event Store)│
        └──────────────┘      └──────────────┘
```

### Requirements

#### 1. Distributed Event Store

```yaml
cluster:
  event_store:
    driver: redis          # or "s3", "dynamodb"
    redis:
      endpoints:
        - redis.us-east-1.example.com:6379
        - redis.eu-west-1.example.com:6379
      password: "${REDIS_PASSWORD}"
      database: 0
      pool_size: 100
    s3:
      bucket: guardian-events
      region: us-east-1
      prefix: "events/"
```

#### 2. Global Configuration Sync

```yaml
cluster:
  config_sync:
    driver: redis          # or "consul", "etcd"
    redis:
      key_prefix: "guardian:config:"
    ttl: 30s               # Config propagation delay
```

#### 3. Cross-Region Health Checking

```yaml
cluster:
  health:
    cross_region: true
    probe_interval: 10s
    timeout: 5s
    unhealthy_threshold: 3
    probe_targets:
      - region: eu-west-1
        url: https://guardian.eu-west-1.example.com/healthz
      - region: ap-south-1
        url: https://guardian.ap-south-1.example.com/healthz
```

#### 4. Regional Failover

```yaml
cluster:
  failover:
    auto_promote: true     # Promote standby to primary
    election_timeout: 10s
    min_health_ratio: 0.5  # At least 50% nodes healthy
```

#### 5. Geo-Based Routing

```yaml
cluster:
  routing:
    strategy: geo          # geo, latency, weighted
    health_check:
      path: /healthz
      interval: 10s
    backends:
      - region: us-east-1
        weight: 50
        health: true
      - region: eu-west-1
        weight: 30
        health: true
      - region: ap-south-1
        weight: 20
        health: false      # Standby
```

#### 6. Global TLS Certificate Management

```yaml
cluster:
  tls:
    shared_cert_store: s3   # or "vault", "cert-manager"
    s3:
      bucket: guardian-certs
      region: us-east-1
    cert_key: "certs/{domain}/fullchain.pem"
    key_key: "certs/{domain}/privkey.pem"
```

### Data Consistency

#### Eventual Consistency Model

- Events are local-first, then replicated
- Replication lag: typically <1s within region, <5s cross-region
- Conflict resolution: last-write-wins with vector clocks

#### Consistency Levels

| Level | Use Case | Latency |
|-------|----------|---------|
| `local` | High performance, can lose events | <1ms |
| `region` | Balanced, events replicated within region | <10ms |
| `global` | Strong consistency, cross-region | <100ms |

### Implementation Phases

**Phase 1: Redis Event Store**
- Add Redis adapter for event store
- Maintain local cache for hot events
- Background sync to Redis

**Phase 2: Config Sync**
- Redis-backed configuration
- Pub/sub for config change notifications
- Multi-region config propagation

**Phase 3: Health & Failover**
- Cross-region health checking
- Automatic failover
- Leader election

**Phase 4: Global Routing**
- Geo-based load balancing
- Latency-based routing
- Traffic shifting (canary deployments)

## Consequences

### Positive
- High availability across regions
- Geographic distribution for latency
- Disaster recovery capability
- Consistent config across fleet

### Negative
- Increased operational complexity
- Cross-region latency for some operations
- Redis/infra dependency
- Cost increase for multi-region infra

## Implementation Locations

**Note**: This ADR describes a proposed feature. `internal/multiregion/` does not exist; `internal/cluster/` provides cluster coordination (leader election, IP ban sync, rate limit sync) but not multi-region failover. The files below represent the intended multi-region implementation.

| File | Purpose |
|------|---------|
| `internal/cluster/redis_store.go` | Redis event store adapter |
| `internal/cluster/config_sync.go` | Distributed config |
| `internal/cluster/health.go` | Cross-region health |
| `internal/cluster/failover.go` | Automatic failover |
| `internal/cluster/geo.go` | Geo-based routing |
| `internal/cluster/tls_sync.go` | Shared TLS certs |

## References

- [GuardianWAF Cluster Mode](../ARCHITECTURE.md#cluster)
- [Redis Cluster](https://redis.io/topics/cluster-tutorial/)
- [AWS Global Accelerator](https://aws.amazon.com/global-accelerator/)
