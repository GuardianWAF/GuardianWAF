# ADR 0011: IP Reputation Sharing

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF has threat intelligence via:
- IP-based block/allow lists
- GeoIP country blocking
- Rate limiting with auto-ban
- AI-based verdict banning

However, when one GuardianWAF instance detects a new attack source, that intelligence is not shared with other instances. This means:
- New attack sources must be manually blocklisted across all instances
- Each instance learns the same threats independently
- Coordinated attacks bypass individual instances

## Decision

Implement opt-in, privacy-preserving IP reputation sharing between GuardianWAF instances.

### Design Principles

1. **Opt-in only** — Explicitly enabled per instance
2. **Privacy-preserving** — Only share malicious IPs, not legitimate traffic
3. **Decentralized** — No central server required (gossip protocol)
4. **Privacy-respecting** — Do not share internal network IPs or private ranges

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  GuardianWAF │────▶│  GuardianWAF │────▶│  GuardianWAF │
│  Instance A  │◀────│  Instance B  │◀────│  Instance C  │
└──────────────┘     └──────────────┘     └──────────────┘
      │                    │                    │
      └────────────────────┴────────────────────┘
                     Gossip Protocol
                   (TLS encrypted, auth)
```

### Sharing Protocol

1. **Gossip-based** — Instances periodically share recent block events
2. **TTL-based** — Shared entries expire after configurable time (default: 24h)
3. **Bloom filter** — Use Bloom filters for efficient set sharing without exact IP lists
4. **Dead drop** — Optional: publish to dead drop URL (S3, GCS) for firewall egress

### Configuration

```yaml
reputation:
  enabled: true
  share_interval: 5m          # How often to share
  ttl: 24h                    # How long shared entries live
  min_confidence: 0.7        # Minimum threat score to share
  exclude_private: true      # Don't share RFC1918 addresses
  cluster_key: "${CLUSTER_KEY}" # Shared secret for auth

  # Transport options (one or more)
  gossip:
    enabled: true
    peers:
      - instance1.example.com:9444
      - instance2.example.com:9444

  dead_drop:
    enabled: false
    url: "s3://my-bucket/reputation/"
    format: "bloomfilter"
```

### Data Shared

Only share minimal threat data:

```json
{
  "ip": "203.0.113.50",
  "first_seen": "2026-04-15T10:30:00Z",
  "last_seen": "2026-04-15T12:45:00Z",
  "threat_types": ["sqli", "cmdi"],
  "count": 15,
  "confidence": 0.85,
  "instance_id": "guardian-us-east-1"
}
```

### Privacy Considerations

- **Never share**: Full request logs, legitimate traffic patterns, internal IPs
- **Aggregate only**: Share threat counts, not request content
- **Expires**: All shared data has TTL (max 48h)
- **Exclude private**: RFC1918, loopback, link-local never shared
- **Audit log**: All sharing actions logged

### Implementation Phases

**Phase 1: Basic Gossip**
- Direct peer-to-peer sharing via TLS
- Manual peer list configuration
- JSON payload over HTTP/2

**Phase 2: Bloom Filters**
- Aggregate IPs into Bloom filter for efficient transfer
- Reduces bandwidth by ~90%

**Phase 3: Dead Drop**
- Publish to S3/GCS for cross-cloud sharing
- Subscribe to others' dead drops

**Phase 4: Incentives**
- Reputation score for participating instances
- Higher reputation = faster propagation

## Consequences

### Positive
- Shared threat intelligence across instances
- Faster response to coordinated attacks
- Reduced manual blocklist management
- Community-driven protection

### Negative
- Privacy complexity
- Potential for abuse (false positives)
- Additional configuration
- Network overhead

### Security

- All gossip traffic over TLS with mutual authentication
- Cluster key prevents unauthorized participation
- Rate limiting on incoming shares
- Input validation on received data

## Implementation Locations

**Note**: This ADR describes a proposed feature. The files below represent the intended implementation structure — `internal/layers/threatintel/sharing.go`, `bloom.go`, and `deaddrop.go` do not yet exist.

| File | Purpose |
|------|---------|
| `internal/layers/threatintel/sharing.go` | Gossip protocol |
| `internal/layers/threatintel/bloom.go` | Bloom filter aggregation |
| `internal/layers/threatintel/deaddrop.go` | Dead drop integration |
| `internal/config/reputation.go` | Configuration schema |

## References

- [GuardianWAF Threat Intel Layer](../ARCHITECTURE.md#layer-order)
- [Gossip Protocol](https://en.wikipedia.org/wiki/Gossip_protocol)
- [Bloom Filters](https://en.wikipedia.org/wiki/Bloom_filter)
