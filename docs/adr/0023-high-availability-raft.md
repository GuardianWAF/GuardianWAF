# ADR 0023: High Availability with Raft Consensus

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF's cluster support (`internal/cluster/`, `internal/clustersync/`) currently provides stateless horizontal scaling: multiple instances share no state and each node makes independent decisions. This model works for stateless WAF checks but breaks down for state that must be consistent across the cluster:

- **Rate limit counters** — a distributed attacker hitting different nodes stays under per-node limits
- **Auto-ban decisions** — a node that bans an IP doesn't propagate the ban to peers; the attacker simply routes to another node
- **Custom rule updates** — dashboard rule changes on one node are not visible to peers
- **ATO protection state** — failed login counters per user are per-node, defeating cross-node credential stuffing detection

Today, operators work around this with an external Redis instance. However, Redis introduces an external dependency (conflict with ADR 0001), a single point of failure, and operational overhead.

The solution is **embedded distributed consensus** so that a GuardianWAF cluster elects a leader and replicates critical state internally, without requiring any external coordination service.

## Decision

Implement Raft consensus using a pure-Go, zero-dependency Raft implementation embedded in GuardianWAF. Only the **state machine** (rate counters, ban list, rules) is replicated; WAF request processing remains fully local and does not touch the consensus path.

### State Partitioning

| State Type | Replicated via Raft | Rationale |
|------------|---------------------|-----------|
| Rate limit counters (per IP) | Yes — eventually consistent | Cross-node accuracy |
| Auto-ban IP list | Yes — strongly consistent | All nodes must block banned IPs |
| Custom rules | Yes — strongly consistent | Rules must be identical across cluster |
| ATO failed attempts (per user) | Yes — eventually consistent | Cross-node brute force tracking |
| WAF per-request scores | No — local only | Consensus would add unacceptable latency |
| TLS session state | No — local | TLS is terminated per-node |
| JA4 fingerprint data | No — local cache | TTL-based, loss tolerable |

### Raft Implementation Approach

Rather than adopting `hashicorp/raft` (external dependency), implement a minimal Raft subset sufficient for GuardianWAF's needs:

**In scope:**
- Leader election (randomized election timeout, 150–300ms)
- Log replication (AppendEntries RPC)
- Log compaction via snapshots (when log exceeds 10,000 entries)
- Membership changes (AddServer / RemoveServer, one node at a time)

**Out of scope (for this ADR):**
- Joint consensus (multi-node simultaneous membership change)
- Pre-vote optimization
- Read-only lease reads (all reads are linearizable)

**RPC transport:** Raft messages use a hand-rolled binary framing protocol over TCP (`net.Conn`) — no external gRPC library, no protobuf. The message format mirrors the gossip wire format: `<type:1><len:4><payload>` with JSON-encoded command structs for human readability during debugging.

**Peer discovery:** The gossip membership layer (`internal/cluster/gossip/`, implemented in v0.6.0) provides the peer list. Raft nodes discover each other through gossip's `Members()` API rather than static config. The gossip layer handles liveness detection (alive/suspect/dead) and node discovery; Raft handles strong consistency on top of the membership view. This mirrors the etcd/Consul architecture: gossip for membership, Raft for consensus.

### Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                  GuardianWAF Cluster (3 nodes)                  │
│                                                                 │
│  Node A (Leader)          Node B             Node C            │
│  ┌──────────────┐        ┌──────────────┐   ┌──────────────┐  │
│  │ WAF Pipeline │        │ WAF Pipeline │   │ WAF Pipeline │  │
│  │  (local)     │        │  (local)     │   │  (local)     │  │
│  └──────┬───────┘        └──────┬───────┘   └──────┬───────┘  │
│         │ Apply                  │ Apply             │ Apply    │
│  ┌──────▼───────┐        ┌──────▼───────┐   ┌──────▼───────┐  │
│  │ State Machine│        │ State Machine│   │ State Machine│  │
│  │ (ban list,   │◀──────▶│              │◀─▶│              │  │
│  │  rules,      │  Raft  │              │   │              │  │
│  │  counters)   │  RPC   │              │   │              │  │
│  └──────────────┘        └──────────────┘   └──────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### State Machine

The replicated log contains **commands** (not raw state). Each command is a typed struct:

```go
type Command struct {
    Type    CommandType
    Payload []byte       // Protobuf-encoded command body
}

// Command types:
const (
    CmdBanIP         CommandType = 1   // { ip: string, duration: int64 }
    CmdUnbanIP       CommandType = 2   // { ip: string }
    CmdSetRule       CommandType = 3   // { rule_id: string, rule: []byte }
    CmdDeleteRule    CommandType = 4   // { rule_id: string }
    CmdIncrCounter   CommandType = 5   // { key: string, delta: int64, window: int64 }
    CmdResetCounter  CommandType = 6   // { key: string }
)
```

On each node, a goroutine applies committed log entries to the local in-memory state machine. The state machine is snapshotted to disk periodically using `encoding/gob`.

### Read Path

- **Strongly consistent reads** (ban list, rules): routed to leader via HTTP redirect or internal RPC. Leader confirms it is still leader before returning.
- **Eventually consistent reads** (rate counters): read from local state machine. Counters may lag by up to one replication round-trip (~2ms on LAN).

WAF hot path (request processing) always reads from the local state machine — **no synchronous Raft operations on the request path**. This preserves sub-millisecond WAF latency.

### Leader-Forwarded Writes

When a non-leader node needs to write (e.g., auto-ban triggered by local rate limit detection):

1. Non-leader sends `ProposeCommand` RPC to current leader
2. Leader appends to log, replicates to quorum, commits
3. Leader responds with `committed: true`
4. Non-leader applies optimistically to local state (will be confirmed when log entry arrives via AppendEntries)

### Configuration

```yaml
cluster:
  enabled: true
  node_id: "node-a"              # Must be unique across cluster
  listen_addr: "0.0.0.0:7946"   # Raft RPC listener

  peers:
    - id: "node-b"
      addr: "10.0.0.2:7946"
    - id: "node-c"
      addr: "10.0.0.3:7946"

  raft:
    election_timeout_min_ms: 150
    election_timeout_max_ms: 300
    heartbeat_interval_ms: 50
    snapshot_threshold: 10000    # Entries before compaction
    snapshot_dir: /var/lib/guardianwaf/raft/

  replicated_state:
    ban_list: true
    rate_counters: true
    custom_rules: true
    ato_counters: true
```

### Failure Modes

| Scenario | Behavior |
|----------|----------|
| Leader crash | Election in 150–300ms; writes blocked until new leader elected |
| Follower crash | Cluster continues; quorum maintained (2 of 3 nodes) |
| Network partition (minority side) | Minority nodes process reads from stale state; writes return error |
| All nodes unreachable | WAF continues processing with last-known state; no writes until quorum restored |
| Split-brain | Prevented by quorum requirement — minority partition cannot commit |

### Dashboard

- **Cluster health page** — node status, current leader, log index, replication lag per node
- **Manual failover** — force leader step-down via dashboard (operator tool)
- **Membership management** — add/remove nodes via dashboard with live Raft membership change

## Consequences

### Positive
- Cross-node rate limits and bans without external Redis dependency
- Rule updates propagate atomically across the cluster
- Embedded Raft has no external dependencies — preserves zero-external-dep constraint
- Clear failure semantics: minority partition is read-only, not write-split

### Negative
- Implementing Raft from scratch is ~3,000–5,000 LOC and requires extensive testing (especially around election edge cases and log truncation)
- 3-node minimum for production HA; 2-node deployment has no fault tolerance
- Write latency increases by one Raft round-trip (~2ms LAN, ~100ms WAN) — acceptable for ban/rule changes, not for per-request decisions
- Snapshot/restore adds startup complexity; corrupted snapshots must be detected and handled

## Implementation Locations

**Current tree note:** The SWIM gossip membership protocol is implemented at `internal/cluster/gossip/` (member state machine, UDP transport, probe/indirect-ping/suspicion protocol, push-pull join, piggyback dissemination — 28 tests, race-clean). The Raft consensus layer is implemented at `internal/cluster/raft/` (leader election, log replication over TCP, per-peer connection pooling, 26 tests, race-clean). The replicated state store is implemented at `internal/clustersync/` (ReplicatedStore with ban list, rules, rate counters, StateMachine adapter for Raft). Gossip handles membership and failure detection; Raft handles strong consistency; clustersync provides the replicated state machine on top of Raft. Cluster dashboard handlers at `internal/dashboard/cluster_handlers.go` exist as stubs returning empty/disabled responses.

| File | Status | Purpose |
|------|--------|---------|
| `internal/cluster/gossip/member.go` | **Implemented** | Member struct, MemberList state machine (incarnation-based conflict resolution) |
| `internal/cluster/gossip/message.go` | **Implemented** | Wire format encoding, member list serialization for piggyback |
| `internal/cluster/gossip/transport.go` | **Implemented** | UDP transport with `Transport` interface |
| `internal/cluster/gossip/protocol.go` | **Implemented** | SWIM protocol: probe loop, indirect ping, suspicion, push-pull, piggyback |
| `internal/cluster/raft/types.go` | **Implemented** | Core types: Role, LogEntry, Config, RPC message structs |
| `internal/cluster/raft/log.go` | **Implemented** | In-memory LogStore with conflict detection and RWMutex locking |
| `internal/cluster/raft/state.go` | **Implemented** | PersistentState, LeaderState (nextIndex/matchIndex), commit index |
| `internal/cluster/raft/rpc.go` | **Implemented** | Binary framing RPC encode/decode over TCP |
| `internal/cluster/raft/transport.go` | **Implemented** | TCP transport with per-peer connection pooling |
| `internal/cluster/raft/raft.go` | **Implemented** | Core Raft node: election loop, heartbeat, AppendEntries handler |
| `internal/clustersync/commands.go` | **Implemented** | Command types (ban/unban/set-rule/delete-rule/incr/reset-counter) |
| `internal/clustersync/store.go` | **Implemented** | ReplicatedStore with ban list, rules, rate counters |
| `internal/clustersync/state_machine.go` | **Implemented** | Raft StateMachine adapter — decodes commands, applies to store |
| `internal/clustersync/api.go` | **Implemented** | Public write API (ProposeBan, ProposeUnban, etc.) |
| `internal/dashboard/cluster_handlers.go` | **Stub** | Returns empty/disabled responses — will wire to Raft state |
| `internal/config/config.go` | **Exists** | `ClusterConfig` struct — Raft config fields will be added |

## References

- [Raft Consensus Algorithm — Ongaro & Ousterhout](https://raft.github.io/raft.pdf)
- [Raft Visualization](https://raft.github.io/)
- [TiKV Raft in Go (inspiration)](https://github.com/tikv/raft-rs)
- [ADR 0013: Multi-Region Support](./0013-multi-region-support.md)
- [ADR 0015: Distributed Event Store](./0015-distributed-event-store.md)
