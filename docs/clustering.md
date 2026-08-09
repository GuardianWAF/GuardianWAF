# Clustering & High Availability

GuardianWAF supports multi-node clustering for horizontal scaling, cross-node state replication, and high availability. In cluster mode, nodes share a **ban list**, **custom rules**, and **rate-limit counters** via Raft consensus — no external database required.

> **Architecture background**: See [ADR 0023](adr/0023-high-availability-raft.md) for the design rationale behind the embedded Raft approach.

---

## How It Works

```
                    ┌──────────────────┐
                    │   Gossip (UDP)   │  ← Membership, failure detection
                    │   port 7946      │     SWIM protocol, peer discovery
                    └──────┬───────────┘
                           │ join/leave events
                    ┌──────▼───────────┐
                    │  PeerSyncBridge  │  ← Bridges gossip → Raft peer list
                    └──────┬───────────┘
                           │ UpdatePeers()
                    ┌──────▼───────────┐
     Ban request    │   Raft (TCP)     │  ← Leader election, log replication
     POST /api/v1/  │   port 7947      │     Strong consistency for bans/rules
     bans           └──────┬───────────┘
        │                   │ Apply()
        ▼                   ▼
 ┌─────────────┐   ┌─────────────────┐
 │ HTTP Handler│   │ ReplicatedStore │  ← In-memory state machine
 │ + Redirect  │   │ bans, rules,   │     Read locally at request time
 │ (307)       │   │ counters       │     Zero latency on WAF path
 └─────────────┘   └─────────────────┘
```

**Key design principle**: WAF request processing never touches the consensus path. Raft replication only happens on **writes** (ban/unban, rule changes). Reads happen locally against each node's replicated store with zero network overhead.

---

## Configuration

<!-- guardianwaf-config:validate -->
```yaml
cluster:
  enabled: true
  node_id: "guardian-01"

  # Raft TCP listen address — used for leader election and log replication.
  bind_addr: "0.0.0.0:7947"

  # Gossip UDP listen address — used for membership and peer discovery.
  gossip_addr: "0.0.0.0:7946"

  # Seed peers for bootstrapping. After initial discovery via gossip,
  # the cluster maintains its own peer list dynamically.
  # Only ONE seed peer is needed to discover the entire cluster.
  peers:
    - id: "guardian-02"
      addr: "10.0.0.2:7947"
    - id: "guardian-03"
      addr: "10.0.0.3:7947"

  # Raft timing (optional — defaults shown).
  election_timeout_min: 2s   # Minimum randomized election timeout.
  election_timeout_max: 4s   # Maximum randomized election timeout.
  heartbeat_interval: 50ms   # Leader heartbeat frequency.
```

### Minimum Required Fields

When `cluster.enabled: true`, these fields are **required** — config validation will fail without them:

| Field | Purpose | Example |
|---|---|---|
| `node_id` | Unique node identifier | `guardian-01` |
| `bind_addr` | Raft TCP listen address | `0.0.0.0:7947` |
| `gossip_addr` | Gossip UDP listen address | `0.0.0.0:7946` |
| `peers` | At least one seed peer (or self for single-node bootstrap) | See above |

---

## Peer Discovery

### Static Configuration (Simple)

List all peers in YAML. Each node must know at least one other node's Raft TCP address.

```yaml
cluster:
  enabled: true
  node_id: "node-1"
  bind_addr: "0.0.0.0:7947"
  gossip_addr: "0.0.0.0:7946"
  peers:
    - id: "node-2"
      addr: "10.0.0.2:7947"
    - id: "node-3"
      addr: "10.0.0.3:7947"
```

### Dynamic Discovery via Gossip (Recommended)

Gossip automatically discovers all cluster members and propagates them to Raft. You only need **one seed peer** in the config — gossip finds the rest.

**How it works:**

1. Each node starts a gossip member (UDP port 7946) and announces itself with its Raft address and dashboard URL.
2. The gossip protocol (SWIM-based) probes members and detects joins/leaves/failures.
3. The [`PeerSyncBridge`](https://github.com/guardianwaf/guardianwaf/blob/main/internal/cluster/peersync/bridge.go) watches gossip events and calls `raft.UpdatePeers()` when the membership changes.
4. The Raft leader immediately starts replicating to new peers or stops replicating to departed ones.

**Benefits:**
- Add/remove nodes without restarting the cluster or editing YAML on every node.
- Automatic failover — dead nodes are removed from the Raft peer list.
- Each node learns every other node's dashboard URL (for leader redirects).

**Wire format fields propagated via gossip:**

| Field | Purpose |
|---|---|
| `Addr` | Gossip UDP address (SWIM probe target) |
| `RaftAddr` | Raft TCP address (consensus + log replication) |
| `DashboardAddr` | Dashboard HTTP address (for 307 leader redirects) |

---

## State Replication

### What Gets Replicated

| State | Replicated | Consistency | How |
|---|---|---|---|
| **IP bans** | Yes | Strong | `ProposeBan(ip, duration)` → Raft log → all stores |
| **IP unbans** | Yes | Strong | `ProposeUnban(ip)` → Raft log → all stores |
| **Custom rules** | Yes | Strong | `ProposeSetRule(id, rule)` / `ProposeDeleteRule(id)` |
| **Rate-limit counters** | Yes | Eventual | `ProposeIncrCounter(key, window)` |
| **WAF request scores** | No | Local | Each node processes independently |
| **TLS session state** | No | Local | TLS is terminated per-node |

### Replication Flow

```
Operator bans IP     Leader                   Followers
on dashboard          node                     node-2, node-3
                      ┌───┐                    ┌───┐
  POST /api/v1/bans ──►   │  AppendEntries     │   │
                      │   ├───────────────────►│   │
                      │   │  AppendEntries     │   │
                      │   ├───────────────────►│   │
                      │   │                    └───┘
                      │   │
                      │   │  Apply to local store
                      │   ▼
                      │ store.AddBan(ip)       store.AddBan(ip)
                      └───┘                    └───┘
```

1. The ban request hits the leader's dashboard API.
2. `clustersync.API.ProposeBan()` encodes the command and calls `raft.Propose()`.
3. The Raft leader appends the command to its log and replicates it via `AppendEntries` RPCs.
4. Once a quorum acknowledges, the entry is committed.
5. Each node's `StoreStateMachine.Apply()` applies the committed entry to its local `ReplicatedStore`.
6. The WAF request pipeline reads from the local store — no network round-trip.

**Latency**: Write latency = Raft consensus round-trip (typically 1-10ms on LAN). Read latency = zero (local memory).

---

## Leader Redirect

Raft requires all writes to go through the leader. If a ban request hits a **follower**, the dashboard automatically redirects the client to the leader.

### How It Works

1. Follower receives `POST /api/v1/bans` with `{"ip": "1.2.3.4", "duration": "1h"}`.
2. The handler calls `clusterStatus.ProposeBan("1.2.3.4", 1*time.Hour)`.
3. `ProposeBan` returns `ErrRaftNotLeader`.
4. The handler checks `clusterStatus.IsNotLeader(err)` → `true`.
5. The handler looks up the leader's `DashboardURL` from the gossip member list.
6. Returns **HTTP 307 Temporary Redirect** with `Location: http://leader-host:8080/api/v1/bans`.

```
Client                    Follower (node-2)         Leader (node-1)
  │                            │                         │
  │ POST /api/v1/bans         │                         │
  │──────────────────────────►│                         │
  │                            │  ProposeBan()           │
  │                            │  → ErrRaftNotLeader     │
  │  307 Redirect              │                         │
  │◄──────────────────────────│                         │
  │  Location: http://node-1:8080/api/v1/bans            │
  │                            │                         │
  │ POST /api/v1/bans (follows redirect)                 │
  │─────────────────────────────────────────────────────►│
  │                            │  ProposeBan() → OK      │
  │                            │  Raft replicates →      │
  │                            │  all stores             │
  │  200 OK                    │                         │
  │◄─────────────────────────────────────────────────────│
```

### Dashboard Address Propagation

Each node's dashboard address is propagated through gossip as the `DashboardAddr` field. This is how a follower knows the leader's dashboard URL without any static configuration.

When gossip is **not** active (static peer config only), the follower returns a **503** with the leader's node ID but no redirect URL — the operator must retry on the leader directly.

---

## Observability

### Prometheus Metrics

Cluster metrics are exposed at `/metrics` when cluster mode is active. See [Metrics Reference](metrics.md#cluster-metrics) for the full list.

Key metrics to monitor:

| Metric | Alert When | Meaning |
|---|---|---|
| `guardianwaf_cluster_member_count` | `< expected` | Node loss — cluster degraded |
| `guardianwaf_cluster_is_leader` | `max() == 0` for >30s | No leader — cluster cannot accept writes |
| `commit_index - last_applied` | `> 10` | Replication lag — state machine falling behind |
| `store_bans` | Sudden spike | Ban storm — investigate attack or misconfiguration |

### Grafana Dashboard

A pre-built Grafana dashboard is included at [`contrib/grafana/cluster-dashboard.json`](https://github.com/guardianwaf/guardianwaf/blob/main/contrib/grafana/cluster-dashboard.json).

Import instructions:
1. Open Grafana → Dashboards → Import.
2. Upload `contrib/grafana/cluster-dashboard.json`.
3. Select your Prometheus datasource.
4. (Optional) Filter by `$instance` to view individual nodes.

### Dashboard API

The dashboard REST API exposes cluster status endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/cluster/status` | GET | Node role, term, leader ID, commit index |
| `/api/v1/cluster/nodes` | GET | Peer list with Raft addresses |
| `/api/v1/cluster/health` | GET | Healthy/unhealthy status |
| `/api/v1/cluster/config` | GET | Current cluster configuration |
| `/api/v1/cluster/bans` | GET | All active bans in the replicated store |

---

## Deployment

### Minimum Cluster Size

A minimum of **3 nodes** is recommended for production. This provides:
- Quorum tolerance for 1 node failure
- No split-brain risk

| Cluster Size | Failures Tolerated | Recommended For |
|---|---|---|
| 1 | 0 | Development / single-node testing |
| 3 | 1 | **Production minimum** |
| 5 | 2 | High-availability production |
| 7 | 3 | Mission-critical, multi-AZ |

**Never deploy 2 nodes** — you lose quorum on any single failure, and there is no majority for election.

### Docker Compose Example

```yaml
services:
  guardian-01:
    image: guardianwaf:latest
    ports:
      - "8081:8080"  # Dashboard
      - "7947"        # Raft
      - "7946"        # Gossip
    environment:
      GUARDIANWAF_CLUSTER_ENABLED: "true"
      GUARDIANWAF_CLUSTER_NODE_ID: "guardian-01"
      GUARDIANWAF_CLUSTER_BIND_ADDR: "0.0.0.0:7947"
      GUARDIANWAF_CLUSTER_GOSSIP_ADDR: "0.0.0.0:7946"
    # ... (WAF config omitted for brevity)

  guardian-02:
    image: guardianwaf:latest
    ports:
      - "8082:8080"
      - "7947"
      - "7946"
    environment:
      GUARDIANWAF_CLUSTER_ENABLED: "true"
      GUARDIANWAF_CLUSTER_NODE_ID: "guardian-02"
      GUARDIANWAF_CLUSTER_BIND_ADDR: "0.0.0.0:7947"
      GUARDIANWAF_CLUSTER_GOSSIP_ADDR: "0.0.0.0:7946"
    # Seed peer points to guardian-01
    # Only one seed needed — gossip discovers the rest
```

### Kubernetes

For Kubernetes, use a **headless Service** so each pod gets a stable DNS name for Raft and gossip:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: guardianwaf-cluster
spec:
  clusterIP: None  # Headless — gives each pod a DNS record
  selector:
    app: guardianwaf
  ports:
    - name: raft
      port: 7947
    - name: gossip
      port: 7946
      protocol: UDP
    - name: dashboard
      port: 8080
```

Pods discover each other via the headless Service DNS: `guardian-01.guardianwaf-cluster.namespace.svc.cluster.local`.

---

## Troubleshooting

### Cluster won't form

1. **Check ports**: Raft TCP (7947) and Gossip UDP (7946) must be open between all nodes.
2. **Check `node_id` uniqueness**: Each node must have a unique `node_id`.
3. **Check peer addresses**: At least one peer's Raft address must be reachable.
4. **Check logs**: Look for `gossip started`, `raft: starting election`, `became leader`.

### No leader elected

1. Wait for election timeout (default 2-4 seconds after startup).
2. Check `guardianwaf_cluster_is_leader` — should be 1 on exactly one node.
3. If 0 on all nodes, the cluster has no majority — add nodes or check connectivity.

### Ban not replicating

1. Check `guardianwaf_cluster_raft_commit_index` is advancing on all nodes.
2. Check `commit_index - last_applied` is near 0 — high lag means the apply loop is stuck.
3. Send the ban to the **leader** node directly (check `/api/v1/cluster/status` for leader ID).
4. Check for `ErrRaftNotLeader` errors in the logs.

### Redirect not working (503 instead of 307)

1. Verify gossip is running: check `/api/v1/cluster/nodes` — if empty, gossip didn't converge.
2. The leader's `DashboardAddr` must be non-empty in the gossip member list.
3. If using static peers only (no gossip), redirects are not available — the 503 response includes `leader_id` for manual retry.

---

## Implementation Reference

| Package | Purpose |
|---|---|
| `internal/cluster/raft/` | Raft consensus: leader election, log replication, RPC |
| `internal/cluster/gossip/` | SWIM membership: failure detection, peer discovery |
| `internal/cluster/peersync/` | Bridge: gossip events → Raft `UpdatePeers()` |
| `internal/clustersync/` | Replicated state machine: bans, rules, counters + API |
| `cmd/guardianwaf/cluster_runtime.go` | Wiring: creates gossip + Raft + bridge at startup |
| `cmd/guardianwaf/cluster_status_provider.go` | Dashboard adapter: `ClusterStatusProvider` implementation |
