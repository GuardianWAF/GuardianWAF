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

### CLI Quick Reference

The `guardianwaf cluster` command provides six subcommands for querying and managing the cluster from the terminal. All accept `--url`, `--api-key`, `-c/--config`, and `--timeout` flags (see [CLI Reference](#cli-reference) for details).

```bash
guardianwaf cluster status           # detailed node + store summary
guardianwaf cluster nodes            # peer table with leader marking
guardianwaf cluster bans             # active cluster-wide ban list
guardianwaf cluster ban 10.0.0.5     # ban an IP cluster-wide
guardianwaf cluster unban 10.0.0.5   # remove a cluster-wide ban
guardianwaf cluster health           # scriptable health check (exit 0/1)
```

See [CLI Reference](#cli-reference) below for full flags, sample output, and scripting patterns.

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

GuardianWAF ships production-ready Kubernetes manifests for cluster mode. A **StatefulSet** provides stable pod identities (`guardianwaf-0`, `-1`, `-2`) with stable DNS names via a **headless Service**. This is required because Raft and gossip need to know peer addresses at startup.

**Apply the manifests:**

```bash
# ConfigMap first (contains cluster config with peer DNS names)
kubectl apply -f contrib/k8s/cluster-configmap.yaml

# StatefulSet + headless Service
kubectl apply -f contrib/k8s/cluster-statefulset.yaml
```

**Pod DNS pattern**: `guardianwaf-0.guardianwaf-cluster.default.svc.cluster.local`

The ConfigMap references these DNS names as seed peers. Each pod uses the Kubernetes downward API (`metadata.name`) as its `node_id`. Gossip discovers additional peers automatically after bootstrap.

**Port reference:**

| Port | Protocol | Purpose |
|------|----------|---------|
| 7947 | TCP | Raft — leader election, log replication |
| 7946 | UDP | Gossip — membership, peer discovery |
| 8088 | TCP | WAF reverse proxy |
| 9443 | TCP | Dashboard + REST API |

**Helm chart** (preferred for production):

```bash
helm install guardianwaf contrib/k8s/helm \
  --set cluster.enabled=true \
  --set cluster.replicas=3 \
  --set apiKey.existingSecret=guardianwaf-dashboard-auth
```

The Helm chart automatically deploys the StatefulSet, headless Service, and a PodDisruptionBudget (prevents simultaneous evictions from breaking Raft quorum). Set `cluster.enabled: true` in `values.yaml` to switch from a Deployment to a StatefulSet.

---

## CLI Reference

The `guardianwaf cluster` command provides six subcommands for querying and managing the cluster from the terminal. All subcommands work against any node — ban/unban requests automatically follow 307 redirects to the current leader.

**Common flags** (all subcommands):

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | from config `dashboard.listen` | Dashboard base URL |
| `--api-key` | `GWAF_DASHBOARD_API_KEY` env or config | Dashboard API key |
| `--timeout` | `5s` | Request timeout |
| `-c` / `--config` | platform default | Config file path |

### `cluster status` — detailed summary

Prints node identity, Raft state (term, commit/applied indices, replication lag), replicated store stats (bans/rules/counters), and the full peer list with leader marking.

```bash
guardianwaf cluster status
guardianwaf cluster status --url http://10.0.0.1:9443 --api-key SECRET
```

Sample output (leader node):

```
┌─────────────────────────────────────────────┐
│           GuardianWAF Cluster Status         │
└─────────────────────────────────────────────┘

  Node ID:        guardianwaf-0
  Role:           leader ★
  Term:           5
  Commit Index:   42
  Last Applied:   42
  Log Length:     42
  Replication Lag: 0

  Replicated Store:
    Bans:      3
    Rules:     7
    Counters:  12

  Cluster Members (3):
    ★ guardianwaf-0    (leader)
      guardianwaf-1    10.0.0.2:7947
      guardianwaf-2    10.0.0.3:7947

  ✓ This node is the cluster leader.
```

Exits 0 on success, 1 on error or when cluster mode is disabled.

### `cluster nodes` — peer table

Lists all known cluster members with their Raft addresses. The leader is marked with ★.

```bash
guardianwaf cluster nodes
```

Sample output:

```
ID               ROLE      ADDR                      LEADER
---------------  --------  ------------------------  ------
guardianwaf-0    leader    (self)                    ★
guardianwaf-1              10.0.0.2:7947
guardianwaf-2              10.0.0.3:7947

3 cluster member(s), leader: guardianwaf-0
```

### `cluster bans` — active ban list

Lists all non-expired banned IPs from the replicated store.

```bash
guardianwaf cluster bans
```

Sample output:

```
IP               BANNED AT                  EXPIRES AT
---------------  -------------------------  -------------------------
10.0.0.5         2026-08-07T14:30:00Z       2026-08-07T15:30:00Z
192.168.1.100    2026-08-07T13:00:00Z       permanent

2 active cluster-wide ban(s)
```

### `cluster ban` — ban an IP

Bans an IP cluster-wide via Raft consensus. The request automatically redirects to the leader if sent to a follower (up to 3 redirects).

```bash
# Ban for 1 hour (default)
guardianwaf cluster ban 10.0.0.5

# Custom duration and reason
guardianwaf cluster ban --duration 24h --reason "credential stuffing" 10.0.0.5

# Explicit endpoint
guardianwaf cluster ban --url http://10.0.0.1:9443 --api-key SECRET 10.0.0.5
```

| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | `1h` | Ban duration (Go duration string: `30m`, `1h`, `24h`) |
| `--reason` | `"manual ban from CLI"` | Reason recorded in the ban entry |

Sample output:

```
✓ Banned 10.0.0.5 for 1h0m0s (cluster-wide)
```

### `cluster unban` — remove a ban

Removes an IP from the cluster-wide ban list via Raft consensus.

```bash
guardianwaf cluster unban 10.0.0.5
```

Sample output:

```
✓ Removed ban on 10.0.0.5 (cluster-wide)
```

### `cluster health` — scriptable health check

Queries the cluster health endpoint and exits 0 if healthy, 1 if not. Minimal output — designed for cron jobs, init containers, and monitoring scripts.

```bash
# One-shot check
guardianwaf cluster health

# Use in a script
if guardianwaf cluster health --url http://10.0.0.1:9443; then
  echo "cluster is healthy"
else
  echo "cluster is unhealthy or unreachable" >&2
  exit 1
fi
```

Output:

```
OK: leader (leader=guardianwaf-0, term=5)
```

| Condition | Exit Code | Output |
|-----------|-----------|--------|
| Node is leader or follower | 0 | `OK: <role> (leader=<id>, term=<N>)` |
| Single-node mode (no cluster) | 0 | `OK: single-node` |
| Node reports unhealthy | 1 | `UNHEALTHY: <status>` |
| Connection refused / timeout | 1 | Error to stderr |

### Scripting patterns

**Environment variables**: Set these once for all cluster subcommands:

```bash
export GWAF_DASHBOARD_URL=http://guardianwaf:9443
export GWAF_DASHBOARD_API_KEY=secret

guardianwaf cluster status
guardianwaf cluster ban 10.0.0.5
guardianwaf cluster health
```

**Cron-based health monitoring**:

```bash
# /etc/cron.d/guardianwaf-cluster-check
*/1 * * * * root guardianwaf cluster health || systemctl restart guardianwaf
```

**Bulk ban from a feed**:

```bash
while read -r ip; do
  guardianwaf cluster ban --duration 24h --reason "threat feed" "$ip"
done < /etc/guardianwaf/threat-feed.txt
```

**Kubernetes init container** — wait for cluster before starting the WAF:

```yaml
initContainers:
  - name: wait-for-cluster
    image: ghcr.io/guardianwaf/guardianwaf:latest
    command: ['guardianwaf', 'cluster', 'health', '--url', 'http://localhost:9443']
    env:
      - name: GWAF_DASHBOARD_API_KEY
        valueFrom:
          secretKeyRef:
            name: guardianwaf-dashboard-auth
            key: api-key
```

**Leader redirect behavior**: `ban` and `unban` commands sent to a follower receive a 307 redirect to the leader's dashboard URL. The CLI follows up to 3 redirects automatically, re-authenticating each time. If the leader is unknown or redirects loop, the command fails with exit 1.

---

## Troubleshooting

### Cluster won't form

1. **Check ports**: Raft TCP (7947) and Gossip UDP (7946) must be open between all nodes.
2. **Check `node_id` uniqueness**: Each node must have a unique `node_id`.
3. **Check peer addresses**: At least one peer's Raft address must be reachable.
4. **Check logs**: Look for `gossip started`, `raft: starting election`, `became leader`.
5. **Use the CLI**: Run `guardianwaf cluster status` on each node — if `Member Count: 1`, gossip can't reach peers.

### No leader elected

1. Wait for election timeout (default 2-4 seconds after startup).
2. Check `guardianwaf_cluster_is_leader` — should be 1 on exactly one node.
3. If 0 on all nodes, the cluster has no majority — add nodes or check connectivity.
4. **Use the CLI**: Run `guardianwaf cluster status` — if `Role:` is empty or `Term:` is 0, the node hasn't started an election yet.

### Ban not replicating

1. Check `guardianwaf_cluster_raft_commit_index` is advancing on all nodes.
2. Check `commit_index - last_applied` is near 0 — high lag means the apply loop is stuck.
3. **Use the CLI**: Run `guardianwaf cluster status` on each node and compare `Commit Index` values — diverging values indicate replication failure.
4. Send the ban to the **leader** node directly (the CLI shows `★` next to the leader; or check `/api/v1/cluster/status`).
5. Check for `ErrRaftNotLeader` errors in the logs.

### Redirect not working (503 instead of 307)

1. Verify gossip is running: check `/api/v1/cluster/nodes` — if empty, gossip didn't converge.
2. The leader's `DashboardAddr` must be non empty in the gossip member list.
3. If using static peers only (no gossip), redirects are not available — the 503 response includes `leader_id` for manual retry.

### Network partition (split-brain)

A network partition isolates one or more nodes from the rest of the cluster. GuardianWAF's Raft implementation guarantees that **only the majority partition can commit entries** — the minority cannot accept bans, unban, or rule changes.

**Symptoms:**

- One or more nodes report `not ready` on `/readyz` (gossip isolation detected).
- Bans sent to a minority node fail — the node is either not the leader or cannot reach the majority.
- The `guardianwaf_cluster_member_count` metric drops on partitioned nodes.

**Diagnosis:**

```bash
# Check which nodes the local node can see
guardianwaf cluster status

# Or query each node individually
kubectl exec guardianwaf-0 -- guardianwaf cluster status --url http://localhost:9443
kubectl exec guardianwaf-1 -- guardianwaf cluster status --url http://localhost:9443
kubectl exec guardianwaf-2 -- guardianwaf cluster status --url http://localhost:9443
```

If a node shows `Member Count: 1` (only itself) while others show 3, that node is partitioned.

**Expected behavior during partition (verified by integration tests):**

| Cluster size | Partitioned | Quorum | Behavior |
|---|---|---|---|
| 3 nodes | 1 isolated | 2 of 3 | Majority continues serving. Isolated node goes `not ready`. |
| 5 nodes | 2 isolated | 3 of 5 | Majority continues serving. Isolated nodes go `not ready`. |
| 3 nodes | 2 isolated | 1 of 3 | **No quorum** — cluster stops accepting writes until healed. |

**Recovery:**

1. Restore network connectivity between the nodes.
2. The partitioned node automatically rejoins via gossip probe convergence.
3. Raft log replication catches up — the node receives all committed entries it missed.
4. The readiness probe (`/readyz`) returns 200 once gossip sees ≥2 members.

No manual intervention is needed for healing. The cluster was tested with:

- `TestPartition_MinorityCannotCommit` — verifies a partitioned node can't commit bans.
- `TestPartition_HealCatchUp` — verifies the partitioned node receives missed bans after healing.
- `TestPartition_MajorityLeaderStable` — verifies the majority leader stays stable during partition.
- `TestPartition_FollowerRedirectMajorityLeader` — verifies follower redirects still reach the majority leader.

**Chaos tests** (leader failover):

- `TestChaos_KillLeaderCommittedBansSurvive` — committed bans survive leader failure.
- `TestChaos_SecondLeaderKill` — cluster survives double leader failure (5-node cluster).
- `TestChaos_StoreConsistencyAfterFailover` — no split-brain after failover.

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

---

## Production Readiness Checklist

Before deploying GuardianWAF cluster mode to production, review each item below.
Items marked **[limitation]** describe known constraints with recommended mitigations.

### Cluster Size & Quorum

- [ ] **Use an odd number of nodes (3 or 5).** Raft requires a majority quorum to commit entries.
  3 nodes tolerates 1 failure; 5 nodes tolerates 2 failures. Even numbers waste a node without improving fault tolerance.
- [ ] **Never run 2 nodes in production.** Losing either node leaves no quorum — the cluster stalls.
- [ ] **Spread nodes across failure domains.** Use Kubernetes `podAntiAffinity` (see the StatefulSet manifest) or deploy to different physical hosts / availability zones.
- [ ] **Set a PodDisruptionBudget** with `minAvailable: 2` (for 3-node clusters) to prevent voluntary evictions from breaking quorum.

### Network Security

- [ ] **Isolate cluster ports on a private network.** Raft (TCP 7947) and gossip (UDP 7946) carry no TLS — they must not be exposed to untrusted networks.

  ```yaml
  # Kubernetes NetworkPolicy example — restrict inter-node traffic
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: guardianwaf-cluster-net
  spec:
    podSelector:
      matchLabels:
        app: guardianwaf
    policyTypes:
      - Ingress
      - Egress
    ingress:
      - from:
          - podSelector:
              matchLabels:
                app: guardianwaf
        ports:
          - protocol: TCP
            port: 7947
          - protocol: UDP
            port: 7946
    egress:
      - to:
          - podSelector:
              matchLabels:
                app: guardianwaf
        ports:
          - protocol: TCP
            port: 7947
          - protocol: UDP
            port: 7946
  ```

- **[limitation] No inter-node TLS.** The Raft TCP transport and gossip UDP transport use plaintext communication. Mitigations:
  - Deploy on a private subnet or VPC with security group rules limiting port 7947/7946 to cluster members only.
  - Use a service mesh (Istio, Linkerd) with mTLS for sidecar-level encryption.
  - In Kubernetes, the NetworkPolicy above restricts traffic to same-label pods.
  - TLS support for inter-node traffic is planned for a future release.

### Persistence & Backup

- **[limitation] Raft log is in-memory.** The current Raft implementation stores its log, current term, and vote in memory (`internal/cluster/raft/state.go`). A full cluster restart loses all replicated state. Mitigations:

  - **Export the ban list before maintenance.** Use the API to dump all active bans, then re-apply them after restart:

    ```bash
    # Export current bans (run on the leader)
    guardianwaf cluster status  # find the leader
    curl -s -H "X-API-Key: $KEY" http://leader:9443/api/v1/cluster/bans | jq '.bans[].ip' > bans.txt

    # Re-apply after restart
    while read ip; do
      guardianwaf cluster ban --duration 24h "$ip"
    done < bans.txt
    ```

  - **For zero-downtime rolling updates**, restart one node at a time. The surviving majority maintains the ban list in memory and replicates it to the restarted node when it rejoins.

  - **For planned full-cluster restarts**, drain the ban list to a file first (above), then re-apply after restart.

  - **Persisted Raft log (WAL) is planned** — the `PersistentState` API is already designed with locking so a WAL layer can be added without changing callers.

- **[limitation] No log compaction or snapshots.** The Raft log grows unboundedly during the lifetime of a node. For long-running deployments, restart nodes periodically (one at a time, maintaining quorum) to reset their log. Snapshot/log-compaction support is planned.

### Resource Sizing

| Cluster Size | Min Memory/Node | Min CPU/Node | Tolerated Failures | Use Case |
|---|---|---|---|---|
| 3 nodes | 256 Mi | 500m | 1 | Development, small production |
| 5 nodes | 256 Mi | 500m | 2 | Production with high availability |
| 7 nodes | 256 Mi | 500m | 3 | Large production (rarely needed) |

The replicated store (bans, rules, counters) is small — typically a few MB even with thousands of bans. The primary memory consumers are the WAF detection engines and event buffers, not the cluster subsystem.

### Monitoring & Alerting

- [ ] **Import the cluster Grafana dashboard** (`contrib/grafana/cluster-dashboard.json`). See [Monitoring](#monitoring).
- [ ] **Alert on replication lag > 10.** `guardianwaf_cluster_raft_commit_index - guardianwaf_cluster_raft_last_applied > 10` means the state machine is falling behind. Check for disk I/O issues or a stuck apply loop.
- [ ] **Alert on no leader.** `max(guardianwaf_cluster_is_leader) == 0` across all nodes means the cluster has no leader — no writes can succeed.
- [ ] **Alert on member count drop.** `guardianwaf_cluster_member_count < 2` on any node means it's isolated — the readiness probe will return 503.

### Operational Procedures

**Rolling restart (zero downtime):**

1. Restart one node at a time, waiting for it to rejoin and `/readyz` to return 200 before proceeding to the next.
2. Verify quorum is maintained: `guardianwaf cluster status` should show 2+ members alive during the restart.

**Scaling up (3 → 5 nodes):**

1. Deploy the 2 new nodes with the same cluster config.
2. Gossip discovers them automatically — no manual peer configuration needed.
3. Raft includes them in the quorum once they're reachable.
4. Verify with `guardianwaf cluster status` — member count should increase.

**Scaling down (5 → 3 nodes):**

1. Remove one node at a time.
2. Wait for gossip to mark it dead and Raft to adjust quorum.
3. Never remove 2 nodes simultaneously from a 5-node cluster — you'll lose quorum.

**Leader failover:**

- No manual action needed. Raft elects a new leader automatically (typically within 2–4 seconds based on election timeout settings).
- Verify with `guardianwaf cluster status` after a failover.
- Committed bans survive failover (verified by `TestChaos_KillLeaderCommittedBansSurvive`).

