# Distributed Clustering

GuardianWAF supports distributed clustering for high-availability deployments. Multiple WAF nodes can form a cluster to share state, synchronize IP bans, and elect a leader for coordination tasks.

## Features

- **Leader Election**: Automatic leader election using lowest-node-ID algorithm
- **State Synchronization**: Distributed IP ban lists and rate limits across all nodes
- **Heartbeat Mechanism**: Health monitoring with configurable intervals and timeouts
- **HTTP-based Communication**: Zero external dependencies, uses Go standard library only
- **Graceful Join/Leave**: Nodes can join and leave the cluster without disruption
- **Failure Detection**: Automatic detection and handling of failed nodes

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Node A    │◄───►│   Node B    │◄───►│   Node C    │
│  (Leader)   │     │  (Follower) │     │  (Follower) │
└─────────────┘     └─────────────┘     └─────────────┘
       ▲                   ▲                   ▲
       │                   │                   │
       └───────────────────┴───────────────────┘
              Heartbeat (every 5s)
              State Sync (every 30s)
```

### Node States

- `joining`: Node is joining the cluster
- `active`: Node is active and participating
- `leaving`: Node is gracefully leaving
- `failed`: Node has failed heartbeat check
- `leader`: Node is the cluster leader

### Message Types

- `heartbeat`: Periodic health check
- `state_sync`: Distributed state synchronization
- `ip_ban`: Propagate IP ban across cluster
- `ip_unban`: Propagate IP unban across cluster
- `rate_limit`: Rate limit updates
- `config_update`: Configuration changes
- `leader_election`: Leader election announcement

## Configuration

```yaml
waf:
  cluster:
    enabled: true
    node_id: "node-1"              # Optional: auto-generated if empty
    bind_addr: "0.0.0.0"           # Bind address for cluster communication
    bind_port: 7946                # Port for cluster HTTP API
    advertise_addr: ""             # Optional: address to advertise (defaults to bind_addr)
    seed_nodes:                    # List of existing cluster nodes to join
      - "192.168.1.10:7946"
      - "192.168.1.11:7946"
    sync_interval: 30s             # State sync interval
    heartbeat_interval: 5s         # Heartbeat interval
    heartbeat_timeout: 15s         # Node failure timeout
    leader_election_timeout: 30s   # Leader election timeout
    max_nodes: 10                  # Maximum cluster size
```

## API Endpoints

Each cluster node exposes HTTP endpoints on the configured bind port:

### POST /cluster/join
Join a new node to the cluster.

**Request:**
```json
{
  "id": "node-2",
  "address": "192.168.1.12",
  "port": 7946,
  "state": "joining",
  "metadata": {}
}
```

### POST /cluster/message
Send a message to the node.

**Request:**
```json
{
  "type": "heartbeat",
  "from": "node-1",
  "timestamp": "2024-01-15T10:30:00Z",
  "payload": {}
}
```

### GET /cluster/nodes
List all cluster nodes.

**Response:**
```json
[
  {
    "id": "node-1",
    "address": "192.168.1.10",
    "port": 7946,
    "state": "active",
    "is_leader": true,
    "last_heartbeat": "2024-01-15T10:30:00Z"
  }
]
```

### GET /cluster/health
Get node health status.

**Response:**
```json
{
  "status": "active",
  "node_id": "node-1",
  "is_leader": true,
  "nodes": 3
}
```

## Usage

### Starting a Cluster

1. **First node** (becomes leader automatically):
```yaml
waf:
  cluster:
    enabled: true
    node_id: "node-1"
    bind_addr: "0.0.0.0"
    bind_port: 7946
    seed_nodes: []  # No seeds for first node
```

2. **Additional nodes** (join via seed):
```yaml
waf:
  cluster:
    enabled: true
    node_id: "node-2"
    bind_addr: "0.0.0.0"
    bind_port: 7946
    seed_nodes:
      - "192.168.1.10:7946"  # First node's address
```

### WAF Pipeline Integration

The cluster layer runs at order 75 (early in the pipeline) to check cluster-wide IP bans before rate limiting:

```
Order 75: Cluster (IP ban check)
Order 100: IP ACL
Order 125: Threat Intel
...
```

When an IP is banned on any node, the ban is propagated to all cluster nodes within the sync interval.

### Leader Election

The cluster uses a deterministic leader election algorithm:
- The node with the lowest lexicographical ID becomes leader
- If the leader fails, a new election is triggered automatically
- Only the leader performs certain coordination tasks (state sync)

### Monitoring

Check cluster status via the integrator:

```go
stats := integrator.GetStats()
fmt.Printf("Cluster enabled: %v\n", stats.ClusterEnabled)
fmt.Printf("Node count: %d\n", stats.ClusterNodeCount)
fmt.Printf("Is leader: %v\n", stats.ClusterIsLeader)
```

## Security Considerations

1. **Network Isolation**: Cluster communication should be on a private network
2. **Firewall Rules**: Only allow cluster port (7946) between WAF nodes
3. **Node Authentication**: Consider mTLS for cluster communication in production
4. **Seed Nodes**: Use reliable nodes as seeds to ensure join reliability

## Troubleshooting

### Node fails to join cluster
- Verify seed node addresses are correct and reachable
- Check firewall rules allow traffic on cluster port
- Ensure node_id is unique across the cluster

### Leader election issues
- Check logs for election messages
- Verify all nodes can communicate with each other
- Restart failed nodes to trigger re-election

### State sync delays
- Reduce `sync_interval` for faster propagation
- Check network latency between nodes
- Monitor node resource usage

## Performance

- **Heartbeat**: Every 5 seconds (configurable)
- **State Sync**: Every 30 seconds (configurable)
- **Max Nodes**: 10 nodes (configurable)
- **Memory**: ~1MB per node for state storage
- **Network**: ~1KB per heartbeat, ~10KB per state sync

## Limitations

- No automatic data persistence (state is in-memory)
- Split-brain possible if network partitions (mitigated by leader election)
- Maximum recommended cluster size: 10 nodes
- No WAN optimization (designed for LAN deployments)
