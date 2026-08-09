package dashboard

import (
	"net/http"
	"time"
)

// ClusterStatusProvider exposes cluster health and replicated-store state to the
// dashboard without creating a circular import. The main binary implements this
// with concrete types from internal/clustersync and internal/cluster/raft.
type ClusterStatusProvider interface {
	// Enabled returns true when cluster mode is active.
	Enabled() bool

	// NodeID returns this node's Raft ID.
	NodeID() string

	// Role returns the Raft role string ("leader", "candidate", "follower").
	Role() string

	// LeaderID returns the current leader's node ID, or "" if unknown.
	LeaderID() string

	// CurrentTerm returns the current Raft term.
	CurrentTerm() uint64

	// CommitIndex returns the Raft commit index.
	CommitIndex() uint64

	// LastApplied returns the last applied log index.
	LastApplied() uint64

	// LogLength returns the number of entries in the Raft log.
	LogLength() uint64

	// Peers returns the list of configured peer node IDs and addresses.
	Peers() []ClusterPeerInfo

	// StoreStats returns summary statistics for the replicated store.
	StoreStats() ClusterStoreStats

	// BannedIPs returns all non-expired banned IPs in the replicated store.
	BannedIPs() []ClusterBanInfo

	// ProposeBan proposes banning an IP cluster-wide. Returns an error if
	// this node is not the Raft leader or the proposal fails.
	ProposeBan(ip string, duration time.Duration) error

	// ProposeUnban proposes removing an IP from the cluster-wide ban list.
	ProposeUnban(ip string) error

	// IsNotLeader reports whether the given error from ProposeBan/ProposeUnban
	// indicates that this node is not the Raft leader. The dashboard uses this
	// to return a leader-redirect response instead of a generic 503.
	IsNotLeader(err error) bool
}

// ClusterIsolationChecker reports whether this node is isolated from the
// gossip mesh. The readiness probe uses this to take the node out of the
// load-balancer rotation when it can't reach its peers.
type ClusterIsolationChecker interface {
	// IsIsolated returns true when this node cannot reach enough peers to
	// form or maintain quorum. When true, /readyz returns 503.
	IsIsolated() bool

	// MemberCount returns the number of alive gossip members (including self).
	MemberCount() int
}

// ClusterBanMutationResult describes the outcome of a cluster ban/unban request.
type ClusterBanMutationResult struct {
	Proposed bool   `json:"proposed"`
	NodeID   string `json:"node_id,omitempty"`
	Role     string `json:"role,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ClusterPeerInfo describes a single cluster peer.
type ClusterPeerInfo struct {
	ID           string `json:"id"`
	Addr         string `json:"addr"`          // Raft TCP address
	DashboardURL string `json:"dashboard_url"` // Dashboard HTTP base URL (e.g., "http://10.0.0.2:8080")
}

// ClusterStoreStats is a point-in-time snapshot of replicated store sizes.
type ClusterStoreStats struct {
	Bans     int `json:"bans"`
	Rules    int `json:"rules"`
	Counters int `json:"counters"`
}

// ClusterBanInfo describes a single banned IP.
type ClusterBanInfo struct {
	IP        string `json:"ip"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at"`
}

// registerCluster registers cluster health and store inspection routes.
func (d *Dashboard) registerCluster(mux *http.ServeMux) {
	// Legacy v0 endpoints (no-auth convenience for backward compatibility)
	mux.HandleFunc("GET /api/clusters", d.authWrap(d.handleClusterList))
	mux.HandleFunc("GET /api/clusters/{id}", d.authWrap(d.handleClusterNotFound))
	mux.HandleFunc("POST /api/clusters", d.authAuditWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("POST /api/clusters/{id}", d.authAuditWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("DELETE /api/clusters/{id}", d.authAuditWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("GET /api/nodes", d.authWrap(d.handleClusterNodesLegacy))
	mux.HandleFunc("GET /api/sync/stats", d.authWrap(d.handleSyncStats))
	mux.HandleFunc("GET /api/sync/status", d.authWrap(d.handleSyncStatus))

	// v1 endpoints
	mux.HandleFunc("GET /api/v1/cluster/status", d.authWrap(d.handleClusterStatus))
	mux.HandleFunc("GET /api/v1/cluster/store", d.authWrap(d.handleClusterStore))
	mux.HandleFunc("GET /api/v1/cluster/bans", d.authWrap(d.handleClusterBans))
	mux.HandleFunc("GET /api/v1/cluster/nodes", d.authWrap(d.handleClusterNodes))
	mux.HandleFunc("GET /api/v1/cluster/health", d.authWrap(d.handleClusterHealth))
	mux.HandleFunc("GET /api/v1/cluster/node/stats", d.authWrap(d.handleClusterNodeStats))
	mux.HandleFunc("GET /api/v1/cluster/config", d.authWrap(d.handleClusterConfig))
}

// --- Legacy v0 handlers ---

func (d *Dashboard) handleClusterList(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"clusters": []any{},
			"message":  "cluster mode is not configured",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clusters": []map[string]any{{
			"id":        d.clusterStatus.NodeID(),
			"role":      d.clusterStatus.Role(),
			"leader_id": d.clusterStatus.LeaderID(),
			"peers":     len(d.clusterStatus.Peers()),
		}},
	})
}

func (d *Dashboard) handleClusterNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error": "cluster not found",
	})
}

func (d *Dashboard) handleClusterMutationDisabled(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":   "cluster mutations are not available via this endpoint",
		"message": "use the clustersync API (ProposeBan, ProposeSetRule, etc.) to modify cluster state",
	})
}

func (d *Dashboard) handleClusterNodesLegacy(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes":    []any{},
			"disabled": true,
		})
		return
	}
	peers := d.clusterStatus.Peers()
	nodes := make([]map[string]any, len(peers))
	for i, p := range peers {
		nodes[i] = map[string]any{
			"id":   p.ID,
			"addr": p.Addr,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes":    nodes,
		"disabled": false,
	})
}

func (d *Dashboard) handleSyncStats(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"message": "cluster sync is not configured",
		})
		return
	}
	stats := d.clusterStatus.StoreStats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"bans":     stats.Bans,
		"rules":    stats.Rules,
		"counters": stats.Counters,
	})
}

func (d *Dashboard) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"syncing": false,
			"message": "cluster sync is not configured",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"syncing":      false,
		"role":         d.clusterStatus.Role(),
		"leader_id":    d.clusterStatus.LeaderID(),
		"term":         d.clusterStatus.CurrentTerm(),
		"commit_index": d.clusterStatus.CommitIndex(),
	})
}

// --- v1 additional handlers ---

// handleClusterNodes returns the list of cluster peer nodes with their
// role and address. The local node is included.
func (d *Dashboard) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"nodes":   []any{},
		})
		return
	}
	peers := d.clusterStatus.Peers()
	nodes := make([]map[string]any, 0, len(peers)+1)
	// Include self
	nodes = append(nodes, map[string]any{
		"id":        d.clusterStatus.NodeID(),
		"role":      d.clusterStatus.Role(),
		"is_leader": d.clusterStatus.LeaderID() == d.clusterStatus.NodeID(),
	})
	for _, p := range peers {
		nodes = append(nodes, map[string]any{
			"id":        p.ID,
			"addr":      p.Addr,
			"is_leader": p.ID == d.clusterStatus.LeaderID(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"nodes":   nodes,
	})
}

// handleClusterHealth returns a simplified health check for load balancers
// and orchestrators. Returns 200 with role=leader/follower.
func (d *Dashboard) handleClusterHealth(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "single-node",
			"healthy": true,
		})
		return
	}
	role := d.clusterStatus.Role()
	healthy := role != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    role,
		"healthy":   healthy,
		"leader_id": d.clusterStatus.LeaderID(),
		"term":      d.clusterStatus.CurrentTerm(),
	})
}

// handleClusterNodeStats returns per-node Raft and store statistics for
// observability dashboards.
func (d *Dashboard) handleClusterNodeStats(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
		})
		return
	}
	stats := d.clusterStatus.StoreStats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"node_id":      d.clusterStatus.NodeID(),
		"role":         d.clusterStatus.Role(),
		"term":         d.clusterStatus.CurrentTerm(),
		"commit_index": d.clusterStatus.CommitIndex(),
		"last_applied": d.clusterStatus.LastApplied(),
		"log_length":   d.clusterStatus.LogLength(),
		"store": map[string]any{
			"bans":     stats.Bans,
			"rules":    stats.Rules,
			"counters": stats.Counters,
		},
	})
}

// handleClusterConfig returns the cluster configuration (read-only) for
// debugging. Sensitive data (addresses) is included since the endpoint
// requires authentication.
func (d *Dashboard) handleClusterConfig(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
		})
		return
	}
	peers := d.clusterStatus.Peers()
	peerList := make([]map[string]any, len(peers))
	for i, p := range peers {
		peerList[i] = map[string]any{"id": p.ID, "addr": p.Addr}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"node_id": d.clusterStatus.NodeID(),
		"peers":   peerList,
	})
}

// handleClusterStatus returns cluster health: role, leader, term, commit index,
// and peer list. When clustering is disabled, returns enabled=false.
func (d *Dashboard) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"message": "cluster mode is not configured",
		})
		return
	}

	cs := d.clusterStatus
	peers := cs.Peers()
	peerList := make([]map[string]any, len(peers))
	for i, p := range peers {
		peerList[i] = map[string]any{"id": p.ID, "addr": p.Addr}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"node_id":      cs.NodeID(),
		"role":         cs.Role(),
		"leader_id":    cs.LeaderID(),
		"is_leader":    cs.LeaderID() == cs.NodeID() && cs.LeaderID() != "",
		"term":         cs.CurrentTerm(),
		"commit_index": cs.CommitIndex(),
		"last_applied": cs.LastApplied(),
		"log_length":   cs.LogLength(),
		"peers":        peerList,
	})
}

// handleClusterStore returns a snapshot of the replicated store: ban count,
// rule count, and counter count.
func (d *Dashboard) handleClusterStore(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
		})
		return
	}

	stats := d.clusterStatus.StoreStats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  true,
		"bans":     stats.Bans,
		"rules":    stats.Rules,
		"counters": stats.Counters,
	})
}

// handleClusterBans returns the full list of non-expired banned IPs from the
// replicated store. When clustering is disabled, returns an empty list.
func (d *Dashboard) handleClusterBans(w http.ResponseWriter, r *http.Request) {
	if d.clusterStatus == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"bans":    []any{},
		})
		return
	}

	bans := d.clusterStatus.BannedIPs()
	banList := make([]map[string]any, len(bans))
	for i, b := range bans {
		entry := map[string]any{
			"ip":        b.IP,
			"banned_at": b.BannedAt,
		}
		if b.ExpiresAt != "" {
			entry["expires_at"] = b.ExpiresAt
		}
		banList[i] = entry
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"bans":    banList,
	})
}
