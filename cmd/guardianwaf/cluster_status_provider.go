package main

import (
	"errors"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
	"github.com/guardianwaf/guardianwaf/internal/clustersync"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
)

// clusterStatusProvider adapts the Raft node, replicated store, and gossip
// membership to the dashboard.ClusterStatusProvider interface. This avoids a
// circular import between the dashboard and clustersync packages.
type clusterStatusProvider struct {
	raft   *raft.Raft
	store  *clustersync.ReplicatedStore
	api    *clustersync.API
	gossip *gossip.Gossip // may be nil when gossip is not used
}

// NewClusterStatusProvider creates a dashboard-compatible status provider
// from the cluster runtime resources. The api is used for write operations
// (ProposeBan, ProposeUnban); it may be nil for read-only providers.
// gossip may be nil when gossip membership is not active.
func NewClusterStatusProvider(r *raft.Raft, store *clustersync.ReplicatedStore, api *clustersync.API, g *gossip.Gossip) dashboard.ClusterStatusProvider {
	return &clusterStatusProvider{raft: r, store: store, api: api, gossip: g}
}

func (p *clusterStatusProvider) Enabled() bool       { return true }
func (p *clusterStatusProvider) NodeID() string      { return p.raft.ID() }
func (p *clusterStatusProvider) CurrentTerm() uint64 { return p.raft.Term() }
func (p *clusterStatusProvider) CommitIndex() uint64 { return p.raft.CommitIndex() }
func (p *clusterStatusProvider) LastApplied() uint64 { return p.raft.LastApplied() }

func (p *clusterStatusProvider) Role() string {
	return p.raft.Role().String()
}

func (p *clusterStatusProvider) LeaderID() string {
	return p.raft.LeaderID()
}

func (p *clusterStatusProvider) LogLength() uint64 {
	return p.raft.Log().LastIndex()
}

// Peers returns the Raft peer list enriched with dashboard URLs from gossip
// membership. When gossip is active, each peer's DashboardURL is populated
// from the member's DashboardAddr field, enabling leader-redirect (307)
// responses from follower nodes.
func (p *clusterStatusProvider) Peers() []dashboard.ClusterPeerInfo {
	raftPeers := p.raft.Peers()

	// Build a lookup of peer ID → dashboard URL from gossip members.
	dashURLByPeerID := make(map[string]string, len(raftPeers))
	if p.gossip != nil {
		for _, m := range p.gossip.Members() {
			if m.DashboardAddr != "" {
				dashURLByPeerID[m.ID] = normalizeURL(m.DashboardAddr)
			}
		}
	}

	result := make([]dashboard.ClusterPeerInfo, len(raftPeers))
	for i, rp := range raftPeers {
		result[i] = dashboard.ClusterPeerInfo{
			ID:           rp.ID,
			Addr:         rp.Addr,
			DashboardURL: dashURLByPeerID[rp.ID],
		}
	}
	return result
}

func (p *clusterStatusProvider) StoreStats() dashboard.ClusterStoreStats {
	s := p.store.Stats()
	return dashboard.ClusterStoreStats{
		Bans:     s.Bans,
		Rules:    s.Rules,
		Counters: s.Counters,
	}
}

func (p *clusterStatusProvider) BannedIPs() []dashboard.ClusterBanInfo {
	entries := p.store.BannedIPs()
	result := make([]dashboard.ClusterBanInfo, len(entries))
	for i, e := range entries {
		info := dashboard.ClusterBanInfo{
			IP:       e.IP,
			BannedAt: e.BannedAt.Format(time.RFC3339),
		}
		if !e.ExpiresAt.IsZero() {
			info.ExpiresAt = e.ExpiresAt.Format(time.RFC3339)
		}
		result[i] = info
	}
	return result
}

// ProposeBan proposes banning an IP cluster-wide via the Raft consensus layer.
// Returns clustersync.ErrRaftNotLeader if this node is not the leader.
func (p *clusterStatusProvider) ProposeBan(ip string, duration time.Duration) error {
	return p.api.ProposeBan(ip, duration)
}

// ProposeUnban proposes removing an IP from the cluster-wide ban list.
// Returns clustersync.ErrRaftNotLeader if this node is not the leader.
func (p *clusterStatusProvider) ProposeUnban(ip string) error {
	return p.api.ProposeUnban(ip)
}

// IsNotLeader reports whether an error returned by ProposeBan/ProposeUnban
// means "this node is not the Raft leader". The dashboard uses this to decide
// whether to return a leader-redirect (307) or a generic 503.
func (p *clusterStatusProvider) IsNotLeader(err error) bool {
	return errors.Is(err, clustersync.ErrRaftNotLeader) || errors.Is(err, raft.ErrNotLeader)
}

// normalizeURL ensures the dashboard address has a scheme prefix.
// "0.0.0.0:8080" becomes "http://0.0.0.0:8080".
// An address that already has a scheme is returned as-is.
func normalizeURL(addr string) string {
	if addr == "" {
		return ""
	}
	if len(addr) > 7 && (addr[:7] == "http://" || addr[:8] == "https://") {
		return addr
	}
	return "http://" + addr
}
