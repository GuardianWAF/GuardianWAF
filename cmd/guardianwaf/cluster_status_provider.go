package main

import (
	"errors"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
	"github.com/guardianwaf/guardianwaf/internal/clustersync"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
)

// clusterStatusProvider adapts the Raft node and replicated store to the
// dashboard.ClusterStatusProvider interface. This avoids a circular import
// between the dashboard and clustersync packages.
type clusterStatusProvider struct {
	raft  *raft.Raft
	store *clustersync.ReplicatedStore
	api   *clustersync.API
}

// NewClusterStatusProvider creates a dashboard-compatible status provider
// from the cluster runtime resources. The api is used for write operations
// (ProposeBan, ProposeUnban); it may be nil for read-only providers.
func NewClusterStatusProvider(r *raft.Raft, store *clustersync.ReplicatedStore, api *clustersync.API) dashboard.ClusterStatusProvider {
	return &clusterStatusProvider{raft: r, store: store, api: api}
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
	id := p.raft.LeaderID()
	return id
}

func (p *clusterStatusProvider) LogLength() uint64 {
	return p.raft.Log().LastIndex()
}

func (p *clusterStatusProvider) Peers() []dashboard.ClusterPeerInfo {
	raftPeers := p.raft.Peers()
	result := make([]dashboard.ClusterPeerInfo, len(raftPeers))
	for i, rp := range raftPeers {
		result[i] = dashboard.ClusterPeerInfo{
			ID:   rp.ID,
			Addr: rp.Addr,
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
