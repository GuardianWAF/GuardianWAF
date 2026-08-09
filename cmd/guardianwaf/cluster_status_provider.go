package main

import (
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
}

// NewClusterStatusProvider creates a dashboard-compatible status provider
// from the cluster runtime resources.
func NewClusterStatusProvider(r *raft.Raft, store *clustersync.ReplicatedStore) dashboard.ClusterStatusProvider {
	return &clusterStatusProvider{raft: r, store: store}
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
