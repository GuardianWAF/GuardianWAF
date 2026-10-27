// Package peersync bridges the gossip membership layer with the Raft consensus
// layer for observability. Gossip failure detection never changes the Raft
// voting configuration: a partition must not reduce the majority needed to
// elect a leader. Voters are configured explicitly on every node.
package peersync

import (
	"log/slog"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// GossipMemberList is the minimal subset of gossip.Gossip needed by the bridge.
type GossipMemberList interface {
	Members() []gossip.Member
}

// Bridge watches gossip membership without changing Raft voters. Dynamic
// consensus membership is unsupported; operators must configure the same fixed
// voting set on every node (excluding that node itself).
type Bridge struct {
	gossip GossipMemberList
	raft   *raft.Raft
	log    *slog.Logger

	mu        sync.Mutex
	lastPeers map[string]bool // peer IDs from the last sync, for diff logging
}

// NewBridge creates a peer-sync bridge. After calling NewBridge, wire the
// join/leave callbacks via Callbacks(), then start gossip.
func NewBridge(g GossipMemberList, r *raft.Raft, logger *slog.Logger) *Bridge {
	if logger == nil {
		logger = slog.Default()
	}
	return &Bridge{
		gossip:    g,
		raft:      r,
		log:       logger,
		lastPeers: make(map[string]bool),
	}
}

// Callbacks returns onJoin/onLeave functions suitable for
// gossip.Gossip.SetCallbacks. The callbacks trigger Sync(), which recomputes
// observed liveness from the full gossip member list.
func (b *Bridge) Callbacks() (onJoin func(id, addr string), onLeave func(id string)) {
	return b.onJoin, b.onLeave
}

func (b *Bridge) onJoin(id, addr string) {
	b.log.Info("peersync: member joined, syncing raft peers",
		"member_id", id, "gossip_addr", addr)
	b.Sync()
}

func (b *Bridge) onLeave(id string) {
	b.log.Info("peersync: member left, syncing raft peers",
		"member_id", id)
	b.Sync()
}

// Sync records observed liveness only. A dead or newly discovered gossip member
// is not a consensus configuration change. In particular, the configured peer
// list must survive an empty or partitioned gossip view unchanged.
func (b *Bridge) Sync() {
	b.mu.Lock()
	defer b.mu.Unlock()
	peerIDs := make(map[string]bool)
	for _, m := range b.gossip.Members() {
		if m.State == gossip.StateAlive && m.ID != b.raft.ID() {
			peerIDs[m.ID] = true
		}
	}
	for id := range peerIDs {
		if !b.lastPeers[id] {
			b.log.Info("peersync: gossip member observed alive; voting configuration unchanged", "peer_id", id)
		}
	}
	for id := range b.lastPeers {
		if !peerIDs[id] {
			b.log.Info("peersync: gossip member unavailable; voting configuration unchanged", "peer_id", id)
		}
	}
	b.lastPeers = peerIDs
}
