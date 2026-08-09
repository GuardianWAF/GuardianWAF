// Package peersync bridges the gossip membership layer with the Raft consensus
// layer. When gossip detects a node joining or leaving the cluster, the bridge
// recomputes the alive peer set (with Raft TCP addresses) and calls
// raft.UpdatePeers so the Raft leader replicates to the new node or stops
// replicating to the departed one.
package peersync

import (
	"log/slog"
	"sort"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// GossipMemberList is the minimal subset of gossip.Gossip needed by the bridge.
type GossipMemberList interface {
	Members() []gossip.Member
}

// Bridge watches gossip membership events and propagates alive peers to Raft.
// This enables dynamic peer discovery: new nodes that join via gossip are
// automatically added to the Raft configuration without manual restart or
// YAML reconfiguration.
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
// the alive peer set from the full gossip member list.
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

// Sync recomputes the alive peer set from gossip membership and updates Raft.
// Only members in StateAlive with a non-empty RaftAddr are included.
// This method is safe to call concurrently — it serializes on an internal mutex.
func (b *Bridge) Sync() {
	b.mu.Lock()
	defer b.mu.Unlock()

	members := b.gossip.Members()
	peers := make([]raft.Peer, 0, len(members))
	peerIDs := make(map[string]bool, len(members))

	for _, m := range members {
		if m.State != gossip.StateAlive {
			continue
		}
		if m.RaftAddr == "" {
			// Member hasn't announced a Raft address yet — skip.
			b.log.Debug("peersync: skipping member without raft_addr",
				"member_id", m.ID)
			continue
		}
		peers = append(peers, raft.Peer{
			ID:   m.ID,
			Addr: m.RaftAddr,
		})
		peerIDs[m.ID] = true
	}

	// Sort peers by ID for deterministic ordering (stable Raft config).
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})

	b.raft.UpdatePeers(peers)

	// Log diff if peer set changed.
	changed := false
	for id := range peerIDs {
		if !b.lastPeers[id] {
			changed = true
			b.log.Info("peersync: peer added to raft config", "peer_id", id)
		}
	}
	for id := range b.lastPeers {
		if !peerIDs[id] {
			changed = true
			b.log.Info("peersync: peer removed from raft config", "peer_id", id)
		}
	}
	if changed {
		b.log.Info("peersync: raft peer set updated",
			"peer_count", len(peers))
	}

	b.lastPeers = peerIDs
}
