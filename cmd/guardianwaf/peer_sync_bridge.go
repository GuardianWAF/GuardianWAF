package main

import (
	"log/slog"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// PeerSyncBridge listens to gossip membership events (join/leave) and
// propagates the alive member set to the Raft node via UpdatePeers.
//
// When a new node joins the gossip mesh, the bridge adds it to the Raft peer
// list so the leader can begin replicating to it. When a node leaves (or is
// marked dead), the bridge removes it from the peer list.
//
// The bridge debounces membership changes — it rebuilds the full peer list
// from the gossip member snapshot on each event rather than incrementally
// mutating, which is simpler and avoids drift between gossip and Raft state.
type PeerSyncBridge struct {
	gossip *gossip.Gossip
	raft   *raft.Raft
	selfID string
	log    *slog.Logger

	mu      sync.Mutex
	members map[string]struct{} // track known members for change detection
}

// NewPeerSyncBridge creates a bridge that syncs gossip membership to Raft peers.
func NewPeerSyncBridge(g *gossip.Gossip, r *raft.Raft, log *slog.Logger) *PeerSyncBridge {
	if log == nil {
		log = slog.Default()
	}
	return &PeerSyncBridge{
		gossip:  g,
		raft:    r,
		selfID:  r.ID(),
		log:     log,
		members: make(map[string]struct{}),
	}
}

// Start performs an initial sync of the current member set.
// Callbacks must be registered separately via g.SetCallbacks before Start.
func (b *PeerSyncBridge) Start() {
	b.SyncPeers()
}

// Stop clears the gossip callbacks. The bridge does not own any goroutines.
func (b *PeerSyncBridge) Stop() {
	b.gossip.SetCallbacks(nil, nil)
}

// SyncPeers rebuilds the Raft peer list from the current gossip membership.
// Alive members with a non-empty RaftAddr are included. This is called on
// startup and on every join/leave event.
func (b *PeerSyncBridge) SyncPeers() {
	members := b.gossip.Members()

	peers := make([]raft.Peer, 0, len(members))
	for _, m := range members {
		// Skip non-alive members.
		if m.State != gossip.StateAlive {
			continue
		}
		// Skip members without a Raft address (gossip-only nodes).
		if m.RaftAddr == "" {
			continue
		}
		peers = append(peers, raft.Peer{
			ID:   m.ID,
			Addr: m.RaftAddr,
		})
	}

	b.raft.UpdatePeers(peers)
	b.log.Info("peer sync: updated raft peers",
		"count", len(peers),
		"members", len(members),
	)
}

// onJoin is called by the gossip layer when a new member joins.
func (b *PeerSyncBridge) onJoin(id, addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.members[id]; exists {
		return // already known, no change
	}
	b.members[id] = struct{}{}
	b.log.Info("peer sync: member joined", "id", id, "addr", addr)
	b.SyncPeers()
}

// onLeave is called by the gossip layer when a member leaves or is declared dead.
func (b *PeerSyncBridge) onLeave(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.members[id]; !exists {
		return // unknown member, no change
	}
	delete(b.members, id)
	b.log.Info("peer sync: member left", "id", id)
	b.SyncPeers()
}
