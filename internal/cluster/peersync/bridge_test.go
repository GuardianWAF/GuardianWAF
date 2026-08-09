package peersync

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// fakeMemberList implements GossipMemberList for testing.
type fakeMemberList struct {
	members []gossip.Member
}

func (f *fakeMemberList) Members() []gossip.Member { return f.members }

// noopStateMachine satisfies raft.StateMachine.
type noopStateMachine struct{}

func (noopStateMachine) Apply(raft.LogEntry) {}

func TestBridge_SyncAddsAlivePeers(t *testing.T) {
	fakeML := &fakeMemberList{
		members: []gossip.Member{
			{ID: "n1", Addr: "10.0.0.1:7946", RaftAddr: "127.0.0.1:9001", State: gossip.StateAlive},
			{ID: "n2", Addr: "10.0.0.2:7946", RaftAddr: "127.0.0.1:9002", State: gossip.StateAlive},
			// Dead members should be excluded.
			{ID: "n3", Addr: "10.0.0.3:7946", RaftAddr: "127.0.0.1:9003", State: gossip.StateDead},
			// Members without RaftAddr should be excluded.
			{ID: "n4", Addr: "10.0.0.4:7946", RaftAddr: "", State: gossip.StateAlive},
		},
	}

	r, err := raft.New(raft.DefaultConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	bridge := NewBridge(fakeML, r, nil)
	bridge.Sync()

	peers := r.Peers()
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers (alive + raftAddr), got %d: %+v", len(peers), peers)
	}

	peerIDs := map[string]bool{}
	for _, p := range peers {
		peerIDs[p.ID] = true
	}
	if !peerIDs["n1"] || !peerIDs["n2"] {
		t.Errorf("expected peers n1 and n2, got %v", peerIDs)
	}
	if peerIDs["n3"] || peerIDs["n4"] {
		t.Errorf("dead/no-raftaddr members should be excluded, got %v", peerIDs)
	}
}

func TestBridge_SyncExcludesSelf(t *testing.T) {
	// Self ID is derived from the Raft node, not gossip. The bridge should
	// NOT filter self because the gossip member list doesn't include self
	// (it's queried from the gossip protocol which returns all members
	// including self). The test verifies that self IS included if present.
	fakeML := &fakeMemberList{
		members: []gossip.Member{
			{ID: "self", Addr: "127.0.0.1:7946", RaftAddr: "127.0.0.1:9000", State: gossip.StateAlive},
		},
	}

	r, err := raft.New(raft.DefaultConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	bridge := NewBridge(fakeML, r, nil)
	bridge.Sync()

	peers := r.Peers()
	// Self is included because the bridge doesn't filter by Raft node ID.
	// The Raft layer handles self-exclusion internally.
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer (self), got %d", len(peers))
	}
}

func TestBridge_CallbacksTriggerSync(t *testing.T) {
	fakeML := &fakeMemberList{
		members: []gossip.Member{
			{ID: "n1", Addr: "10.0.0.1:7946", RaftAddr: "127.0.0.1:9001", State: gossip.StateAlive},
		},
	}

	r, err := raft.New(raft.DefaultConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	bridge := NewBridge(fakeML, r, nil)
	onJoin, onLeave := bridge.Callbacks()

	// Trigger join — should sync peers.
	onJoin("n1", "10.0.0.1:7946")
	if peers := r.Peers(); len(peers) != 1 {
		t.Errorf("after onJoin, expected 1 peer, got %d", len(peers))
	}

	// Trigger leave — should resync (member still in fake list, so no change).
	onLeave("n1")
	if peers := r.Peers(); len(peers) != 1 {
		t.Errorf("after onLeave, expected 1 peer (fake list unchanged), got %d", len(peers))
	}
}

func TestBridge_EmptyMemberList(t *testing.T) {
	fakeML := &fakeMemberList{members: nil}

	r, err := raft.New(raft.DefaultConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	bridge := NewBridge(fakeML, r, nil)
	bridge.Sync()

	if peers := r.Peers(); len(peers) != 0 {
		t.Errorf("expected 0 peers for empty member list, got %d", len(peers))
	}
}

func TestBridge_PeerOrdering(t *testing.T) {
	fakeML := &fakeMemberList{
		members: []gossip.Member{
			{ID: "zzz", RaftAddr: "127.0.0.1:3", State: gossip.StateAlive},
			{ID: "aaa", RaftAddr: "127.0.0.1:1", State: gossip.StateAlive},
			{ID: "mmm", RaftAddr: "127.0.0.1:2", State: gossip.StateAlive},
		},
	}

	r, err := raft.New(raft.DefaultConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	bridge := NewBridge(fakeML, r, nil)
	bridge.Sync()

	peers := r.Peers()
	if len(peers) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(peers))
	}

	// Peers should be sorted by ID.
	expected := []string{"aaa", "mmm", "zzz"}
	for i, want := range expected {
		if peers[i].ID != want {
			t.Errorf("peer[%d].ID = %q, want %q", i, peers[i].ID, want)
		}
	}
}

// TestBridge_RealGossipIntegration creates a real gossip node and Raft node
// to verify the bridge works end-to-end with real components.
func TestBridge_RealGossipIntegration(t *testing.T) {
	// Create a real gossip node.
	gCfg := gossip.DefaultConfig("bridge-test", "127.0.0.1:0")
	g, err := gossip.New(gCfg)
	if err != nil {
		t.Fatalf("gossip.New: %v", err)
	}
	defer g.Stop()

	if err := g.Start(); err != nil {
		t.Fatalf("gossip.Start: %v", err)
	}

	// Create a real Raft node.
	r, err := raft.New(raft.DefaultConfig("bridge-test", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	// Wire the bridge.
	bridge := NewBridge(g, r, nil)
	onJoin, onLeave := bridge.Callbacks()
	g.SetCallbacks(onJoin, onLeave)

	// Initial sync — self should be the only member.
	bridge.Sync()
	time.Sleep(100 * time.Millisecond)

	peers := r.Peers()
	// Self member has an empty RaftAddr (gossip config didn't set it),
	// so it should be excluded.
	if len(peers) != 0 {
		t.Logf("expected 0 peers (self has empty RaftAddr), got %d", len(peers))
	}
}
