package raft

import (
	"testing"
	"time"
)

// Regression: ComputeCommitIndex early-returned 0 when matchIndex was empty,
// which is the single-node-cluster case (becomeLeader builds peerIDs from
// config.Peers only, excluding self). A single-node deployment elected its
// leader fine but commitIndex stayed frozen at 0 forever — the state machine
// never applied anything.

func TestComputeCommitIndexSingleNode(t *testing.T) {
	ls := NewLeaderState(nil, 5) // single-node leader: no peers
	if got := ls.ComputeCommitIndex(5); got != 5 {
		t.Fatalf("FAIL: single-node ComputeCommitIndex = %d, want 5 (leader alone is the quorum)", got)
	}
}

func TestComputeCommitIndexThreeNodes(t *testing.T) {
	ls := NewLeaderState([]string{"b", "c"}, 10)
	ls.SetMatchIndex("b", 8)
	// counts = [10, 8, 0] -> mid=1 -> 8 (replicated on leader+b = 2 of 3).
	if got := ls.ComputeCommitIndex(10); got != 8 {
		t.Fatalf("ComputeCommitIndex = %d, want 8", got)
	}
}

func TestComputeCommitIndexEvenClusterMajority(t *testing.T) {
	// 4 nodes: majority is 3 — an index on 3 of 4 commits; one on 2 does not.
	ls := NewLeaderState([]string{"b", "c", "d"}, 10)
	ls.SetMatchIndex("b", 9)
	ls.SetMatchIndex("c", 9)
	ls.SetMatchIndex("d", 2)
	// counts = [10, 9, 9, 2] -> mid=2 -> 9 (on 3 of 4: leader+b+c).
	if got := ls.ComputeCommitIndex(10); got != 9 {
		t.Fatalf("ComputeCommitIndex = %d, want 9", got)
	}
}

func TestComputeCommitIndexUnderReplicatedNotCommitted(t *testing.T) {
	// Index 9 is on only 2 of 4 nodes: it must not be committed even though
	// index 2 (on 3 of 4) is.
	ls := NewLeaderState([]string{"b", "c", "d"}, 10)
	ls.SetMatchIndex("b", 9)
	ls.SetMatchIndex("c", 2)
	ls.SetMatchIndex("d", 2)
	if got := ls.ComputeCommitIndex(10); got >= 9 {
		t.Fatalf("ComputeCommitIndex = %d, want < 9 (under-replicated)", got)
	}
}

// Integration: the full single-node production path — elect, propose, apply.
func TestSingleNodeRaftAppliesProposals(t *testing.T) {
	applied := make(chan LogEntry, 8)
	cfg := DefaultConfig("solo", "127.0.0.1:0")
	cfg.ElectionTimeoutMin = 1 * time.Millisecond
	cfg.ElectionTimeoutMax = 1 * time.Millisecond
	cfg.Peers = nil
	cfg.Secret = []byte("state-commit-test-0123456789abcdef0123")
	r, err := New(cfg, ApplyFunc(func(e LogEntry) { applied <- e }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Stop()
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Role() == RoleLeader {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if r.Role() != RoleLeader {
		t.Fatalf("single-node node never became leader (role=%v)", r.Role())
	}

	if err := r.Propose([]byte("cmd-1")); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if err := r.Propose([]byte("cmd-2")); err != nil {
		t.Fatalf("Propose: %v", err)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-applied:
		case <-time.After(2 * time.Second):
			t.Fatalf("FAIL: state machine never applied entries — CommitIndex=%d (single-node commit frozen)", r.CommitIndex())
		}
	}
	if got := r.CommitIndex(); got != 2 {
		t.Fatalf("FAIL: CommitIndex = %d, want 2", got)
	}
}
