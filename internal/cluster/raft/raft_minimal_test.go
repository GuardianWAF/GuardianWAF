package raft

import (
	"testing"
	"time"
)

// TestAppendEntries_DirectSend tests log replication without election timing.
// Two nodes are created, node A manually becomes leader, and sends entries
// to node B via the real TCP transport.
func TestAppendEntries_DirectSend(t *testing.T) {
	// Create two nodes with no peers (no election will fire).
	a, err := New(Config{
		NodeID:             "a",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 9999 * time.Second, // effectively never
		ElectionTimeoutMax: 9999 * time.Second,
		HeartbeatInterval:  9999 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	defer a.Transport().Close()

	b, err := New(Config{
		NodeID:             "b",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 9999 * time.Second,
		ElectionTimeoutMax: 9999 * time.Second,
		HeartbeatInterval:  9999 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	defer b.Transport().Close()

	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}

	// Manually make 'a' the leader and configure peers.
	a.mu.Lock()
	a.role = RoleLeader
	a.persist.SetCurrentTerm(1)
	a.leaderID = "a"
	a.leaderState = NewLeaderState([]string{"b"}, 0)
	a.config.Peers = []Peer{{ID: "b", Addr: b.Transport().LocalAddr()}}
	a.mu.Unlock()

	// Append an entry to the leader's log.
	a.mu.Lock()
	a.persist.Log().Append(1, []byte("hello"))
	a.mu.Unlock()

	// Manually send AppendEntries to 'b'.
	a.sendAppendEntries(Peer{ID: "b", Addr: b.Transport().LocalAddr()})

	// Give the RPC time to complete.
	time.Sleep(200 * time.Millisecond)

	// Check follower received the entry.
	b.mu.Lock()
	bLast := b.persist.Log().LastIndex()
	b.mu.Unlock()

	if bLast != 1 {
		t.Fatalf("follower log lastIndex = %d, want 1", bLast)
	}

	bEntry, ok := b.persist.Log().Get(1)
	if !ok {
		t.Fatal("follower missing entry at index 1")
	}
	if string(bEntry.Command) != "hello" {
		t.Fatalf("follower entry command = %q, want %q", string(bEntry.Command), "hello")
	}
}
