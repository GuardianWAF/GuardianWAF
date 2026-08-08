package raft

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// --- LogStore tests ---

func TestLogStore_AppendAndGet(t *testing.T) {
	l := NewLogStore()

	idx1 := l.Append(1, []byte("cmd1"))
	if idx1 != 1 {
		t.Errorf("first append index = %d, want 1", idx1)
	}
	idx2 := l.Append(1, []byte("cmd2"))
	if idx2 != 2 {
		t.Errorf("second append index = %d, want 2", idx2)
	}

	e, ok := l.Get(1)
	if !ok {
		t.Fatal("Get(1) returned !ok")
	}
	if e.Term != 1 || e.Index != 1 || string(e.Command) != "cmd1" {
		t.Errorf("Get(1) = %+v", e)
	}

	if _, ok := l.Get(0); ok {
		t.Error("Get(0) should return false (1-based)")
	}
	if _, ok := l.Get(99); ok {
		t.Error("Get(99) should return false (out of range)")
	}
}

func TestLogStore_LastIndexAndTerm(t *testing.T) {
	l := NewLogStore()
	if l.LastIndex() != 0 || l.LastTerm() != 0 {
		t.Fatal("empty log: LastIndex and LastTerm should be 0")
	}
	l.Append(1, []byte("a"))
	l.Append(2, []byte("b"))
	if l.LastIndex() != 2 || l.LastTerm() != 2 {
		t.Errorf("LastIndex=%d LastTerm=%d, want 2/2", l.LastIndex(), l.LastTerm())
	}
}

func TestLogStore_Term(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(2, []byte("b"))
	l.Append(1, []byte("c"))

	if l.Term(0) != 0 {
		t.Error("Term(0) should be 0 (virtual)")
	}
	if l.Term(1) != 1 {
		t.Errorf("Term(1) = %d, want 1", l.Term(1))
	}
	if l.Term(2) != 2 {
		t.Errorf("Term(2) = %d, want 2", l.Term(2))
	}
	if l.Term(99) != 0 {
		t.Error("Term(99) should be 0 (out of range)")
	}
}

func TestLogStore_HasAt(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(2, []byte("b"))

	if !l.HasAt(0, 0) {
		t.Error("HasAt(0,0) should be true (virtual entry)")
	}
	if !l.HasAt(1, 1) {
		t.Error("HasAt(1,1) should be true")
	}
	if l.HasAt(1, 2) {
		t.Error("HasAt(1,2) should be false (wrong term)")
	}
	if l.HasAt(99, 0) {
		t.Error("HasAt(99,0) should be false (out of range)")
	}
}

func TestLogStore_TruncateFrom(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(1, []byte("b"))
	l.Append(2, []byte("c"))

	l.TruncateFrom(3)
	if l.LastIndex() != 2 {
		t.Errorf("after truncate, LastIndex = %d, want 2", l.LastIndex())
	}

	// Truncate again at 1 — clears everything.
	l.TruncateFrom(1)
	if l.LastIndex() != 0 {
		t.Errorf("after truncate all, LastIndex = %d, want 0", l.LastIndex())
	}

	// Truncate out of range on empty log is a no-op.
	l.TruncateFrom(10)
	if l.LastIndex() != 0 {
		t.Errorf("after out-of-range truncate, LastIndex = %d, want 0", l.LastIndex())
	}
}

func TestLogStore_EntriesFrom(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(1, []byte("b"))
	l.Append(2, []byte("c"))

	entries := l.EntriesFrom(2)
	if len(entries) != 2 {
		t.Fatalf("EntriesFrom(2) returned %d entries, want 2", len(entries))
	}
	if string(entries[0].Command) != "b" {
		t.Errorf("entries[0].Command = %q, want %q", entries[0].Command, "b")
	}

	if l.EntriesFrom(99) != nil {
		t.Error("EntriesFrom(99) should return nil")
	}
	if l.EntriesFrom(0) != nil {
		t.Error("EntriesFrom(0) should return nil")
	}
}

func TestLogStore_CheckConflict(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(1, []byte("b"))
	l.Append(2, []byte("c"))
	l.Append(2, []byte("d"))

	// Case 3: no conflict.
	ci := l.CheckConflict(4, 2)
	if ci.ConflictTerm != 0 || ci.ConflictIndex != 0 {
		t.Errorf("no conflict: got %+v, want zero", ci)
	}

	// Case 1: follower log too short.
	ci = l.CheckConflict(10, 2)
	if ci.ConflictIndex != 5 {
		t.Errorf("too short: ConflictIndex = %d, want 5", ci.ConflictIndex)
	}

	// Case 2: term mismatch at prevLogIndex.
	ci = l.CheckConflict(3, 1) // entry 3 has term 2, not 1
	if ci.ConflictTerm != 2 {
		t.Errorf("mismatch: ConflictTerm = %d, want 2", ci.ConflictTerm)
	}
	if ci.ConflictIndex != 3 {
		t.Errorf("mismatch: ConflictIndex = %d, want 3", ci.ConflictIndex)
	}
}

func TestLogStore_Slice(t *testing.T) {
	l := NewLogStore()
	l.Append(1, []byte("a"))
	l.Append(1, []byte("b"))
	l.Append(2, []byte("c"))

	s := l.Slice(1, 2)
	if len(s) != 2 {
		t.Fatalf("Slice(1,2) = %d entries, want 2", len(s))
	}
	s = l.Slice(2, 99)
	if len(s) != 2 {
		t.Errorf("Slice(2,99) = %d entries, want 2 (clamped)", len(s))
	}
}

// --- PersistentState tests ---

func TestPersistentState_TermAndVote(t *testing.T) {
	ps := NewPersistentState()

	if ps.CurrentTerm() != 0 {
		t.Error("initial term should be 0")
	}
	if ps.VotedFor() != "" {
		t.Error("initial votedFor should be empty")
	}

	ps.SetCurrentTerm(5)
	if ps.CurrentTerm() != 5 {
		t.Errorf("term = %d, want 5", ps.CurrentTerm())
	}
	if ps.VotedFor() != "" {
		t.Error("SetCurrentTerm should reset votedFor")
	}

	ps.SetVotedFor("node-a")
	if ps.VotedFor() != "node-a" {
		t.Errorf("votedFor = %q", ps.VotedFor())
	}

	newTerm := ps.IncCurrentTerm()
	if newTerm != 6 {
		t.Errorf("IncCurrentTerm = %d, want 6", newTerm)
	}
	if ps.VotedFor() != "" {
		t.Error("IncCurrentTerm should reset votedFor")
	}
}

// --- LeaderState tests ---

func TestLeaderState_NextAndMatchIndex(t *testing.T) {
	ls := NewLeaderState([]string{"a", "b"}, 5)

	if ls.NextIndex("a") != 6 {
		t.Errorf("NextIndex(a) = %d, want 6", ls.NextIndex("a"))
	}
	if ls.MatchIndex("a") != 0 {
		t.Errorf("MatchIndex(a) = %d, want 0", ls.MatchIndex("a"))
	}

	ls.SetNextIndex("a", 4)
	if ls.NextIndex("a") != 4 {
		t.Errorf("NextIndex(a) = %d, want 4", ls.NextIndex("a"))
	}

	ls.DecrNextIndex("a", 3)
	if ls.NextIndex("a") != 3 {
		t.Errorf("after DecrNextIndex, NextIndex(a) = %d, want 3", ls.NextIndex("a"))
	}

	ls.SetMatchIndex("a", 5)
	if ls.MatchIndex("a") != 5 {
		t.Errorf("MatchIndex(a) = %d, want 5", ls.MatchIndex("a"))
	}
	// SetMatchIndex should not go backward.
	ls.SetMatchIndex("a", 3)
	if ls.MatchIndex("a") != 5 {
		t.Errorf("MatchIndex(a) should not decrease, got %d", ls.MatchIndex("a"))
	}
}

func TestLeaderState_ComputeCommitIndex(t *testing.T) {
	ls := NewLeaderState([]string{"a", "b"}, 0)

	ls.SetMatchIndex("a", 4)
	ls.SetMatchIndex("b", 5)

	// 3 nodes (leader+a+b), matchIndex = {leader: lastIndex, a:4, b:5}.
	// Sorted desc: {5, 4, lastIndex}. Majority (floor(3/2)=1) = index 1.
	// With lastIndex=5: {5,5,4}, majority = 5.
	ci := ls.ComputeCommitIndex(5)
	if ci != 5 {
		t.Errorf("ComputeCommitIndex = %d, want 5", ci)
	}

	// With only 1 match: {5, 0, lastIndex=5}, majority = 5.
	ls.SetMatchIndex("a", 0)
	ci = ls.ComputeCommitIndex(5)
	if ci != 5 {
		t.Errorf("ComputeCommitIndex with leader only = %d, want 5", ci)
	}
}

// --- RPC encode/decode tests ---

func TestRPC_EncodeDecodeRequestVote(t *testing.T) {
	req := RequestVoteRequest{
		Term:         5,
		CandidateID:  "node-a",
		LastLogIndex: 10,
		LastLogTerm:  3,
	}

	data, err := EncodeRequestVote(req)
	if err != nil {
		t.Fatalf("EncodeRequestVote: %v", err)
	}

	decoded, err := DecodeRequestVote(data)
	if err != nil {
		t.Fatalf("DecodeRequestVote: %v", err)
	}
	if decoded.Term != req.Term || decoded.CandidateID != req.CandidateID ||
		decoded.LastLogIndex != req.LastLogIndex || decoded.LastLogTerm != req.LastLogTerm {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, req)
	}
}

func TestRPC_EncodeDecodeAppendEntries(t *testing.T) {
	req := AppendEntriesRequest{
		Term:         3,
		LeaderID:     "node-a",
		PrevLogIndex: 5,
		PrevLogTerm:  2,
		Entries: []LogEntry{
			{Term: 3, Index: 6, Command: []byte("cmd1")},
			{Term: 3, Index: 7, Command: []byte("cmd2")},
		},
		LeaderCommit: 4,
	}

	data, err := EncodeAppendEntries(req)
	if err != nil {
		t.Fatalf("EncodeAppendEntries: %v", err)
	}

	decoded, err := DecodeAppendEntries(data)
	if err != nil {
		t.Fatalf("DecodeAppendEntries: %v", err)
	}
	if decoded.Term != req.Term || decoded.LeaderID != req.LeaderID ||
		decoded.PrevLogIndex != req.PrevLogIndex || decoded.PrevLogTerm != req.PrevLogTerm ||
		len(decoded.Entries) != 2 || decoded.LeaderCommit != req.LeaderCommit {
		t.Errorf("round-trip mismatch: got %+v", decoded)
	}
	if string(decoded.Entries[0].Command) != "cmd1" {
		t.Errorf("entry[0].Command mismatch")
	}
}

func TestRPC_EncodeDecodeAppendEntries_Heartbeat(t *testing.T) {
	req := AppendEntriesRequest{
		Term:         3,
		LeaderID:     "node-a",
		PrevLogIndex: 5,
		PrevLogTerm:  2,
		Entries:      nil, // heartbeat
		LeaderCommit: 4,
	}

	data, err := EncodeAppendEntries(req)
	if err != nil {
		t.Fatalf("EncodeAppendEntries: %v", err)
	}
	decoded, err := DecodeAppendEntries(data)
	if err != nil {
		t.Fatalf("DecodeAppendEntries: %v", err)
	}
	if len(decoded.Entries) != 0 {
		t.Errorf("heartbeat should have 0 entries, got %d", len(decoded.Entries))
	}
}

// --- Frame encode/decode tests ---

func TestRPC_ReadWriteFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("hello raft")

	go func() {
		_ = EncodeRequest(client, RPCRequestVote, payload)
	}()

	msgType, data, err := ReadFrame(server)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != RPCRequestVote {
		t.Errorf("msgType = %d, want %d", msgType, RPCRequestVote)
	}
	if string(data) != "hello raft" {
		t.Errorf("data = %q", string(data))
	}
}

// --- Multi-node TCP integration test ---

func TestRaft_ElectionSingleCandidate(t *testing.T) {
	// A single-node cluster should elect itself leader immediately.
	r, err := New(Config{
		NodeID:             "solo",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 100 * time.Millisecond,
		ElectionTimeoutMax: 150 * time.Millisecond,
		HeartbeatInterval:  30 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	// Wait for election.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Role() == RoleLeader {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r.Role() != RoleLeader {
		t.Fatalf("single node did not become leader (role=%s)", r.Role())
	}
	if r.LeaderID() != "solo" {
		t.Errorf("LeaderID = %q, want %q", r.LeaderID(), "solo")
	}
}

func TestRaft_ThreeNodeElection(t *testing.T) {
	nodes := setupCluster(t, 3)
	defer teardownCluster(nodes)

	// Wait for a leader to emerge.
	leader := waitForLeader(t, nodes, 5*time.Second)
	if leader == "" {
		t.Fatal("no leader elected after 5s")
	}

	// Exactly one leader.
	leaderCount := 0
	for _, r := range nodes {
		if r.Role() == RoleLeader {
			leaderCount++
		}
	}
	if leaderCount != 1 {
		t.Errorf("expected 1 leader, got %d", leaderCount)
	}

	// Leader term should be >= 1.
	leaderNode := findNode(nodes, leader)
	if leaderNode.Term() < 1 {
		t.Errorf("leader term = %d, want >= 1", leaderNode.Term())
	}
}

func TestRaft_LogReplication(t *testing.T) {
	nodes := setupCluster(t, 3)
	defer teardownCluster(nodes)

	// Wait for a stable leader: same leader must hold leadership across
	// two consecutive checks 200ms apart. This avoids proposing during a
	// brief leader transition (split-vote recovery).
	var leaderNode *testNode
	dl := time.Now().Add(10 * time.Second)
	for time.Now().Before(dl) {
		l := waitForLeader(t, nodes, 3*time.Second)
		if l == "" {
			continue
		}
		time.Sleep(200 * time.Millisecond)
		// Verify the same node is still leader.
		stillLeader := true
		for id, r := range nodes {
			if id == l && r.Role() != RoleLeader {
				stillLeader = false
			}
		}
		if stillLeader {
			leaderNode = findNode(nodes, l)
			break
		}
	}
	if leaderNode == nil {
		t.Fatal("no stable leader after 10s")
	}

	// Debug: print leader state before propose
	t.Logf("BEFORE PROPOSE: leader=%s", leaderNode.ID())
	t.Logf("  leader role=%s lastIndex=%d", leaderNode.Role(), leaderNode.persist.Log().LastIndex())
	for id, n := range nodes {
		t.Logf("  node %s: role=%s lastIndex=%d peers=%d", id, n.Role(), n.persist.Log().LastIndex(), len(n.config.Peers))
	}

	// Propose a command. Retry if the leader reverted between detection and
	// propose (Raft election instability on localhost with tight timing).
	cmd, _ := json.Marshal(map[string]string{"type": "ban", "ip": "10.0.0.1"})
	var proposeErr error
	for attempt := 0; attempt < 20; attempt++ {
		lid := ""
		for _, n := range nodes {
			if n.Role() == RoleLeader {
				lid = n.ID()
				break
			}
		}
		if lid == "" {
			// No leader — wait for re-election.
			time.Sleep(200 * time.Millisecond)
			continue
		}
		leaderNode = nodes[lid]
		proposeErr = leaderNode.Propose(cmd)
		if proposeErr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if proposeErr != nil {
		t.Fatalf("Propose failed after 20 attempts: %v", proposeErr)
	}
	t.Logf("after Propose: leader %s lastIndex=%d", leaderNode.config.NodeID, leaderNode.persist.Log().LastIndex())

	// Wait for replication to followers.
	dl2 := time.Now().Add(5 * time.Second)
	for time.Now().Before(dl2) {
		allReplicated := true
		for _, r := range nodes {
			if r.persist.Log().LastIndex() < 1 {
				allReplicated = false
				break
			}
		}
		if allReplicated {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// All nodes should have at least 1 entry.
	for _, r := range nodes {
		li := r.persist.Log().LastIndex()
		if li < 1 {
			t.Errorf("node %s: LastIndex = %d, want >= 1", r.ID(), li)
		}
	}
}

func TestRaft_LeaderFailover(t *testing.T) {
	nodes := setupCluster(t, 3)
	defer teardownCluster(nodes)

	leader := waitForLeader(t, nodes, 5*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}

	// Stop the leader.
	leaderNode := findNode(nodes, leader)
	leaderNode.Stop()
	leaderNode.Transport().Close()

	// Wait for a new leader.
	newLeader := waitForLeaderExcluding(t, nodes, leader, 5*time.Second)
	if newLeader == "" {
		t.Fatal("no new leader after failover")
	}
	if newLeader == leader {
		t.Fatal("same node became leader again after being stopped")
	}
}

// --- Helpers ---

type testNode struct {
	*Raft
}

func setupCluster(t *testing.T, n int) map[string]*testNode {
	t.Helper()
	nodes := make(map[string]*testNode, n)

	// Phase 1: Create all nodes with ephemeral ports (no peers yet).
	type nodeInit struct {
		id   string
		raft *Raft
	}
	inits := make([]nodeInit, n)

	for i := 0; i < n; i++ {
		id := "node-" + string(rune('a'+i))
		r, err := New(Config{
			NodeID:             id,
			BindAddr:           "127.0.0.1:0",
			ElectionTimeoutMin: 2000 * time.Millisecond,
			ElectionTimeoutMax: 4000 * time.Millisecond,
			HeartbeatInterval:  50 * time.Millisecond,
		}, nil)
		if err != nil {
			t.Fatalf("node %s: %v", id, err)
		}
		inits[i] = nodeInit{id: id, raft: r}
	}

	// Phase 2: Collect addresses and configure peers.
	for _, ni := range inits {
		peers := make([]Peer, 0, n-1)
		for _, other := range inits {
			if other.id == ni.id {
				continue
			}
			peers = append(peers, Peer{
				ID:   other.id,
				Addr: other.raft.Transport().LocalAddr(),
			})
		}
		ni.raft.UpdatePeers(peers)
	}

	// Phase 3: Start all nodes.
	for _, ni := range inits {
		if err := ni.raft.Start(); err != nil {
			t.Fatalf("node %s start: %v", ni.id, err)
		}
		nodes[ni.id] = &testNode{Raft: ni.raft}
	}

	// Give the nodes a moment to establish connections.
	time.Sleep(100 * time.Millisecond)

	return nodes
}

func teardownCluster(nodes map[string]*testNode) {
	for _, n := range nodes {
		n.Stop()
	}
}

func waitForLeader(t *testing.T, nodes map[string]*testNode, timeout time.Duration) string {
	t.Helper()
	return waitForLeaderExcluding(t, nodes, "", timeout)
}

func waitForLeaderExcluding(t *testing.T, nodes map[string]*testNode, exclude string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		var leaderID string
		for id, r := range nodes {
			if id == exclude {
				continue
			}
			if r.Role() == RoleLeader {
				leaders++
				leaderID = id
			}
		}
		if leaders == 1 {
			return leaderID
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

func findNode(nodes map[string]*testNode, id string) *testNode {
	return nodes[id]
}
