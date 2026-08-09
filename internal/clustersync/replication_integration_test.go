package clustersync

import (
	"errors"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// This file contains a full 3-node integration test that:
//  1. Creates 3 Raft nodes, each backed by its own ReplicatedStore +
//     StoreStateMachine.
//  2. Waits for a leader to be elected.
//  3. Proposes a ban on the leader via the API.
//  4. Verifies that all 3 stores reflect the ban (Raft replication).
//  5. Proposes an unban and verifies it propagates.
//
// The test uses real TCP connections between nodes (ephemeral ports).
// It exercises the full pipeline: API → Command.Encode → raft.Propose →
// AppendEntries → StoreStateMachine.Apply → ReplicatedStore mutation.

// integrationNode bundles a Raft node with its clustersync state machine.
type integrationNode struct {
	id    string
	raft  *raft.Raft
	store *ReplicatedStore
	sm    *StoreStateMachine
	api   *API
}

// setupIntegrationCluster creates n Raft nodes, each with a ReplicatedStore.
// The nodes are started and given time to elect a leader.
func setupIntegrationCluster(t *testing.T, n int) map[string]*integrationNode {
	t.Helper()

	// Phase 1: Create all nodes with ephemeral ports (no peers yet).
	type nodeInit struct {
		id    string
		raft  *raft.Raft
		store *ReplicatedStore
		sm    *StoreStateMachine
		api   *API
	}
	inits := make([]nodeInit, n)

	for i := 0; i < n; i++ {
		id := "node-" + string(rune('a'+i))
		store := NewReplicatedStore()
		sm := NewStoreStateMachine(store, nil)

		r, err := raft.New(raft.Config{
			NodeID:             id,
			BindAddr:           "127.0.0.1:0",
			ElectionTimeoutMin: 2000 * time.Millisecond,
			ElectionTimeoutMax: 4000 * time.Millisecond,
			HeartbeatInterval:  50 * time.Millisecond,
		}, sm)
		if err != nil {
			t.Fatalf("node %s create: %v", id, err)
		}

		api := NewAPI(r, store)

		inits[i] = nodeInit{
			id:    id,
			raft:  r,
			store: store,
			sm:    sm,
			api:   api,
		}
	}

	// Phase 2: Collect addresses and configure peers.
	for _, ni := range inits {
		peers := make([]raft.Peer, 0, n-1)
		for _, other := range inits {
			if other.id == ni.id {
				continue
			}
			peers = append(peers, raft.Peer{
				ID:   other.id,
				Addr: other.raft.Transport().LocalAddr(),
			})
		}
		ni.raft.UpdatePeers(peers)
	}

	// Phase 3: Start all nodes.
	nodes := make(map[string]*integrationNode, n)
	for _, ni := range inits {
		if err := ni.raft.Start(); err != nil {
			t.Fatalf("node %s start: %v", ni.id, err)
		}
		nodes[ni.id] = &integrationNode{
			id:    ni.id,
			raft:  ni.raft,
			store: ni.store,
			sm:    ni.sm,
			api:   ni.api,
		}
	}

	// Give the nodes a moment to establish connections and elect a leader.
	time.Sleep(200 * time.Millisecond)

	return nodes
}

func teardownIntegrationCluster(nodes map[string]*integrationNode) {
	for _, n := range nodes {
		n.raft.Stop()
	}
}

// waitForIntegrationLeader polls all nodes until exactly one reports itself
// as leader. Returns the leader's ID or "" on timeout.
func waitForIntegrationLeader(t *testing.T, nodes map[string]*integrationNode, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		var leaderID string
		for id, n := range nodes {
			if n.raft.Role() == raft.RoleLeader {
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

// TestThreeNodeBanReplication starts a 3-node cluster, bans an IP on the
// leader, and verifies that the ban is visible on ALL nodes via Raft
// log replication.
func TestThreeNodeBanReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	// Wait for a leader to be elected.
	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}
	t.Logf("leader elected: %s", leader)

	// Propose a ban on the leader.
	leaderNode := nodes[leader]
	targetIP := "203.0.113.42"
	if err := leaderNode.api.ProposeBan(targetIP, 5*time.Minute); err != nil {
		t.Fatalf("ProposeBan: %v", err)
	}

	// Wait for the ban to propagate to all nodes.
	deadline := time.Now().Add(5 * time.Second)
	allBanned := false
	for time.Now().Before(deadline) {
		allBanned = true
		for _, n := range nodes {
			if !n.store.IsBanned(targetIP) {
				allBanned = false
				break
			}
		}
		if allBanned {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allBanned {
		// Report which nodes don't see the ban.
		for id, n := range nodes {
			t.Errorf("node %s: IsBanned(%q) = %v", id, targetIP, n.store.IsBanned(targetIP))
		}
		t.Fatal("ban did not replicate to all nodes within timeout")
	}

	t.Logf("ban for %s replicated to all %d nodes", targetIP, len(nodes))
}

// TestThreeNodeBanThenUnban verifies that an unban proposal propagates and
// removes the ban from all nodes.
func TestThreeNodeBanThenUnban(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	leaderNode := nodes[leader]
	targetIP := "198.51.100.7"

	// Ban the IP.
	if err := leaderNode.api.ProposeBan(targetIP, time.Hour); err != nil {
		t.Fatalf("ProposeBan: %v", err)
	}

	// Wait for ban to propagate.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if leaderNode.store.IsBanned(targetIP) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !leaderNode.store.IsBanned(targetIP) {
		t.Fatal("ban did not apply on leader")
	}

	// Unban the IP.
	if err := leaderNode.api.ProposeUnban(targetIP); err != nil {
		t.Fatalf("ProposeUnban: %v", err)
	}

	// Wait for unban to propagate to all nodes.
	deadline = time.Now().Add(5 * time.Second)
	allUnbanned := false
	for time.Now().Before(deadline) {
		allUnbanned = true
		for _, n := range nodes {
			if n.store.IsBanned(targetIP) {
				allUnbanned = false
				break
			}
		}
		if allUnbanned {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allUnbanned {
		for id, n := range nodes {
			t.Errorf("node %s: IsBanned(%q) = %v (want false)", id, targetIP, n.store.IsBanned(targetIP))
		}
		t.Fatal("unban did not propagate to all nodes")
	}

	t.Logf("unban for %s propagated to all %d nodes", targetIP, len(nodes))
}

// TestThreeNodeRuleReplication verifies that a custom rule proposed on the
// leader replicates to all nodes.
func TestThreeNodeRuleReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	leaderNode := nodes[leader]
	ruleID := "block-sqli-v2"
	ruleBody := []byte(`{"pattern":"union select","action":"block"}`)

	if err := leaderNode.api.ProposeSetRule(ruleID, ruleBody); err != nil {
		t.Fatalf("ProposeSetRule: %v", err)
	}

	// Wait for rule to propagate.
	deadline := time.Now().Add(5 * time.Second)
	allPresent := false
	for time.Now().Before(deadline) {
		allPresent = true
		for _, n := range nodes {
			if _, ok := n.store.GetRule(ruleID); !ok {
				allPresent = false
				break
			}
		}
		if allPresent {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allPresent {
		for id, n := range nodes {
			_, ok := n.store.GetRule(ruleID)
			t.Errorf("node %s: GetRule(%q) ok=%v", id, ruleID, ok)
		}
		t.Fatal("rule did not replicate to all nodes")
	}

	t.Logf("rule %q replicated to all %d nodes", ruleID, len(nodes))
}

// TestThreeNodeCounterReplication verifies that counter increments proposed on
// the leader accumulate on all nodes.
func TestThreeNodeCounterReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	leaderNode := nodes[leader]
	counterKey := "ratelimit:1.2.3.4"
	window := int64(1000)

	// Increment the counter 5 times.
	for i := 0; i < 5; i++ {
		if err := leaderNode.api.ProposeIncrCounter(counterKey, 1, window); err != nil {
			t.Fatalf("ProposeIncrCounter #%d: %v", i+1, err)
		}
	}

	// Wait for counter to propagate and settle.
	deadline := time.Now().Add(5 * time.Second)
	allMatch := false
	for time.Now().Before(deadline) {
		allMatch = true
		for _, n := range nodes {
			if n.store.GetCounter(counterKey, window) != 5 {
				allMatch = false
				break
			}
		}
		if allMatch {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allMatch {
		for id, n := range nodes {
			t.Errorf("node %s: GetCounter = %d, want 5", id, n.store.GetCounter(counterKey, window))
		}
		t.Fatal("counter did not replicate to all nodes")
	}

	t.Logf("counter %q = 5 on all %d nodes", counterKey, len(nodes))
}

// TestProposeOnFollowerReturnsError verifies that proposing on a follower
// returns ErrRaftNotLeader (or the wrapped raft.ErrNotLeader).
func TestProposeOnFollowerReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	// Find a follower.
	var follower *integrationNode
	for id, n := range nodes {
		if id != leader {
			follower = n
			break
		}
	}
	if follower == nil {
		t.Fatal("no follower found")
	}

	// Proposing on a follower should fail.
	err := follower.api.ProposeBan("1.2.3.4", time.Minute)
	if err == nil {
		t.Fatal("ProposeBan on follower should return error")
	}
	if !errors.Is(err, ErrRaftNotLeader) {
		t.Errorf("expected ErrRaftNotLeader, got: %v", err)
	}

	t.Logf("follower %s correctly rejected proposal with ErrRaftNotLeader", follower.id)
}

// TestThreeNodeLeaderFailoverAndReplication verifies that after the leader
// crashes, a new leader is elected and replication continues.
func TestThreeNodeLeaderFailoverAndReplication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	nodes := setupIntegrationCluster(t, 3)
	defer teardownIntegrationCluster(nodes)

	leader := waitForIntegrationLeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	// Propose a ban on the original leader.
	originalLeader := nodes[leader]
	targetIP := "10.0.0.99"
	if err := originalLeader.api.ProposeBan(targetIP, time.Hour); err != nil {
		t.Fatalf("ProposeBan on original leader: %v", err)
	}

	// Wait for ban to propagate.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if originalLeader.store.IsBanned(targetIP) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Kill the original leader.
	originalLeader.raft.Stop()
	originalLeader.raft.Transport().Close()
	delete(nodes, leader)

	// Wait for a new leader among the remaining nodes.
	newLeader := ""
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		leaders := 0
		for id, n := range nodes {
			if n.raft.Role() == raft.RoleLeader {
				leaders++
				newLeader = id
			}
		}
		if leaders == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if newLeader == "" {
		t.Fatal("no new leader elected after failover")
	}
	t.Logf("new leader after failover: %s", newLeader)

	// Propose a new ban on the new leader.
	newLeaderNode := nodes[newLeader]
	targetIP2 := "10.0.0.100"
	if err := newLeaderNode.api.ProposeBan(targetIP2, time.Hour); err != nil {
		t.Fatalf("ProposeBan on new leader: %v", err)
	}

	// Verify the new ban propagates to all remaining nodes.
	deadline = time.Now().Add(5 * time.Second)
	allBanned := false
	for time.Now().Before(deadline) {
		allBanned = true
		for _, n := range nodes {
			if !n.store.IsBanned(targetIP2) {
				allBanned = false
				break
			}
		}
		if allBanned {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !allBanned {
		for id, n := range nodes {
			t.Errorf("node %s: IsBanned(%q) = %v", id, targetIP2, n.store.IsBanned(targetIP2))
		}
		t.Fatal("new ban did not replicate to all surviving nodes after failover")
	}

	t.Logf("ban %s replicated to all surviving nodes after failover", targetIP2)
}
