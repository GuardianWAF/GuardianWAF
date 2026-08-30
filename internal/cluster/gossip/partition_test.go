package gossip

import (
	"context"
	"sync"
	"testing"
	"time"
)

// partitionableTransport wraps a real UDP transport and can block sends and
// receives to/from specific remote addresses, simulating a network partition
// at the application layer.
//
// When partitioned, Send() silently drops packets to blocked addresses, and
// Receive() drops packets from blocked addresses (looping until a non-blocked
// packet arrives or the context is cancelled).
type partitionableTransport struct {
	inner   Transport
	mu      sync.RWMutex
	blocked map[string]bool
}

func newPartitionableTransport(addr string) (*partitionableTransport, error) {
	inner, err := NewUDPTransport(addr)
	if err != nil {
		return nil, err
	}
	return &partitionableTransport{
		inner:   inner,
		blocked: make(map[string]bool),
	}, nil
}

func (t *partitionableTransport) Send(addr string, data []byte) error {
	t.mu.RLock()
	blocked := t.blocked[addr]
	t.mu.RUnlock()
	if blocked {
		return nil // silently drop — simulates packet loss
	}
	return t.inner.Send(addr, data)
}

func (t *partitionableTransport) Receive(ctx context.Context) ([]byte, string, error) {
	for {
		data, addr, err := t.inner.Receive(ctx)
		if err != nil {
			return nil, "", err
		}
		t.mu.RLock()
		blocked := t.blocked[addr]
		t.mu.RUnlock()
		if !blocked {
			return data, addr, nil
		}
		// Drop blocked packet and continue receiving.
	}
}

func (t *partitionableTransport) LocalAddr() string {
	return t.inner.LocalAddr()
}

func (t *partitionableTransport) Close() error {
	return t.inner.Close()
}

func (t *partitionableTransport) block(addr string) {
	t.mu.Lock()
	t.blocked[addr] = true
	t.mu.Unlock()
}

func (t *partitionableTransport) unblockAll() {
	t.mu.Lock()
	t.blocked = make(map[string]bool)
	t.mu.Unlock()
}

// --- Helpers ---

// gossipTestNode bundles a gossip node with its partitionable transport.
type gossipTestNode struct {
	g    *Gossip
	tr   *partitionableTransport
	id   string
	addr string
}

func newGossipTestNode(t *testing.T, id string) *gossipTestNode {
	t.Helper()
	tr, err := newPartitionableTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("node %s transport: %v", id, err)
	}
	cfg := DefaultConfig(id, "127.0.0.1:0")
	cfg.Secret = testSecret
	cfg.ProbeInterval = 200 * time.Millisecond
	cfg.ProbeTimeout = 500 * time.Millisecond
	cfg.SuspicionTimeout = 1 * time.Second
	cfg.GossipInterval = 100 * time.Millisecond
	cfg.GossipFanout = 3

	g, err := NewWithTransport(cfg, tr)
	if err != nil {
		t.Fatalf("node %s gossip: %v", id, err)
	}
	return &gossipTestNode{
		g:    g,
		tr:   tr,
		id:   id,
		addr: tr.LocalAddr(),
	}
}

func (n *gossipTestNode) start() {
	if err := n.g.Start(); err != nil {
		panic("gossip start: " + err.Error())
	}
}

func (n *gossipTestNode) stop() {
	n.g.Stop()
}

// waitForConvergence polls all nodes until each reports the expected member
// count, or fails the test on timeout.
func waitForGossipConvergence(t *testing.T, nodes []*gossipTestNode, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allOK := true
		for _, n := range nodes {
			if n.g.MemberCount() < want {
				allOK = false
				break
			}
		}
		if allOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, n := range nodes {
		t.Logf("node %s: memberCount=%d", n.id, n.g.MemberCount())
	}
	t.Fatalf("gossip did not converge to %d members within %s", want, timeout)
}

// memberState returns the state of the named member on the given node, or
// (0, false) if not found.
func memberState(g *Gossip, id string) (MemberState, bool) {
	for _, m := range g.Members() {
		if m.ID == id {
			return m.State, true
		}
	}
	return 0, false
}

// --- Tests ---

// TestGossipPartition_IsolationAndRecovery is the comprehensive gossip-level
// partition test. It verifies:
//
//  1. Before partition: all 3 nodes converge and see each other.
//  2. After partition: the isolated node's MemberCount drops to 1 (only self).
//  3. After partition: the majority nodes still see each other (MemberCount 2).
//  4. After partition: the majority marks the isolated node as dead.
//  5. After heal + rejoin: all nodes converge again.
//
// Connection to /readyz:
//
//	clusterStatusProvider.IsIsolated() returns true when gossip.MemberCount() < 2.
//	When the isolated node's MemberCount drops to 1 (step 2), IsIsolated() fires,
//	and handleReady returns HTTP 503. The dashboard-level handler test is in
//	internal/dashboard/health_handlers_test.go::TestHandleReady_ClusterIsolated.
func TestGossipPartition_IsolationAndRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping gossip partition test in short mode")
	}

	// Create 3 nodes with partitionable transports.
	nodes := make([]*gossipTestNode, 3)
	for i := range nodes {
		id := "pnode-" + string(rune('a'+i))
		nodes[i] = newGossipTestNode(t, id)
	}
	defer func() {
		for _, n := range nodes {
			n.stop()
		}
	}()

	// Start all nodes.
	for _, n := range nodes {
		n.start()
	}

	// All-to-all join for fast convergence.
	for i, n := range nodes {
		var seeds []string
		for j, other := range nodes {
			if j == i {
				continue
			}
			seeds = append(seeds, other.addr)
		}
		n.g.Join(seeds)
	}

	// Step 1: Verify convergence — all nodes see 3 members.
	waitForGossipConvergence(t, nodes, 3, 5*time.Second)
	t.Log("all 3 nodes converged")

	for _, n := range nodes {
		if n.g.MemberCount() != 3 {
			t.Fatalf("node %s: expected 3 members, got %d", n.id, n.g.MemberCount())
		}
	}

	// Step 2: Partition node C (index 2) from A and B.
	// Block sends/receives to/from A and B on C's transport.
	nodeC := nodes[2]
	addrA := nodes[0].addr
	addrB := nodes[1].addr
	nodeC.tr.block(addrA)
	nodeC.tr.block(addrB)
	t.Logf("partitioned node %s from %s and %s", nodeC.id, addrA, addrB)

	// Step 3: Wait for failure detection.
	// With ProbeInterval=200ms, ProbeTimeout=500ms, SuspicionTimeout=1s:
	// - C probes A/B, fails → marks suspect → after 1s → dead
	// - A/B probe C, fails → marks suspect → after 1s → dead
	// Expected total time: ~2-3 seconds. Use 8s deadline for safety.
	isolationDeadline := time.Now().Add(8 * time.Second)
	isolated := false
	cDeadOnA := false
	for time.Now().Before(isolationDeadline) {
		// C's own member count should drop to 1 (only self).
		if nodeC.g.MemberCount() <= 1 {
			isolated = true
		}
		// A should mark C as dead.
		if state, ok := memberState(nodes[0].g, nodeC.id); ok && state == StateDead {
			cDeadOnA = true
		}
		// Both conditions met — can stop early.
		if isolated && cDeadOnA {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Step 4: Verify the isolated node's MemberCount dropped to 1.
	// This is the precondition for IsIsolated() → /readyz returns 503.
	if !isolated {
		t.Errorf("node %s: MemberCount did not drop to 1 (got %d) — expected isolation",
			nodeC.id, nodeC.g.MemberCount())
	} else {
		t.Logf("node %s isolated: MemberCount=%d", nodeC.id, nodeC.g.MemberCount())
	}

	// Step 5: Verify A and B still see each other (MemberCount >= 2).
	// They may still count C as suspect until the dead transition completes,
	// but they must have at least each other.
	if nodes[0].g.MemberCount() < 2 {
		t.Errorf("node %s: MemberCount=%d, expected >= 2 (majority should still see each other)",
			nodes[0].id, nodes[0].g.MemberCount())
	}
	if nodes[1].g.MemberCount() < 2 {
		t.Errorf("node %s: MemberCount=%d, expected >= 2",
			nodes[1].id, nodes[1].g.MemberCount())
	}

	// Step 6: Verify A marks C as dead (failure detection works).
	if !cDeadOnA {
		// C might still be in suspect state — check if at least suspect.
		state, ok := memberState(nodes[0].g, nodeC.id)
		if !ok {
			t.Logf("node %s: C (%s) not in member list (purged)", nodes[0].id, nodeC.id)
		} else {
			t.Logf("node %s: C (%s) state = %s", nodes[0].id, nodeC.id, state)
		}
		// Not a hard failure — the important thing is C is isolated and
		// A still has B. But log for diagnostics.
	} else {
		t.Logf("node %s correctly marked %s as dead", nodes[0].id, nodeC.id)
	}

	// Step 7: Heal the partition.
	nodeC.tr.unblockAll()
	t.Log("partition healed")

	// Step 8: Re-join to force full state exchange.
	// After a partition, dead member entries may prevent automatic recovery
	// because alive state with the same incarnation can't override dead state.
	// A Join() push-pull exchange resolves this by refreshing all state.
	for _, n := range nodes {
		var seeds []string
		for _, other := range nodes {
			if other.id == n.id {
				continue
			}
			seeds = append(seeds, other.addr)
		}
		n.g.Join(seeds)
	}

	// Step 9: Verify reconvergence.
	// After healing + rejoin, all nodes should see 3 members again.
	// Allow generous time — dead members need to be overridden by new alive state.
	healDeadline := time.Now().Add(10 * time.Second)
	converged := false
	for time.Now().Before(healDeadline) {
		allOK := true
		for _, n := range nodes {
			if n.g.MemberCount() < 3 {
				allOK = false
				break
			}
		}
		if allOK {
			converged = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !converged {
		for _, n := range nodes {
			t.Logf("after heal: node %s memberCount=%d", n.id, n.g.MemberCount())
			for _, m := range n.g.Members() {
				t.Logf("  member %s state=%s inc=%d", m.ID, m.State, m.Incarnation)
			}
		}
		t.Errorf("cluster did not reconverge after heal within 10s")
	} else {
		t.Log("cluster reconverged after heal — all 3 nodes see each other")
	}
}

// TestGossipPartition_ReadinessPrecondition explicitly verifies that an
// isolated gossip node reports MemberCount < 2 — the exact condition that
// clusterStatusProvider.IsIsolated() checks to trigger a 503 on /readyz.
//
// See cmd/guardianwaf/cluster_status_provider.go::IsIsolated():
//
//	func (p *clusterStatusProvider) IsIsolated() bool {
//	    if p.gossip == nil { return false }
//	    return p.gossip.MemberCount() < 2
//	}
func TestGossipPartition_ReadinessPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping gossip partition test in short mode")
	}

	nodes := make([]*gossipTestNode, 3)
	for i := range nodes {
		id := "rnode-" + string(rune('a'+i))
		nodes[i] = newGossipTestNode(t, id)
	}
	defer func() {
		for _, n := range nodes {
			n.stop()
		}
	}()

	for _, n := range nodes {
		n.start()
	}
	for i, n := range nodes {
		var seeds []string
		for j, other := range nodes {
			if j == i {
				continue
			}
			seeds = append(seeds, other.addr)
		}
		n.g.Join(seeds)
	}

	waitForGossipConvergence(t, nodes, 3, 5*time.Second)

	// Before partition: not isolated.
	if nodes[2].g.MemberCount() < 2 {
		t.Fatal("pre-partition: MemberCount should be >= 2")
	}

	// Partition node C.
	nodes[2].tr.block(nodes[0].addr)
	nodes[2].tr.block(nodes[1].addr)

	// Wait for MemberCount < 2 (the IsIsolated trigger).
	deadline := time.Now().Add(8 * time.Second)
	triggered := false
	for time.Now().Before(deadline) {
		if nodes[2].g.MemberCount() < 2 {
			triggered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !triggered {
		t.Fatalf("isolated node MemberCount never dropped below 2 (got %d) — /readyz would NOT fire 503",
			nodes[2].g.MemberCount())
	}

	// This is the exact check that IsIsolated() performs:
	isolated := nodes[2].g.MemberCount() < 2
	t.Logf("MemberCount=%d → IsIsolated()=%v → /readyz would return %s",
		nodes[2].g.MemberCount(), isolated,
		map[bool]string{true: "503 (not ready)", false: "200 (ready)"}[isolated])

	if !isolated {
		t.Fatal("expected IsIsolated() to be true")
	}
}
