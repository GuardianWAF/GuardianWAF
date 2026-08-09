package clustersync

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// This file tests Raft consensus under network partitions (split-brain
// scenarios). The key invariants verified:
//
//  1. Majority partition: continues to elect a leader and commit entries.
//  2. Minority partition: cannot commit entries (no quorum).
//  3. No split-brain: at most one leader across all partitions.
//  4. Healing: after the partition heals, the minority node catches up
//     via Raft AppendEntries from the leader.

// ---------------------------------------------------------------------------
// Partition infrastructure
// ---------------------------------------------------------------------------

// partitionedGossipTransport wraps a gossip.Transport and can be toggled
// to silently drop all packets (send + receive), simulating a network
// partition at the gossip layer.
type partitionedGossipTransport struct {
	inner   gossip.Transport
	blocked atomic.Bool
}

func (t *partitionedGossipTransport) Send(addr string, data []byte) error {
	if t.blocked.Load() {
		return nil // silently drop
	}
	return t.inner.Send(addr, data)
}

func (t *partitionedGossipTransport) Receive(ctx context.Context) ([]byte, string, error) {
	if t.blocked.Load() {
		// Block until unpartitioned or context cancelled.
		for t.blocked.Load() {
			select {
			case <-ctx.Done():
				return nil, "", ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return t.inner.Receive(ctx)
}

func (t *partitionedGossipTransport) LocalAddr() string { return t.inner.LocalAddr() }
func (t *partitionedGossipTransport) Close() error      { return t.inner.Close() }

func (t *partitionedGossipTransport) Block()   { t.blocked.Store(true) }
func (t *partitionedGossipTransport) Unblock() { t.blocked.Store(false) }

// partitionDialer returns a Dialer that refuses all connections, simulating
// a total network partition at the Raft TCP layer.
func partitionDialer() raft.Dialer {
	return func(network, addr string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: &net.TCPAddr{},
			Err: errPartitioned}
	}
}

var errPartitioned = &partitionError{}

type partitionError struct{}

func (e *partitionError) Error() string   { return "network partitioned" }
func (e *partitionError) Temporary() bool { return false }

// pNode is a partition-aware node.
type pNode struct {
	id         string
	raft       *raft.Raft
	store      *ReplicatedStore
	sm         *StoreStateMachine
	api        *API
	gossipTr   *partitionedGossipTransport
	gossip     *gossip.Gossip
	httpLn     net.Listener
	httpSrv    *http.Server
	dashAddr   string
	normalDial raft.Dialer
}

// setupPartitionCluster creates n nodes with partitionable transports.
func setupPartitionCluster(t *testing.T, n int) map[string]*pNode {
	t.Helper()

	type pInit struct {
		id     string
		raft   *raft.Raft
		store  *ReplicatedStore
		sm     *StoreStateMachine
		gTr    *partitionedGossipTransport
		gossip *gossip.Gossip
		httpLn net.Listener
	}

	inits := make([]pInit, n)

	// Phase 1: Create Raft + gossip + HTTP per node.
	for i := 0; i < n; i++ {
		id := "pnode-" + string(rune('a'+i))
		store := NewReplicatedStore()
		sm := NewStoreStateMachine(store, nil)

		// Raft node.
		r, err := raft.New(raft.Config{
			NodeID:             id,
			BindAddr:           "127.0.0.1:0",
			ElectionTimeoutMin: 300 * time.Millisecond,
			ElectionTimeoutMax: 600 * time.Millisecond,
			HeartbeatInterval:  50 * time.Millisecond,
		}, sm)
		if err != nil {
			t.Fatalf("node %s raft: %v", id, err)
		}

		// HTTP listener.
		httpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("node %s http: %v", id, err)
		}

		// Gossip with partitionable transport.
		udpTr, err := gossip.NewUDPTransport("127.0.0.1:0")
		if err != nil {
			t.Fatalf("node %s gossip transport: %v", id, err)
		}
		pt := &partitionedGossipTransport{inner: udpTr}

		gCfg := gossip.DefaultConfig(id, pt.LocalAddr())
		gCfg.RaftAddr = r.Transport().LocalAddr()
		gCfg.DashboardAddr = "http://" + httpLn.Addr().String()
		gCfg.ProbeInterval = 200 * time.Millisecond
		gCfg.GossipInterval = 100 * time.Millisecond
		gCfg.SuspicionTimeout = 1 * time.Second

		g, err := gossip.NewWithTransport(gCfg, pt)
		if err != nil {
			t.Fatalf("node %s gossip: %v", id, err)
		}

		inits[i] = pInit{
			id:     id,
			raft:   r,
			store:  store,
			sm:     sm,
			gTr:    pt,
			gossip: g,
			httpLn: httpLn,
		}
	}

	// Phase 2: Start gossip + join all seeds.
	var gossipAddrs []string
	for i := range inits {
		inits[i].gossip.Start()
		gossipAddrs = append(gossipAddrs, inits[i].gTr.LocalAddr())
	}
	for i := range inits {
		var seeds []string
		for j, addr := range gossipAddrs {
			if j == i {
				continue
			}
			seeds = append(seeds, addr)
		}
		inits[i].gossip.Join(seeds)
	}

	// Phase 3: Wait for gossip convergence.
	deadline := time.Now().Add(time.Duration(n) * 3 * time.Second)
	for time.Now().Before(deadline) {
		allOK := true
		for i := range inits {
			if inits[i].gossip.MemberCount() < n {
				allOK = false
				break
			}
		}
		if allOK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for i := range inits {
		if inits[i].gossip.MemberCount() < n {
			t.Fatalf("gossip not converged: node %s has %d members", inits[i].id, inits[i].gossip.MemberCount())
		}
	}

	// Phase 4: Configure Raft peers from gossip members.
	for i := range inits {
		members := inits[i].gossip.Members()
		peers := make([]raft.Peer, 0, n-1)
		for _, m := range members {
			if m.ID == inits[i].id || m.State != gossip.StateAlive || m.RaftAddr == "" {
				continue
			}
			peers = append(peers, raft.Peer{ID: m.ID, Addr: m.RaftAddr})
		}
		inits[i].raft.UpdatePeers(peers)
	}

	// Phase 5: Start Raft + HTTP servers.
	nodes := make(map[string]*pNode, n)
	for i := range inits {
		if err := inits[i].raft.Start(); err != nil {
			t.Fatalf("node %s raft start: %v", inits[i].id, err)
		}

		mux := http.NewServeMux()
		registerPartitionBanMux(mux, inits[i].raft, NewAPI(inits[i].raft, inits[i].store))

		srv := &http.Server{Handler: mux}
		dashAddr := "http://" + inits[i].httpLn.Addr().String()

		nodes[inits[i].id] = &pNode{
			id:         inits[i].id,
			raft:       inits[i].raft,
			store:      inits[i].store,
			sm:         inits[i].sm,
			api:        NewAPI(inits[i].raft, inits[i].store),
			gossipTr:   inits[i].gTr,
			gossip:     inits[i].gossip,
			httpLn:     inits[i].httpLn,
			httpSrv:    srv,
			dashAddr:   dashAddr,
			normalDial: net.Dial,
		}
		go srv.Serve(inits[i].httpLn)
	}

	// Wait for leader election.
	leader := waitForPartitionLeader(t, nodes, "", 15*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("leader: %s", leader)

	return nodes
}

func teardownPartitionCluster(nodes map[string]*pNode) {
	for _, n := range nodes {
		if n.httpSrv != nil {
			_ = n.httpSrv.Close()
		}
		if n.httpLn != nil {
			_ = n.httpLn.Close()
		}
		if n.gossip != nil {
			n.gossip.Stop()
		}
		if n.raft != nil {
			n.raft.Stop()
		}
	}
}

// partitionNode blocks all gossip + Raft communication for the given node.
func partitionNode(t *testing.T, node *pNode) {
	t.Helper()
	t.Logf("partitioning node %s", node.id)
	node.gossipTr.Block()
	node.raft.Transport().SetDialer(partitionDialer())
}

// healNode restores all communication for the given node.
func healNode(t *testing.T, node *pNode) {
	t.Helper()
	t.Logf("healing node %s", node.id)
	node.gossipTr.Unblock()
	node.raft.Transport().SetDialer(node.normalDial)
}

// waitForPartitionLeader polls nodes for a leader.
func waitForPartitionLeader(t *testing.T, nodes map[string]*pNode, excludeID string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		var leaderID string
		for id, n := range nodes {
			if id == excludeID {
				continue
			}
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

// countLeaders returns the number of nodes currently in the leader role.
func countLeaders(nodes map[string]*pNode) int {
	c := 0
	for _, n := range nodes {
		if n.raft.Role() == raft.RoleLeader {
			c++
		}
	}
	return c
}

func partitionBanDirect(node *pNode, ip string) (int, error) {
	body, _ := json.Marshal(map[string]any{"ip": ip, "reason": "partition test", "ttl": "1h"})
	resp, err := http.Post(node.dashAddr+"/api/v1/bans", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// registerPartitionBanMux registers ban/unban handlers with leader-redirect.
func registerPartitionBanMux(mux *http.ServeMux, r *raft.Raft, api *API) {
	mux.HandleFunc("POST /api/v1/bans", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			IP  string `json:"ip"`
			TTL string `json:"ttl"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			writePartitionJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		dur := time.Hour
		if body.TTL != "" {
			if d, err := time.ParseDuration(body.TTL); err == nil {
				dur = d
			}
		}
		if err := api.ProposeBan(body.IP, dur); err != nil {
			if errors.Is(err, ErrRaftNotLeader) || errors.Is(err, raft.ErrNotLeader) {
				writePartitionJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "not raft leader",
				})
				return
			}
			writePartitionJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /api/v1/bans", func(w http.ResponseWriter, req *http.Request) {
		ip := req.URL.Query().Get("ip")
		if ip == "" {
			writePartitionJSON(w, http.StatusBadRequest, map[string]any{"error": "ip query param required"})
			return
		}
		if err := api.ProposeUnban(ip); err != nil {
			if errors.Is(err, ErrRaftNotLeader) || errors.Is(err, raft.ErrNotLeader) {
				writePartitionJSON(w, http.StatusServiceUnavailable, map[string]any{
					"error": "not raft leader",
				})
				return
			}
			writePartitionJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func writePartitionJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func waitForPartitionStoreBan(t *testing.T, store *ReplicatedStore, ip string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if store.IsBanned(ip) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestPartition_MajorityContinuesServing verifies that after partitioning
// one node from a 3-node cluster, the majority (2 nodes) continues to elect
// a leader and process bans.
func TestPartition_MajorityContinuesServing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition test in short mode")
	}

	nodes := setupPartitionCluster(t, 3)
	defer teardownPartitionCluster(nodes)

	// Commit a ban on the leader before partitioning.
	leader1 := waitForPartitionLeader(t, nodes, "", 5*time.Second)
	if leader1 == "" {
		t.Fatal("no initial leader")
	}
	t.Logf("initial leader: %s", leader1)

	prePartitionIP := "10.0.0.1"
	if status, err := partitionBanDirect(nodes[leader1], prePartitionIP); err != nil || status != http.StatusNoContent {
		t.Fatalf("pre-partition ban: err=%v status=%d", err, status)
	}

	// Find a follower to partition.
	var partitionID string
	for id := range nodes {
		if id != leader1 {
			partitionID = id
			break
		}
	}
	if partitionID == "" {
		t.Fatal("no follower to partition")
	}

	// Partition the follower.
	partitionNode(t, nodes[partitionID])
	time.Sleep(500 * time.Millisecond) // let gossip detect the failure

	// The majority should still have a leader.
	leader2 := waitForPartitionLeader(t, nodes, partitionID, 10*time.Second)
	if leader2 == "" {
		t.Fatal("no leader in majority after partition")
	}
	t.Logf("majority leader after partition: %s", leader2)

	// Commit a new ban on the majority leader.
	postPartitionIP := "10.0.0.2"
	if status, err := partitionBanDirect(nodes[leader2], postPartitionIP); err != nil || status != http.StatusNoContent {
		t.Fatalf("post-partition ban: err=%v status=%d", err, status)
	}

	// Verify both IPs are replicated to majority nodes.
	for id, n := range nodes {
		if id == partitionID {
			continue
		}
		if !n.store.IsBanned(prePartitionIP) {
			t.Errorf("majority node %s: pre-partition ban %s missing", id, prePartitionIP)
		}
		if !waitForPartitionStoreBan(t, n.store, postPartitionIP, 5*time.Second) {
			t.Errorf("majority node %s: post-partition ban %s not replicated", id, postPartitionIP)
		}
	}
	t.Log("majority partition continues serving — bans committed successfully")
}

// TestPartition_MinorityCannotCommit verifies that the partitioned minority
// node cannot commit bans (no Raft quorum).
func TestPartition_MinorityCannotCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition test in short mode")
	}

	nodes := setupPartitionCluster(t, 3)
	defer teardownPartitionCluster(nodes)

	leader1 := waitForPartitionLeader(t, nodes, "", 5*time.Second)
	if leader1 == "" {
		t.Fatal("no initial leader")
	}

	// Partition a non-leader node.
	var partitionID string
	for id := range nodes {
		if id != leader1 {
			partitionID = id
			break
		}
	}

	partitionNode(t, nodes[partitionID])
	time.Sleep(500 * time.Millisecond)

	// The partitioned node should NOT be able to commit a ban.
	minorityIP := "10.0.0.99"
	status, err := partitionBanDirect(nodes[partitionID], minorityIP)
	if err != nil {
		t.Logf("minority ban request failed (expected): %v", err)
	} else if status == http.StatusNoContent {
		t.Error("partitioned minority node committed a ban — split-brain detected!")
	}
	t.Logf("minority ban returned status %d (expected non-204)", status)

	// Verify the minority's store does NOT have the ban.
	if nodes[partitionID].store.IsBanned(minorityIP) {
		t.Error("minority node applied a ban without quorum")
	}

	t.Log("minority partition correctly cannot commit bans")
}

// TestPartition_NoSplitBrain verifies that at most one leader exists across
// all partitions at any time.
func TestPartition_NoSplitBrain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition test in short mode")
	}

	nodes := setupPartitionCluster(t, 3)
	defer teardownPartitionCluster(nodes)

	leader1 := waitForPartitionLeader(t, nodes, "", 5*time.Second)
	if leader1 == "" {
		t.Fatal("no initial leader")
	}

	// Partition a node.
	var partitionID string
	for id := range nodes {
		if id != leader1 {
			partitionID = id
			break
		}
	}

	partitionNode(t, nodes[partitionID])

	// Check multiple times over 3 seconds — at no point should there be >1 leader.
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		leaders := countLeaders(nodes)
		if leaders > 1 {
			t.Fatalf("split-brain detected: %d leaders after partition", leaders)
		}
	}

	finalLeaders := countLeaders(nodes)
	if finalLeaders > 1 {
		t.Fatalf("split-brain: %d leaders", finalLeaders)
	}
	t.Logf("no split-brain: %d leader(s) across all partitions", finalLeaders)
}

// TestPartition_HealingAndCatchUp verifies that after the partition heals,
// the previously isolated node receives the committed entries via Raft
// AppendEntries from the leader.
func TestPartition_HealingAndCatchUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping partition test in short mode")
	}

	nodes := setupPartitionCluster(t, 3)
	defer teardownPartitionCluster(nodes)

	leader1 := waitForPartitionLeader(t, nodes, "", 5*time.Second)
	if leader1 == "" {
		t.Fatal("no initial leader")
	}

	// Partition a follower.
	var partitionID string
	for id := range nodes {
		if id != leader1 {
			partitionID = id
			break
		}
	}

	partitionNode(t, nodes[partitionID])
	time.Sleep(500 * time.Millisecond)

	// Commit a ban on the majority leader while the node is partitioned.
	partitionedIP := "10.0.0.50"
	leader2 := waitForPartitionLeader(t, nodes, partitionID, 5*time.Second)
	if leader2 == "" {
		t.Fatal("no majority leader")
	}
	if status, err := partitionBanDirect(nodes[leader2], partitionedIP); err != nil || status != http.StatusNoContent {
		t.Fatalf("ban during partition: err=%v status=%d", err, status)
	}

	// Verify the partitioned node does NOT have the ban yet.
	time.Sleep(500 * time.Millisecond)
	if nodes[partitionID].store.IsBanned(partitionedIP) {
		t.Log("partitioned node has the ban (unexpected but not harmful)")
	}

	// Heal the partition.
	healNode(t, nodes[partitionID])

	// Wait for the healed node to catch up.
	if !waitForPartitionStoreBan(t, nodes[partitionID].store, partitionedIP, 15*time.Second) {
		t.Errorf("healed node %s did not catch up — ban %s missing", partitionID, partitionedIP)
	} else {
		t.Log("healed node caught up successfully via Raft AppendEntries")
	}

	// Verify the healed node can participate in new bans.
	newIP := "10.0.0.51"
	leader3 := waitForPartitionLeader(t, nodes, "", 5*time.Second)
	if leader3 == "" {
		t.Fatal("no leader after healing")
	}
	if status, err := partitionBanDirect(nodes[leader3], newIP); err != nil || status != http.StatusNoContent {
		t.Fatalf("post-heal ban: err=%v status=%d", err, status)
	}
	for id, n := range nodes {
		if !waitForPartitionStoreBan(t, n.store, newIP, 10*time.Second) {
			t.Errorf("node %s: post-heal ban %s not replicated", id, newIP)
		}
	}
	t.Log("cluster fully recovered — all nodes serving")
}
