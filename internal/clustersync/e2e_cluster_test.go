package clustersync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// This file contains the full end-to-end integration test that exercises:
//  1. Gossip membership discovery (3 nodes discover each other)
//  2. Raft leader election (via static peers configured from gossip discovery)
//  3. Ban request sent to a follower → leader-redirect (307) response
//  4. Following the redirect to the leader → ban replicated to all nodes
//
// Unlike replication_integration_test.go which uses only Raft, this test adds
// gossip membership and HTTP servers that mimic the dashboard's ban handler
// with leader-redirect logic.

// e2eNode bundles all subsystems for a single cluster node.
type e2eNode struct {
	id       string
	raft     *raft.Raft
	store    *ReplicatedStore
	sm       *StoreStateMachine
	api      *API
	gossip   *gossip.Gossip
	httpSrv  *http.Server
	ln       net.Listener
	dashAddr string // e.g., "http://127.0.0.1:12345"
}

// e2eBanRequest is the JSON body for POST /api/v1/bans.
type e2eBanRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	TTL    string `json:"ttl"` // duration string, e.g., "1h"
}

// setupE2ECluster creates n nodes with Raft + gossip + HTTP ban handlers.
// Nodes discover each other via gossip, and their Raft peers are configured
// from the gossip member list (simulating the peersync bridge).
func setupE2ECluster(t *testing.T, n int) map[string]*e2eNode {
	t.Helper()

	type nodeInit struct {
		id      string
		raft    *raft.Raft
		store   *ReplicatedStore
		sm      *StoreStateMachine
		api     *API
		gossip  *gossip.Gossip
		httpLn  net.Listener
		dashURL string
	}
	inits := make([]nodeInit, n)

	// Phase 1: Create Raft nodes + HTTP listeners with ephemeral ports.
	for i := 0; i < n; i++ {
		id := "e2e-" + string(rune('a'+i))
		store := NewReplicatedStore()
		sm := NewStoreStateMachine(store, nil)

		r, err := raft.New(raft.Config{
			NodeID:             id,
			Secret:             testClusterSecret,
			BindAddr:           "127.0.0.1:0",
			ElectionTimeoutMin: 2000 * time.Millisecond,
			ElectionTimeoutMax: 4000 * time.Millisecond,
			HeartbeatInterval:  50 * time.Millisecond,
		}, sm)
		if err != nil {
			t.Fatalf("node %s raft create: %v", id, err)
		}

		// Create HTTP listener early so we know the dashboard address
		// before gossip starts — this avoids post-hoc UpdateMember calls
		// and ensures DashboardAddr is correct from the first gossip round.
		httpLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("node %s http listen: %v", id, err)
		}
		dashAddr := "http://" + httpLn.Addr().String()

		// Create gossip node with ephemeral UDP port.
		gCfg := gossip.DefaultConfig(id, "127.0.0.1:0")
		gCfg.Secret = testClusterSecret
		gCfg.RaftAddr = r.Transport().LocalAddr()
		gCfg.DashboardAddr = dashAddr
		gCfg.ProbeInterval = 200 * time.Millisecond
		gCfg.GossipInterval = 100 * time.Millisecond
		gCfg.SuspicionTimeout = 1 * time.Second
		g, err := gossip.New(gCfg)
		if err != nil {
			t.Fatalf("node %s gossip create: %v", id, err)
		}

		inits[i] = nodeInit{
			id:      id,
			raft:    r,
			store:   store,
			sm:      sm,
			api:     NewAPI(r, store),
			gossip:  g,
			httpLn:  httpLn,
			dashURL: dashAddr,
		}
	}

	// Phase 2: Collect gossip addresses for joining.
	var gossipAddrs []string
	for _, ni := range inits {
		ni.gossip.Start()
		gossipAddrs = append(gossipAddrs, ni.gossip.LocalMember().Addr)
	}

	// Phase 3: Each node joins the gossip mesh via the first node.
	for i := 1; i < n; i++ {
		// Join ALL other nodes, not just the first seed. Push-pull exchange
		// with every peer makes gossip converge immediately instead of
		// waiting for periodic dissemination.
		var seeds []string
		for j, addr := range gossipAddrs {
			if j == i {
				continue // skip self
			}
			seeds = append(seeds, addr)
		}
		inits[i].gossip.Join(seeds)
	}

	// Phase 4: Wait for gossip convergence.
	// Scale the deadline with node count: more nodes need more gossip rounds.
	deadline := time.Now().Add(time.Duration(n) * 3 * time.Second)
	for time.Now().Before(deadline) {
		allConverged := true
		for _, ni := range inits {
			if ni.gossip.MemberCount() < n {
				allConverged = false
				break
			}
		}
		if allConverged {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify convergence.
	for _, ni := range inits {
		if ni.gossip.MemberCount() < n {
			t.Fatalf("node %s: gossip did not converge (members=%d, want %d)",
				ni.id, ni.gossip.MemberCount(), n)
		}
	}

	// Phase 5: Configure Raft peers from gossip members (simulates peersync bridge).
	for _, ni := range inits {
		members := ni.gossip.Members()
		peers := make([]raft.Peer, 0, n-1)
		for _, m := range members {
			if m.ID == ni.id {
				continue
			}
			if m.State != gossip.StateAlive {
				continue
			}
			peers = append(peers, raft.Peer{
				ID:   m.ID,
				Addr: m.RaftAddr,
			})
		}
		ni.raft.UpdatePeers(peers)
	}

	// Phase 6: Start Raft nodes.
	nodes := make(map[string]*e2eNode, n)
	for _, ni := range inits {
		if err := ni.raft.Start(); err != nil {
			t.Fatalf("node %s raft start: %v", ni.id, err)
		}

		// Create HTTP server with ban handler.
		node := &e2eNode{
			id:     ni.id,
			raft:   ni.raft,
			store:  ni.store,
			sm:     ni.sm,
			api:    ni.api,
			gossip: ni.gossip,
		}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/bans", node.handleBan)
		mux.HandleFunc("DELETE /api/v1/bans", node.handleUnban)

		// Use the listener we created in Phase 1 so the dashboard address
		// matches what we put in gossip — no UpdateMember hack needed.
		node.dashAddr = ni.dashURL
		srv := &http.Server{Handler: mux}
		go func() { _ = srv.Serve(ni.httpLn) }()
		node.httpSrv = srv

		nodes[ni.id] = node
	}

	// Wait for Raft leader election.
	time.Sleep(300 * time.Millisecond)

	return nodes
}

func teardownE2ECluster(nodes map[string]*e2eNode) {
	for _, n := range nodes {
		if n.httpSrv != nil {
			_ = n.httpSrv.Close()
		}
		if n.ln != nil {
			_ = n.ln.Close()
		}
		if n.gossip != nil {
			n.gossip.Stop()
		}
		if n.raft != nil {
			n.raft.Stop()
		}
	}
}

func waitForE2ELeader(t *testing.T, nodes map[string]*e2eNode, timeout time.Duration) string {
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

// handleBan mimics the dashboard's handleAddBan with leader-redirect logic.
// When ProposeBan returns ErrRaftNotLeader, it looks up the leader's dashboard
// URL from gossip and returns a 307 redirect.
func (n *e2eNode) handleBan(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req e2eBanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	duration := time.Hour
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err == nil {
			duration = d
		}
	}

	err = n.api.ProposeBan(req.IP, duration)
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Not leader → redirect to leader's dashboard URL.
	if isNotLeaderErr(err) {
		leaderID := n.raft.LeaderID()
		if leaderID == "" {
			writeE2EJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":     "not raft leader",
				"leader_id": "",
				"hint":      "no leader elected yet",
			})
			return
		}

		// Look up leader's dashboard URL from gossip.
		leaderURL := ""
		for _, m := range n.gossip.Members() {
			if m.ID == leaderID && m.DashboardAddr != "" {
				leaderURL = m.DashboardAddr
				break
			}
		}

		if leaderURL == "" {
			writeE2EJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":     "not raft leader",
				"leader_id": leaderID,
				"hint":      "leader dashboard URL unknown",
			})
			return
		}

		location := strings.TrimRight(leaderURL, "/") + r.URL.Path
		w.Header().Set("Location", location)
		writeE2EJSON(w, http.StatusTemporaryRedirect, map[string]any{
			"error":      "not raft leader",
			"leader_id":  leaderID,
			"leader_url": leaderURL,
			"location":   location,
		})
		return
	}

	// Other errors.
	writeE2EJSON(w, http.StatusInternalServerError, map[string]any{
		"error": err.Error(),
	})
}

// handleUnban mimics the dashboard's handleRemoveBan with leader-redirect.
func (n *e2eNode) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip parameter", http.StatusBadRequest)
		return
	}

	err := n.api.ProposeUnban(ip)
	if err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if isNotLeaderErr(err) {
		leaderID := n.raft.LeaderID()
		if leaderID == "" {
			writeE2EJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":     "not raft leader",
				"leader_id": "",
			})
			return
		}

		leaderURL := ""
		for _, m := range n.gossip.Members() {
			if m.ID == leaderID && m.DashboardAddr != "" {
				leaderURL = m.DashboardAddr
				break
			}
		}

		if leaderURL == "" {
			writeE2EJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error":     "not raft leader",
				"leader_id": leaderID,
			})
			return
		}

		location := strings.TrimRight(leaderURL, "/") + r.URL.Path + "?ip=" + ip
		w.Header().Set("Location", location)
		writeE2EJSON(w, http.StatusTemporaryRedirect, map[string]any{
			"leader_id": leaderID,
			"location":  location,
		})
		return
	}

	writeE2EJSON(w, http.StatusInternalServerError, map[string]any{
		"error": err.Error(),
	})
}

func isNotLeaderErr(err error) bool {
	return errors.Is(err, ErrRaftNotLeader) || strings.Contains(err.Error(), "not leader")
}

func writeE2EJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// banViaFollower sends a ban request to the given node and follows at most
// one redirect to the leader. Returns the final HTTP status and body.
func banViaFollower(node *e2eNode, ip string) (int, []byte, error) {
	body, _ := json.Marshal(e2eBanRequest{IP: ip, Reason: "e2e test", TTL: "1h"})
	resp, err := http.Post(node.dashAddr+"/api/v1/bans", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Follow one redirect manually (307).
	if resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		if location == "" {
			return resp.StatusCode, nil, fmt.Errorf("307 without Location header")
		}
		resp2, err := http.Post(location, "application/json", strings.NewReader(string(body)))
		if err != nil {
			return 0, nil, err
		}
		defer resp2.Body.Close()
		respBody2, _ := io.ReadAll(resp2.Body)
		return resp2.StatusCode, respBody2, nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

// waitForStoreBan polls the store until the given IP is banned, or times out.
func waitForStoreBan(t *testing.T, store *ReplicatedStore, ip string, timeout time.Duration) bool {
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

// TestE2E_FullClusterFlow exercises the complete end-to-end flow:
// gossip discovery → leader election → ban via follower → 307 redirect
// → ban on leader → replication to all nodes.
func TestE2E_FullClusterFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end cluster test in short mode")
	}

	nodes := setupE2ECluster(t, 3)
	defer teardownE2ECluster(nodes)

	// Wait for gossip DashboardAddr propagation.
	time.Sleep(500 * time.Millisecond)

	// Verify gossip convergence: each node knows all 3 members.
	for _, n := range nodes {
		if n.gossip.MemberCount() != 3 {
			t.Errorf("node %s: gossip member count = %d, want 3", n.id, n.gossip.MemberCount())
		}
	}

	// Verify DashboardAddr propagated via gossip.
	for _, n := range nodes {
		members := n.gossip.Members()
		for _, m := range members {
			if m.DashboardAddr == "" {
				t.Errorf("node %s sees member %s with empty DashboardAddr", n.id, m.ID)
			}
		}
	}

	// Wait for Raft leader election.
	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}
	t.Logf("leader elected: %s", leader)

	// Find a follower.
	var follower *e2eNode
	for _, n := range nodes {
		if n.id != leader {
			follower = n
			break
		}
	}
	if follower == nil {
		t.Fatal("no follower found (all nodes are leaders?)")
	}

	// Send ban request to the follower.
	targetIP := "203.0.113.42"
	status, _, err := banViaFollower(follower, targetIP)
	if err != nil {
		t.Fatalf("banViaFollower: %v", err)
	}

	if status != http.StatusNoContent {
		t.Fatalf("ban via follower: expected final status %d, got %d", http.StatusNoContent, status)
	}

	// Verify the ban replicated to all nodes' stores.
	for _, n := range nodes {
		if !waitForStoreBan(t, n.store, targetIP, 5*time.Second) {
			t.Errorf("node %s: IP %s not banned after replication timeout", n.id, targetIP)
		} else {
			t.Logf("node %s: confirmed ban for %s", n.id, targetIP)
		}
	}

	// Unban via the follower too.
	unbanURL := fmt.Sprintf("%s/api/v1/bans?ip=%s", follower.dashAddr, targetIP)
	req, _ := http.NewRequest("DELETE", unbanURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unban request: %v", err)
	}
	defer resp.Body.Close()

	// Follow redirect if 307.
	if resp.StatusCode == http.StatusTemporaryRedirect {
		location := resp.Header.Get("Location")
		req2, _ := http.NewRequest("DELETE", location, nil)
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			t.Fatalf("unban redirect: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusNoContent {
			t.Fatalf("unban via leader: expected %d, got %d", http.StatusNoContent, resp2.StatusCode)
		}
	} else if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unban: expected %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Verify the ban is removed on all nodes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allUnbanned := true
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

	for _, n := range nodes {
		if n.store.IsBanned(targetIP) {
			t.Errorf("node %s: IP %s still banned after unban replication", n.id, targetIP)
		}
	}
}

// TestE2E_BanOnLeaderDirectly sends a ban directly to the leader and verifies
// it succeeds (204) without a redirect.
func TestE2E_BanOnLeaderDirectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end cluster test in short mode")
	}

	nodes := setupE2ECluster(t, 3)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected within timeout")
	}

	leaderNode := nodes[leader]
	targetIP := "198.51.100.7"

	body, _ := json.Marshal(e2eBanRequest{IP: targetIP, Reason: "direct", TTL: "30m"})
	resp, err := http.Post(leaderNode.dashAddr+"/api/v1/bans", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("ban request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ban on leader: expected %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	// Verify replication.
	for _, n := range nodes {
		if !waitForStoreBan(t, n.store, targetIP, 5*time.Second) {
			t.Errorf("node %s: IP %s not banned after replication timeout", n.id, targetIP)
		}
	}
}

// TestE2E_GossipDashboardAddrPropagation verifies that the DashboardAddr field
// propagates to all nodes via gossip membership.
func TestE2E_GossipDashboardAddrPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	nodes := setupE2ECluster(t, 3)
	defer teardownE2ECluster(nodes)

	// Wait for gossip to propagate DashboardAddr updates.
	time.Sleep(1 * time.Second)

	// Each node should see all 3 members with non-empty DashboardAddr.
	for _, n := range nodes {
		members := n.gossip.Members()
		if len(members) != 3 {
			t.Errorf("node %s: %d members, want 3", n.id, len(members))
			continue
		}
		for _, m := range members {
			if m.DashboardAddr == "" {
				t.Errorf("node %s: member %s has empty DashboardAddr", n.id, m.ID)
			}
		}
	}
}
