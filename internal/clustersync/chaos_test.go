package clustersync

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// This file contains chaos/fault-injection tests that verify cluster
// resilience under leader failure:
//
//  1. Ban committed before leader kill → survives failover (already-replicated)
//  2. Ban proposed after failover → new leader accepts and replicates
//  3. Multiple consecutive bans across failover boundary → all converge
//  4. Concurrent ban during leader kill → either committed or re-proposable
//
// These tests use a 5-node cluster (quorum = 3) so the cluster survives
// the loss of one leader and still has a healthy majority.

// killLeader stops the given node's Raft + gossip + HTTP, simulating a
// hard crash. The node's store remains in-memory for post-mortem inspection.
func killLeader(t *testing.T, node *e2eNode) {
	t.Helper()
	t.Logf("killing leader %s", node.id)
	node.raft.Stop()
	node.raft.Transport().Close()
	if node.httpSrv != nil {
		_ = node.httpSrv.Close()
	}
	if node.gossip != nil {
		node.gossip.Stop()
	}
	// Mark as killed so teardown doesn't double-close.
	node.httpSrv = nil
	node.gossip = nil
}

// waitForNewLeader polls the surviving nodes (excluding the killed leader)
// until exactly one reports itself as leader. Returns the new leader's ID.
func waitForNewLeader(t *testing.T, nodes map[string]*e2eNode, killedID string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		var leaderID string
		for id, n := range nodes {
			if id == killedID {
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

// banDirect sends a ban request directly to the given node (no redirect
// following). Returns the HTTP status code and error.
func banDirect(node *e2eNode, ip string) (int, error) {
	body, _ := json.Marshal(e2eBanRequest{IP: ip, Reason: "chaos test", TTL: "1h"})
	resp, err := http.Post(node.dashAddr+"/api/v1/bans", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// TestChaos_KillLeaderCommittedBansSurvive verifies that bans already
// committed and replicated before the leader dies remain present on all
// surviving nodes after failover.
func TestChaos_KillLeaderCommittedBansSurvive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("initial leader: %s", leader)

	// Commit several bans on the leader.
	committedIPs := []string{
		"10.0.0.1",
		"10.0.0.2",
		"10.0.0.3",
	}
	for _, ip := range committedIPs {
		status, err := banDirect(nodes[leader], ip)
		if err != nil {
			t.Fatalf("ban %s: %v", ip, err)
		}
		if status != http.StatusNoContent {
			t.Fatalf("ban %s: expected 204, got %d", ip, status)
		}
	}

	// Wait for replication to all nodes.
	for _, ip := range committedIPs {
		for id, n := range nodes {
			if !waitForStoreBan(t, n.store, ip, 5*time.Second) {
				t.Fatalf("node %s: IP %s not replicated before kill", id, ip)
			}
		}
	}
	t.Log("all committed bans replicated to all 5 nodes")

	// Kill the leader.
	killLeader(t, nodes[leader])

	// Wait for a new leader among the survivors.
	newLeader := waitForNewLeader(t, nodes, leader, 10*time.Second)
	if newLeader == "" {
		t.Fatalf("no new leader elected after killing %s", leader)
	}
	if newLeader == leader {
		t.Fatal("same node became leader again (should be dead)")
	}
	t.Logf("new leader after failover: %s", newLeader)

	// Verify all committed bans survived the failover on every surviving node.
	for _, ip := range committedIPs {
		for id, n := range nodes {
			if id == leader {
				continue // killed node — store is stale/inaccessible
			}
			if !n.store.IsBanned(ip) {
				t.Errorf("node %s: committed ban %s lost after failover", id, ip)
			}
		}
	}
	t.Log("all committed bans survived failover")
}

// TestChaos_NewLeaderAcceptsBans verifies that after the leader dies and a
// new leader is elected, new ban proposals on the new leader succeed and
// replicate to all surviving nodes.
func TestChaos_NewLeaderAcceptsBans(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("initial leader: %s", leader)

	// Kill the leader immediately (no prior bans).
	killLeader(t, nodes[leader])

	newLeader := waitForNewLeader(t, nodes, leader, 10*time.Second)
	if newLeader == "" {
		t.Fatal("no new leader elected")
	}
	t.Logf("new leader: %s", newLeader)

	// Propose new bans on the new leader.
	newIPs := []string{
		"192.168.1.10",
		"192.168.1.20",
		"192.168.1.30",
	}
	for _, ip := range newIPs {
		status, err := banDirect(nodes[newLeader], ip)
		if err != nil {
			t.Fatalf("ban %s on new leader: %v", ip, err)
		}
		if status != http.StatusNoContent {
			t.Fatalf("ban %s: expected 204 on new leader, got %d", ip, status)
		}
	}

	// Verify replication to all surviving nodes.
	for _, ip := range newIPs {
		for id, n := range nodes {
			if id == leader {
				continue
			}
			if !waitForStoreBan(t, n.store, ip, 5*time.Second) {
				t.Errorf("node %s: IP %s not replicated after failover", id, ip)
			}
		}
	}
	t.Log("new bans replicated to all surviving nodes after failover")
}

// TestChaos_BansAcrossFailoverBoundary verifies the full lifecycle:
// commit bans → kill leader → re-elect → commit more bans → all converge.
func TestChaos_BansAcrossFailoverBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("phase 1 leader: %s", leader)

	// Phase 1: Commit bans on the original leader.
	preKillIPs := []string{"172.16.0.1", "172.16.0.2"}
	for _, ip := range preKillIPs {
		status, err := banDirect(nodes[leader], ip)
		if err != nil || status != http.StatusNoContent {
			t.Fatalf("pre-kill ban %s: err=%v status=%d", ip, err, status)
		}
	}

	// Wait for replication.
	for _, ip := range preKillIPs {
		for _, n := range nodes {
			if !waitForStoreBan(t, n.store, ip, 5*time.Second) {
				t.Fatalf("pre-kill ban %s not replicated", ip)
			}
		}
	}

	// Phase 2: Kill the leader.
	killLeader(t, nodes[leader])

	newLeader := waitForNewLeader(t, nodes, leader, 10*time.Second)
	if newLeader == "" {
		t.Fatal("no new leader after failover")
	}
	t.Logf("phase 2 leader: %s", newLeader)

	// Phase 3: Commit more bans on the new leader.
	postKillIPs := []string{"172.16.1.1", "172.16.1.2", "172.16.1.3"}
	for _, ip := range postKillIPs {
		status, err := banDirect(nodes[newLeader], ip)
		if err != nil || status != http.StatusNoContent {
			t.Fatalf("post-kill ban %s: err=%v status=%d", ip, err, status)
		}
	}

	// Wait for replication of post-kill bans.
	for _, ip := range postKillIPs {
		for id, n := range nodes {
			if id == leader {
				continue
			}
			if !waitForStoreBan(t, n.store, ip, 5*time.Second) {
				t.Errorf("node %s: post-kill ban %s not replicated", id, ip)
			}
		}
	}

	// Phase 4: Verify pre-kill bans are still present on survivors.
	for _, ip := range preKillIPs {
		for id, n := range nodes {
			if id == leader {
				continue
			}
			if !n.store.IsBanned(ip) {
				t.Errorf("node %s: pre-kill ban %s lost after failover", id, ip)
			}
		}
	}

	total := len(preKillIPs) + len(postKillIPs)
	t.Logf("success: %d bans (%d pre-kill + %d post-kill) all converged on surviving nodes",
		total, len(preKillIPs), len(postKillIPs))
}

// TestChaos_FollowerBanRedirectAfterFailover verifies that after failover,
// a follower correctly redirects ban requests to the NEW leader (not the
// dead one). This exercises the gossip DashboardAddr + Raft LeaderID
// integration under churn.
func TestChaos_FollowerBanRedirectAfterFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("initial leader: %s", leader)

	// Kill the leader.
	killLeader(t, nodes[leader])

	newLeader := waitForNewLeader(t, nodes, leader, 10*time.Second)
	if newLeader == "" {
		t.Fatal("no new leader")
	}
	t.Logf("new leader: %s", newLeader)

	// Find a surviving follower (not the dead leader, not the new leader).
	var follower *e2eNode
	for id, n := range nodes {
		if id == leader || id == newLeader {
			continue
		}
		follower = n
		break
	}
	if follower == nil {
		t.Fatal("no surviving follower found")
	}
	t.Logf("sending ban via follower %s", follower.id)

	// Send ban via the follower — should redirect to the new leader.
	targetIP := "203.0.113.99"
	status, _, err := banViaFollower(follower, targetIP)
	if err != nil {
		t.Fatalf("banViaFollower after failover: %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("ban via follower after failover: expected 204, got %d", status)
	}

	// Verify replication to all surviving nodes.
	for id, n := range nodes {
		if id == leader {
			continue
		}
		if !waitForStoreBan(t, n.store, targetIP, 5*time.Second) {
			t.Errorf("node %s: post-failover redirect ban %s not replicated", id, targetIP)
		}
	}
	t.Log("follower redirect to new leader works after failover")
}

// TestChaos_SecondLeaderKill verifies the cluster survives losing TWO
// leaders sequentially (double failover). With 5 nodes and quorum 3,
// losing 2 nodes still leaves 3 — enough for quorum.
func TestChaos_SecondLeaderKill(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	// First leader.
	leader1 := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader1 == "" {
		t.Fatal("no leader elected")
	}
	t.Logf("leader 1: %s", leader1)

	// Commit a ban on leader 1.
	ip1 := "100.64.0.1"
	if status, err := banDirect(nodes[leader1], ip1); err != nil || status != http.StatusNoContent {
		t.Fatalf("ban on leader 1: err=%v status=%d", err, status)
	}
	for _, n := range nodes {
		if !waitForStoreBan(t, n.store, ip1, 5*time.Second) {
			t.Fatalf("ban %s not replicated", ip1)
		}
	}

	// Kill leader 1.
	killLeader(t, nodes[leader1])
	leader2 := waitForNewLeader(t, nodes, leader1, 10*time.Second)
	if leader2 == "" {
		t.Fatal("no leader 2 after first failover")
	}
	t.Logf("leader 2: %s", leader2)

	// Commit a ban on leader 2.
	ip2 := "100.64.0.2"
	if status, err := banDirect(nodes[leader2], ip2); err != nil || status != http.StatusNoContent {
		t.Fatalf("ban on leader 2: err=%v status=%d", err, status)
	}
	for id, n := range nodes {
		if id == leader1 {
			continue
		}
		if !waitForStoreBan(t, n.store, ip2, 5*time.Second) {
			t.Fatalf("ban %s not replicated after first failover on node %s", ip2, id)
		}
	}

	// Kill leader 2.
	killLeader(t, nodes[leader2])
	leader3 := waitForNewLeaderExcluding(t, nodes, []string{leader1, leader2}, 10*time.Second)
	if leader3 == "" {
		t.Fatal("no leader 3 after second failover")
	}
	t.Logf("leader 3: %s", leader3)

	// Commit a ban on leader 3.
	ip3 := "100.64.0.3"
	if status, err := banDirect(nodes[leader3], ip3); err != nil || status != http.StatusNoContent {
		t.Fatalf("ban on leader 3: err=%v status=%d", err, status)
	}

	// Verify ip3 replicates to the 3 remaining nodes.
	for id, n := range nodes {
		if id == leader1 || id == leader2 {
			continue
		}
		if !waitForStoreBan(t, n.store, ip3, 5*time.Second) {
			t.Errorf("node %s: ban %s not replicated after second failover", id, ip3)
		}
	}

	// Verify ip1 and ip2 survived both failovers on the 3 remaining nodes.
	for id, n := range nodes {
		if id == leader1 || id == leader2 {
			continue
		}
		if !n.store.IsBanned(ip1) {
			t.Errorf("node %s: ban %s lost after double failover", id, ip1)
		}
		if !n.store.IsBanned(ip2) {
			t.Errorf("node %s: ban %s lost after double failover", id, ip2)
		}
	}

	t.Logf("double failover survived: 3 bans across 3 leaders, %d nodes remaining",
		len(nodes)-2)
}

// waitForNewLeaderExcluding polls nodes (excluding the given IDs) until
// exactly one reports itself as leader.
func waitForNewLeaderExcluding(t *testing.T, nodes map[string]*e2eNode, excluded []string, timeout time.Duration) string {
	t.Helper()
	excludeSet := make(map[string]bool, len(excluded))
	for _, id := range excluded {
		excludeSet[id] = true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		leaders := 0
		var leaderID string
		for id, n := range nodes {
			if excludeSet[id] {
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

// TestChaos_KilledLeaderNodeNotReachable verifies that after killing the
// leader, HTTP requests to the dead node's dashboard fail (connection
// refused) rather than hanging — confirming the kill fully stopped the
// HTTP server.
func TestChaos_KilledLeaderNodeNotReachable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}

	deadNode := nodes[leader]
	dashAddr := deadNode.dashAddr

	killLeader(t, nodes[leader])

	// Give the OS a moment to release the port.
	time.Sleep(200 * time.Millisecond)

	// HTTP request to the dead node should fail.
	client := &http.Client{Timeout: 2 * time.Second}
	_, err := client.Get(dashAddr + "/api/v1/bans")
	if err == nil {
		t.Error("expected connection error to dead leader, got nil")
	} else {
		t.Logf("dead leader correctly unreachable: %v", err)
	}
}

// TestChaos_StoreConsistencyAfterFailover verifies that after failover,
// all surviving stores have the exact same set of banned IPs (no split-brain).
func TestChaos_StoreConsistencyAfterFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping chaos test in short mode")
	}

	nodes := setupE2ECluster(t, 5)
	defer teardownE2ECluster(nodes)

	time.Sleep(500 * time.Millisecond)

	leader := waitForE2ELeader(t, nodes, 10*time.Second)
	if leader == "" {
		t.Fatal("no leader elected")
	}

	// Commit a known set of bans.
	allIPs := []string{"10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4", "10.1.1.5"}
	for _, ip := range allIPs {
		if status, err := banDirect(nodes[leader], ip); err != nil || status != http.StatusNoContent {
			t.Fatalf("ban %s: err=%v status=%d", ip, err, status)
		}
	}
	for _, ip := range allIPs {
		for _, n := range nodes {
			if !waitForStoreBan(t, n.store, ip, 5*time.Second) {
				t.Fatalf("ban %s not replicated", ip)
			}
		}
	}

	// Kill the leader.
	killLeader(t, nodes[leader])

	// Wait for new leader.
	newLeader := waitForNewLeader(t, nodes, leader, 10*time.Second)
	if newLeader == "" {
		t.Fatal("no new leader")
	}

	// Commit one more ban after failover.
	postIP := "10.2.2.1"
	if status, err := banDirect(nodes[newLeader], postIP); err != nil || status != http.StatusNoContent {
		t.Fatalf("post-failover ban: err=%v status=%d", err, status)
	}

	// Wait for post-failover ban replication.
	for id, n := range nodes {
		if id == leader {
			continue
		}
		if !waitForStoreBan(t, n.store, postIP, 5*time.Second) {
			t.Fatalf("node %s: post-failover ban not replicated", id)
		}
	}

	// Verify consistency: every surviving node has exactly the same banned set.
	expectedIPs := append(allIPs, postIP)
	for id, n := range nodes {
		if id == leader {
			continue
		}
		banned := n.store.BannedIPs()
		bannedSet := make(map[string]bool, len(banned))
		for _, b := range banned {
			bannedSet[b.IP] = true
		}
		for _, ip := range expectedIPs {
			if !bannedSet[ip] {
				t.Errorf("node %s: missing ban %s (store inconsistency)", id, ip)
			}
		}
		// Check for extra bans (shouldn't happen, but catches split-brain).
		for ip := range bannedSet {
			found := false
			for _, eip := range expectedIPs {
				if ip == eip {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("node %s: unexpected extra ban %s (store inconsistency)", id, ip)
			}
		}
	}

	t.Logf("all %d surviving nodes have consistent ban sets after failover",
		len(nodes)-1)
}
