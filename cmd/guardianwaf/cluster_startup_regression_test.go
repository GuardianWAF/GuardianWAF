package main

// Regression (new-series round 19): setupClusterRuntime built gossip.Config by
// hand with only 5 fields (NodeID, Addr, RaftAddr, DashboardAddr, Secret).
// gossip.New -> NewWithTransport (internal/cluster/gossip/protocol.go:105) does
// NOT apply DefaultConfig, so every timing field stayed zero (ProbeInterval,
// GossipInterval, ProbeTimeout, SuspicionTimeout, IndirectChecks, GossipFanout).
// g.Start() launches runProber and runGossip, which each call
// time.NewTicker(<interval>) (protocol.go:358 and :373). NewTicker panics on a
// non-positive interval inside unrecovered goroutines, so enabling
// cluster.enabled crashed the entire WAF process on startup — every vhost went
// down with it. The fix starts from gossip.DefaultConfig, which supplies these
// timing values, then overrides RaftAddr/DashboardAddr/Secret.

import (
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func clusterProofSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return string(b)
}

func clusterTestEngine(t *testing.T, cfg *config.Config) *engine.Engine {
	t.Helper()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

func clusterEnabledConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = "node-a"
	cfg.Cluster.BindAddr = "127.0.0.1:0"
	cfg.Cluster.GossipAddr = "127.0.0.1:0"
	cfg.Cluster.Secret = clusterProofSecret()
	return cfg
}

// Regression (new-series round 23): gossip never bootstrapped in production.
// gossip.Join is the only bootstrap API (it push-pulls with each address so the
// node learns who else exists), and NOTHING in production called it — every
// test that forms a gossip cluster called it explicitly, which is why the suite
// was green while real deployments never discovered a peer. With no bootstrap,
// membership stayed at the single self-member registered by gossip.New, and
// every discovery path was inert (RandomMember and randomPeers both exclude
// self), so dynamic peer discovery and the peersync bridge never activated.
// The fix calls g.Join with addresses derived from cfg.Cluster.Peers (Raft
// host + the cluster's gossip UDP port). This test pins that two nodes
// configured as mutual peers actually discover each other.

const (
	clusterGossipTestPort = "39461" // shared gossip UDP port, as in a real fleet
	clusterRaftPortA      = "39471"
	clusterRaftPortB      = "39472"
)

func clusterBootNode(t *testing.T, id, host, raftPort string, seeds []config.ClusterPeer) *clusterRuntime {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = id
	cfg.Cluster.BindAddr = host + ":" + raftPort
	cfg.Cluster.GossipAddr = host + ":" + clusterGossipTestPort
	cfg.Cluster.Secret = clusterProofSecret()
	cfg.Cluster.Peers = seeds
	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("setupClusterRuntime(%s): %v", id, err)
	}
	if cr == nil || cr.gossip == nil {
		t.Fatalf("node %s: no gossip node", id)
	}
	return cr
}

// A standalone node is legitimately a 1-member cluster.
func TestGossipBootstrap_StandaloneNodeSeesOnlyItself(t *testing.T) {
	n := clusterBootNode(t, "solo", "127.0.0.1", clusterRaftPortA, nil)
	t.Cleanup(func() { _ = n.Stop() })

	if got := n.gossip.MemberCount(); got != 1 {
		t.Fatalf("standalone node sees %d members, want 1", got)
	}
}

// Two nodes configured as mutual cluster.peers must discover each other. Before
// the fix neither did, because production never called gossip.Join.
func TestGossipBootstrap_TwoConfiguredPeersDiscoverEachOther(t *testing.T) {
	a := clusterBootNode(t, "node-a", "127.0.0.1", clusterRaftPortA,
		[]config.ClusterPeer{{ID: "node-b", Addr: "127.0.0.2:" + clusterRaftPortB}})
	t.Cleanup(func() { _ = a.Stop() })
	b := clusterBootNode(t, "node-b", "127.0.0.2", clusterRaftPortB,
		[]config.ClusterPeer{{ID: "node-a", Addr: "127.0.0.1:" + clusterRaftPortA}})
	t.Cleanup(func() { _ = b.Stop() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.gossip.MemberCount() > 1 && b.gossip.MemberCount() > 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if a.gossip.MemberCount() <= 1 && b.gossip.MemberCount() <= 1 {
		t.Fatalf("node-a sees %d member(s), node-b sees %d; neither discovered the other "+
			"despite being configured as mutual cluster.peers — gossip bootstrap is not happening",
			a.gossip.MemberCount(), b.gossip.MemberCount())
	}
}

// A disabled cluster is a no-op.
func TestClusterDisabledIsNoOp(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cluster.Enabled = false
	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("setupClusterRuntime(disabled): %v", err)
	}
	if cr != nil {
		t.Fatalf("disabled cluster returned a runtime: %+v", cr)
	}
}

// An enabled cluster with a valid config must start and keep gossip alive.
// Before the fix this panics the process in gossip's prober/gossip goroutines
// (time.NewTicker with a zero interval).
func TestClusterEnabledStartsGossipWithValidTiming(t *testing.T) {
	cfg := clusterEnabledConfig()
	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("setupClusterRuntime(enabled): %v", err)
	}
	if cr == nil || cr.raft == nil {
		t.Fatalf("setupClusterRuntime(enabled) returned no raft node")
	}
	if cr.gossip == nil {
		t.Fatalf("setupClusterRuntime(enabled) started no gossip node")
	}
	t.Cleanup(func() { _ = cr.Stop() })

	// With a zero interval the prober/gossip goroutines panic within
	// microseconds of Start; a valid interval keeps this window quiet.
	time.Sleep(150 * time.Millisecond)

	if got := cr.gossip.MemberCount(); got < 1 {
		t.Fatalf("gossip reports %d members after startup; a started gossip node always knows itself", got)
	}
}

// Regression (new-series round 20): the operator's cluster.peers seed list was
// wiped at startup. setupClusterRuntime called peerBridge.Sync() before
// g.Start(), when gossip had only ever seen itself (gossip.New registers only
// the local member). Bridge.Sync EXCLUDES self when building the Raft peer
// set, so it computed an EMPTY peer list, and raft.UpdatePeers is a full
// replace (raft.go:189) — discarding the seeds raft.New was just given. With
// zero peers hasQuorum counts total=1, majority=1, so the node self-elects on a
// cluster the operator configured for N. The onJoin/onLeave callbacks already
// drive Sync() on real membership changes, so the setup-time sync was not just
// harmful — it was redundant.
func TestClusterSeedPeersSurviveStartup(t *testing.T) {
	cfg := clusterEnabledConfig()
	cfg.Cluster.Peers = []config.ClusterPeer{
		{ID: "node-b", Addr: "127.0.0.1:9002"},
		{ID: "node-c", Addr: "127.0.0.1:9003"},
	}
	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("setupClusterRuntime(enabled): %v", err)
	}
	if cr == nil || cr.raft == nil {
		t.Fatalf("setupClusterRuntime(enabled) returned no raft node")
	}
	t.Cleanup(func() { _ = cr.Stop() })

	peers := cr.raft.Peers()
	if len(peers) == 0 {
		t.Fatalf("setupClusterRuntime wiped the operator's cluster.peers seed list; " +
			"gossip knows only itself when the bridge syncs, so the bridge computed an empty " +
			"peer set and UpdatePeers REPLACED the seeds. hasQuorum then counts total=1, " +
			"majority=1, so this node self-elects on a cluster configured for 3")
	}
	found := map[string]bool{}
	for _, p := range peers {
		found[p.ID] = true
	}
	for _, s := range cfg.Cluster.Peers {
		if !found[s.ID] {
			t.Fatalf("configured seed peer %q is missing from the Raft peer set %+v", s.ID, peers)
		}
	}
}

// Regression (new-series round 26): a wildcard cluster.bind_addr was accepted
// and advertised verbatim as the gossip RaftAddr. BindAddr is a BIND address
// (raft net.Listens on it, documented e.g. "0.0.0.0:7947"), but RaftAddr is
// ADVERTISED to every peer (gossip/protocol.go:134), collected by the peersync
// bridge (bridge.go:102 -> raft.Peer{Addr}), and DIALED by raft.SendRPC
// (raft.go:391, :528). A peer that learns a wildcard dials 0.0.0.0, which on
// Linux connects to ITSELF, so replication to every gossip-discovered peer
// silently targets the wrong host and the cluster never forms quorum. Unlike
// the dashboard address there is no second address to fall back to, so a
// cluster node must advertise a routable address; setupClusterRuntime now
// rejects a wildcard bind_addr, mirroring the cluster-secret length check.

// A routable bind_addr still starts and advertises the routable host.
func TestClusterRoutableBindAddrStillStarts(t *testing.T) {
	cfg := clusterEnabledConfig()
	cfg.Cluster.BindAddr = "127.0.0.1:0"
	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("routable bind_addr was rejected: %v", err)
	}
	if cr == nil || cr.gossip == nil {
		t.Fatalf("routable bind_addr returned no cluster node")
	}
	t.Cleanup(func() { _ = cr.Stop() })

	if got := cr.gossip.LocalMember().RaftAddr; !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("advertised RaftAddr %q lost the routable host", got)
	}
}

// A wildcard bind_addr must be rejected at startup, whatever the port.
func TestClusterWildcardBindAddrRejected(t *testing.T) {
	for _, bind := range []string{"0.0.0.0:0", "0.0.0.0:7947", "[::]:0", "[::]:7947"} {
		t.Run(bind, func(t *testing.T) {
			cfg := clusterEnabledConfig()
			cfg.Cluster.BindAddr = bind
			cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
			if cr != nil {
				_ = cr.Stop()
			}
			if err == nil {
				t.Fatalf("cluster.bind_addr %q was accepted; it is advertised verbatim as the "+
					"gossip RaftAddr and a peer dialing a wildcard reaches itself, so the cluster "+
					"never forms quorum", bind)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "bind_addr") {
				t.Fatalf("expected the error to name cluster.bind_addr, got: %v", err)
			}
		})
	}
}
