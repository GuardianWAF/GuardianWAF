package main

// Regression (new-series round 8): the cluster.gossip_addr was accepted with a
// bind wildcard, and — like cluster.bind_addr before it — it is an address
// ADVERTISED to peers, not only a listen address.
//
// GossipAddr is a BIND address (the UDP transport listens on it,
// gossip/transport.go:34 net.ListenUDP), but the member record publishes the
// transport's BOUND address (gossip/protocol.go:137 Addr: tr.LocalAddr()), and
// peers dial that published address when probing (gossip/protocol.go:412
// directProbe(target.Addr)). A wildcard ("0.0.0.0:7946" — the documented
// example) is not a dialable destination: a peer that dials 0.0.0.0 reaches
// ITSELF on Linux, so the remote node is never confirmed alive, the peersync
// bridge drops it from the alive set (bridge.go:82), and raft.UpdatePeers —
// a FULL REPLACE — then wipes the operator's cluster.peers seed. The cluster
// silently collapses to a single node that still reports itself healthy.
//
// setupClusterRuntime already refuses a wildcard cluster.bind_addr for exactly
// this reason; the sibling gossip address now gets the same guard.
//
// These tests drive the real startup path (setupClusterRuntime) rather than
// gossip.Join, so a production bootstrap difference cannot hide behind a
// hand-formed membership.

import (
	"strings"
	"testing"
)

// A wildcard gossip_addr must be rejected at startup, whatever the port.
func TestClusterWildcardGossipAddrRejected(t *testing.T) {
	for _, gossip := range []string{"0.0.0.0:0", "0.0.0.0:7946", "[::]:0", "[::]:7946"} {
		t.Run(gossip, func(t *testing.T) {
			cfg := clusterEnabledConfig()
			cfg.Cluster.BindAddr = "127.0.0.1:0"
			cfg.Cluster.GossipAddr = gossip
			cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
			if cr != nil {
				t.Cleanup(func() { _ = cr.Stop() })
			}
			if err == nil {
				t.Fatalf("cluster.gossip_addr %q was accepted; it is advertised verbatim as the "+
					"gossip member address and a peer dialing a wildcard reaches itself, so the "+
					"remote node is never confirmed alive and the cluster silently collapses to a "+
					"single node", gossip)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "gossip_addr") {
				t.Fatalf("expected the error to name cluster.gossip_addr, got: %v", err)
			}
		})
	}
}

// A routable gossip_addr still starts and advertises the routable host, so
// peers can dial this node.
func TestClusterRoutableGossipAddrStillStarts(t *testing.T) {
	cfg := clusterEnabledConfig()
	cfg.Cluster.BindAddr = "127.0.0.1:0"
	cfg.Cluster.GossipAddr = "127.0.0.1:0"

	cr, err := setupClusterRuntime(cfg, clusterTestEngine(t, cfg), nil)
	if err != nil {
		t.Fatalf("routable gossip_addr was rejected: %v", err)
	}
	if cr == nil || cr.gossip == nil {
		t.Fatal("routable gossip_addr returned no cluster node")
	}
	t.Cleanup(func() { _ = cr.Stop() })

	// The advertised address is the transport's bound address — it must carry
	// the routable host, not a wildcard.
	got := cr.gossip.LocalMember().Addr
	if !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("advertised gossip address %q lost the routable host", got)
	}
	if strings.HasPrefix(got, "0.0.0.0") || strings.HasPrefix(got, "[::]") {
		t.Fatalf("advertised gossip address %q is a bind wildcard and cannot be dialed", got)
	}
}
