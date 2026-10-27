package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/peersync"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
	"github.com/guardianwaf/guardianwaf/internal/clustersync"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// clusterRuntime holds the cluster subsystem resources that need lifecycle
// management (start/stop) alongside the main GuardianWAF process.
type clusterRuntime struct {
	gossip *gossip.Gossip
	bridge *peersync.Bridge
	raft   *raft.Raft
	store  *clustersync.ReplicatedStore
	sm     *clustersync.StoreStateMachine
	api    *clustersync.API
}

// setupClusterRuntime initializes the cluster subsystem if clustering is
// enabled in the configuration. When disabled, returns nil and the engine
// falls back to single-node operation with local-only state.
//
// The cluster subsystem consists of:
//   - Gossip membership (UDP-based node discovery + failure detection)
//   - PeerSyncBridge (observes gossip liveness without changing Raft voters)
//   - Raft consensus node (leader election + log replication)
//   - Replicated state store (ban lists, rules, rate counters)
//   - StoreStateMachine adapter (feeds committed Raft entries to the store)
//   - API (write methods that propose commands to the Raft leader)
func setupClusterRuntime(cfg *config.Config, eng *engine.Engine, bctx *layerregistry.BuildContext) (*clusterRuntime, error) {
	if cfg == nil || !cfg.Cluster.Enabled {
		return nil, nil
	}

	if cfg.Cluster.NodeID == "" {
		return nil, fmt.Errorf("cluster.enabled is true but cluster.node_id is empty")
	}
	if cfg.Cluster.BindAddr == "" {
		return nil, fmt.Errorf("cluster.enabled is true but cluster.bind_addr is empty")
	}
	// These addresses are announced in gossip and used to identify this node.
	// A wildcard is a local bind target, not a remotely dialable destination.
	if isUnspecifiedBindHost(cfg.Cluster.BindAddr) {
		return nil, fmt.Errorf(
			"cluster.enabled is true but cluster.bind_addr host is a wildcard (%s); "+
				"it is advertised to peers as the Raft address and dialing a wildcard "+
				"reaches the dialing host, not this node — set cluster.bind_addr to "+
				"this node's routable IP (e.g. 10.0.0.2:7947)", cfg.Cluster.BindAddr)
	}
	if cfg.Cluster.GossipAddr == "" {
		return nil, fmt.Errorf("cluster.enabled is true but cluster.gossip_addr is empty")
	}
	// Gossip publishes its bound address to peers; wildcard binds would make
	// probes reach the dialing node instead of the remote member.
	if isUnspecifiedBindHost(cfg.Cluster.GossipAddr) {
		return nil, fmt.Errorf(
			"cluster.enabled is true but cluster.gossip_addr host is a wildcard (%s); "+
				"it is advertised to peers as this node's gossip address and dialing a wildcard "+
				"reaches the dialing host, not this node — set cluster.gossip_addr to "+
				"this node's routable IP (e.g. 10.0.0.2:7946)", cfg.Cluster.GossipAddr)
	}
	// Fail closed. Peers authenticate each other with this secret alone, and
	// the replicated log carries ban and rule mutations, so starting a cluster
	// without one would expose fleet-wide enforcement control on an open port.
	if len(cfg.Cluster.Secret) < raft.MinSecretLen {
		return nil, fmt.Errorf(
			"cluster.enabled is true but cluster.secret is shorter than %d bytes; "+
				"set an identical high-entropy secret on every node", raft.MinSecretLen)
	}
	clusterSecret := []byte(cfg.Cluster.Secret)

	store := clustersync.NewReplicatedStore()
	sm := clustersync.NewStoreStateMachine(store, nil)

	raftCfg := raft.Config{
		NodeID:             cfg.Cluster.NodeID,
		BindAddr:           cfg.Cluster.BindAddr,
		ElectionTimeoutMin: cfg.Cluster.ElectionTimeoutMin,
		ElectionTimeoutMax: cfg.Cluster.ElectionTimeoutMax,
		HeartbeatInterval:  cfg.Cluster.HeartbeatInterval,
		DataDir:            cfg.Cluster.DataDir,
		SnapshotThreshold:  cfg.Cluster.SnapshotThreshold,
		Secret:             clusterSecret,
	}

	// Configure the fixed voting set; Raft counts the local node separately.
	for _, p := range cfg.Cluster.Peers {
		if p.ID == cfg.Cluster.NodeID {
			continue // the chart lists the complete set; Raft counts self separately
		}
		raftCfg.Peers = append(raftCfg.Peers, raft.Peer{
			ID:   p.ID,
			Addr: p.Addr,
		})
	}

	r, err := raft.New(raftCfg, sm)
	if err != nil {
		return nil, fmt.Errorf("create raft node: %w", err)
	}

	api := clustersync.NewAPI(r, store)

	if startErr := r.Start(); startErr != nil {
		r.Stop()
		return nil, fmt.Errorf("start raft node: %w", startErr)
	}

	// Wire the store into the engine and layers so the request pipeline
	// consults cluster-replicated state alongside local state.
	eng.SetClusterStore(store)
	eng.PropagateClusterStore()
	if bctx != nil {
		bctx.ClusterStore = store
	}

	// Start gossip membership for dynamic peer discovery.
	// The gossip layer discovers nodes via UDP probes; the PeerSyncBridge
	// observes alive/suspect transitions without modifying the fixed voting set.
	// Failure detection is not a consensus membership change.
	var g *gossip.Gossip
	var peerBridge *peersync.Bridge
	if cfg.Cluster.GossipAddr != "" {
		// Start from DefaultConfig so the timing fields (ProbeInterval,
		// GossipInterval, ProbeTimeout, SuspicionTimeout, IndirectChecks,
		// GossipFanout) get the package's own production values. A hand-rolled
		// Config literal left them all zero, and gossip.Start launches runProber
		// and runGossip, which each call time.NewTicker(<interval>) — a
		// non-positive interval panics inside those unrecovered goroutines, so
		// enabling cluster.enabled crashed the whole process at startup.
		gossipCfg := gossip.DefaultConfig(cfg.Cluster.NodeID, cfg.Cluster.GossipAddr)
		gossipCfg.RaftAddr = cfg.Cluster.BindAddr
		gossipCfg.DashboardAddr = "http://" + clusterDashboardAdvertiseAddr(cfg.Dashboard.Listen, cfg.Cluster.BindAddr)
		gossipCfg.Secret = clusterSecret

		g, err = gossip.New(gossipCfg)
		if err != nil {
			r.Stop()
			return nil, fmt.Errorf("create gossip node: %w", err)
		}

		peerBridge = peersync.NewBridge(g, r, nil)
		onJoin, onLeave := peerBridge.Callbacks()
		g.SetCallbacks(onJoin, onLeave)
		// Gossip observations must never replace the configured Raft voters.

		if err := g.Start(); err != nil {
			g.Stop()
			r.Stop()
			return nil, fmt.Errorf("start gossip node: %w", err)
		}

		// Bootstrap gossip membership. gossip.Join is the ONLY bootstrap API:
		// it push-pulls with each address so this node learns who else exists.
		// Without it, membership stays at the single self-member registered by
		// gossip.New, and every discovery path is inert — RandomMember and
		// randomPeers both exclude self, so the prober has no target and
		// dissemination has no recipient. The peersync bridge would then never
		// activate in a real deployment. Nothing else calls Join: every test
		// that forms a gossip cluster calls it explicitly, which is why the
		// suite was green while production discovery was dead.
		if seeds := gossipBootstrapAddrs(cfg.Cluster.Peers, cfg.Cluster.GossipAddr); len(seeds) > 0 {
			if n := g.Join(seeds); n > 0 {
				eng.Logs.Infof("Gossip bootstrap: contacted %d/%d seed gossip addresses",
					n, len(seeds))
			}
		}
		eng.Logs.Infof("Gossip membership started: node=%s gossip=%s raft=%s",
			cfg.Cluster.NodeID, cfg.Cluster.GossipAddr, cfg.Cluster.BindAddr)
	}

	eng.Logs.Infof("Cluster mode enabled: node=%s bind=%s peers=%d", cfg.Cluster.NodeID, cfg.Cluster.BindAddr, len(raftCfg.Peers))

	return &clusterRuntime{
		gossip: g,
		bridge: peerBridge,
		raft:   r,
		store:  store,
		sm:     sm,
		api:    api,
	}, nil
}

// isUnspecifiedBindHost reports whether a bind address's host is a wildcard /
// unspecified address (0.0.0.0, ::, or empty) — i.e. a listen target that is
// not a valid dialable destination. Such an address must never be advertised to
// cluster peers. IPv6 brackets are handled by net.SplitHostPort, so "[::]:port"
// yields the bare "::" host.
func isUnspecifiedBindHost(bindAddr string) bool {
	host, _, err := net.SplitHostPort(bindAddr)
	if err != nil {
		// Not a host:port pair; fall back to the whole string so a bare
		// "0.0.0.0" is still caught.
		host = bindAddr
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}

// gossipBootstrapAddrs derives gossip bootstrap addresses from the configured
// cluster peers. cfg.Cluster.Peers carries each peer's RAFT TCP address (that
// is what the seed list feeds raft.New), but gossip rides its own UDP port, so
// the port is swapped for this node's configured gossip port while the host —
// the part operators actually configure to be routable — is preserved.
//
// When the gossip address has no parsable port there is nothing to derive, and
// the peer addresses are returned unchanged rather than guessed at.
func gossipBootstrapAddrs(peers []config.ClusterPeer, gossipAddr string) []string {
	if len(peers) == 0 {
		return nil
	}
	_, gossipPort, err := net.SplitHostPort(gossipAddr)
	if err != nil || gossipPort == "" {
		out := make([]string, 0, len(peers))
		for _, p := range peers {
			out = append(out, p.Addr)
		}
		return out
	}
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		host, _, err := net.SplitHostPort(p.Addr)
		if err != nil || host == "" {
			// Not a host:port pair (e.g. a bare host); pass it through and let
			// gossip report the failure rather than dropping the peer silently.
			out = append(out, p.Addr)
			continue
		}
		out = append(out, net.JoinHostPort(host, gossipPort))
	}
	return out
}

// clusterDashboardAdvertiseAddr returns the host:port other cluster nodes
// should use to reach this node's dashboard. The dashboard listen address is
// a BIND address and is typically a wildcard (0.0.0.0/::), which peers cannot
// dial — a follower's 307 leader-redirect would send clients to their own
// machine, looping until the client's redirect cap. A wildcard listen
// therefore falls back to the Raft bind address's host (operators configure a
// real, routable IP there); an explicit listen host is kept as-is. When both
// are wildcards no reachable host is derivable and the listen is returned
// unchanged rather than invented.
func clusterDashboardAdvertiseAddr(dashboardListen, raftBind string) string {
	host, port, err := net.SplitHostPort(dashboardListen)
	if err != nil {
		return dashboardListen
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return net.JoinHostPort(host, port)
	}
	rHost, _, rErr := net.SplitHostPort(raftBind)
	if rErr != nil || rHost == "" || rHost == "0.0.0.0" || rHost == "::" {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(rHost, port)
}

// shutdownCluster gracefully stops the cluster subsystem.
func shutdownCluster(cr *clusterRuntime) error {
	if cr == nil {
		return nil
	}
	if cr.gossip != nil {
		cr.gossip.Stop()
	}
	if cr.raft != nil {
		cr.raft.Stop()
	}
	return nil
}

// Stop gracefully shuts down the cluster subsystem.
func (cr *clusterRuntime) Stop() error {
	return shutdownCluster(cr)
}
