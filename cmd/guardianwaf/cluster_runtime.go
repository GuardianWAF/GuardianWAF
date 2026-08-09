package main

import (
	"fmt"

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
//   - PeerSyncBridge (feeds gossip membership changes into Raft UpdatePeers)
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
	if cfg.Cluster.GossipAddr == "" {
		return nil, fmt.Errorf("cluster.enabled is true but cluster.gossip_addr is empty")
	}

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
	}

	// Convert config peers to raft peers (initial seed list).
	for _, p := range cfg.Cluster.Peers {
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
	// feeds alive/suspect transitions into Raft.UpdatePeers so the consensus
	// layer adjusts its peer list without a restart.
	var g *gossip.Gossip
	var peerBridge *peersync.Bridge
	if cfg.Cluster.GossipAddr != "" {
		gossipCfg := gossip.Config{
			NodeID:        cfg.Cluster.NodeID,
			Addr:          cfg.Cluster.GossipAddr,
			RaftAddr:      cfg.Cluster.BindAddr,
			DashboardAddr: "http://" + cfg.Dashboard.Listen,
		}

		g, err = gossip.New(gossipCfg)
		if err != nil {
			r.Stop()
			return nil, fmt.Errorf("create gossip node: %w", err)
		}

		peerBridge = peersync.NewBridge(g, r, nil)
		onJoin, onLeave := peerBridge.Callbacks()
		g.SetCallbacks(onJoin, onLeave)
		peerBridge.Sync()

		if err := g.Start(); err != nil {
			g.Stop()
			r.Stop()
			return nil, fmt.Errorf("start gossip node: %w", err)
		}

		// Bootstrap: contact known peers so gossip discovers them.
		// The YAML peers list contains Raft TCP addresses; gossip uses
		// its own UDP addresses. For single-bootstrap deployments, nodes
		// discover each other via UDP multicast/seed lists at the gossip
		// layer. Here we just log — gossip probes will find peers once
		// their UDP addresses are known.
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
