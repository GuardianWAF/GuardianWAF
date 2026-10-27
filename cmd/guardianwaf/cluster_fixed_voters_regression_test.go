package main

import (
	"github.com/guardianwaf/guardianwaf/internal/config"
	"testing"
)

func TestClusterRuntimeExcludesOwnConfiguredVoter(t *testing.T) {
	cfg := clusterEnabledConfig()
	cfg.Cluster.Peers = []config.ClusterPeer{
		{ID: cfg.Cluster.NodeID, Addr: cfg.Cluster.BindAddr},
		{ID: "node-b", Addr: "127.0.0.2:0"},
	}
	eng := clusterTestEngine(t, cfg)
	defer eng.Close()
	runtime, err := setupClusterRuntime(cfg, eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Stop()
	peers := runtime.raft.Peers()
	if len(peers) != 1 || peers[0].ID != "node-b" {
		t.Fatalf("configured self inflated remote voter set: %+v", peers)
	}
	runtime.bridge.Sync()
	peers = runtime.raft.Peers()
	if len(peers) != 1 || peers[0].ID != "node-b" {
		t.Fatalf("self-only gossip removed configured remote voter: %+v", peers)
	}
}
