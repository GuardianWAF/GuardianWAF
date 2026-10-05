package config

import (
	"reflect"
	"testing"
	"time"
)

func TestDeepCopyClusterPreservesAllFields(t *testing.T) {
	in := &ClusterConfig{Enabled: true, NodeID: "node", BindAddr: "localhost:7000", GossipAddr: "localhost:7001", Peers: []ClusterPeer{{ID: "peer", Addr: "localhost:7002"}}, ElectionTimeoutMin: time.Second, ElectionTimeoutMax: 2 * time.Second, HeartbeatInterval: time.Millisecond, DataDir: "local-data", SnapshotThreshold: 12, Secret: "fixture-only"}
	out := in.DeepCopy()
	if !reflect.DeepEqual(in, out) || in == out {
		t.Fatal("cluster copy lost fields or returned original")
	}
	configCopy := (&Config{Cluster: *in}).DeepCopy()
	if !reflect.DeepEqual(configCopy.Cluster, *in) {
		t.Fatal("root configuration copy lost cluster fields")
	}
	in.Peers[0].ID = "changed"
	if out.Peers[0].ID != "peer" || configCopy.Cluster.Peers[0].ID != "peer" {
		t.Fatal("peers share backing storage")
	}
	for _, peers := range [][]ClusterPeer{nil, {}} {
		input := &ClusterConfig{Peers: peers}
		if !reflect.DeepEqual(input, input.DeepCopy()) {
			t.Fatal("nil/empty peers changed shape")
		}
	}
	if (*ClusterConfig)(nil).DeepCopy() != nil {
		t.Fatal("nil receiver")
	}
}
