package config

import (
	"strings"
	"testing"
	"time"
)

// validClusterConfig returns a ClusterConfig with all required fields populated,
// suitable as a baseline for tests that then remove one field at a time.
func validClusterConfig() ClusterConfig {
	return ClusterConfig{
		Enabled:    true,
		NodeID:     "node-1",
		BindAddr:   "0.0.0.0:7947",
		GossipAddr: "0.0.0.0:7946",
		Peers:      []ClusterPeer{{ID: "node-2", Addr: "10.0.0.2:7947"}},
		// Peer authentication is mandatory when clustering is enabled; the
		// Raft log replicates ban and rule mutations.
		Secret:             "0123456789abcdef0123456789abcdef",
		ElectionTimeoutMin: 150 * time.Millisecond,
		ElectionTimeoutMax: 300 * time.Millisecond,
		HeartbeatInterval:  50 * time.Millisecond,
	}
}

func TestValidateCluster_Disabled(t *testing.T) {
	cfg := validClusterConfig()
	cfg.Enabled = false
	// Even with empty required fields, disabled cluster should not error.
	cfg.NodeID = ""
	cfg.BindAddr = ""
	cfg.GossipAddr = ""
	cfg.Peers = nil

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if ve.HasErrors() {
		t.Fatalf("disabled cluster should not produce errors, got: %v", ve)
	}
}

func TestValidateCluster_ValidSinglePeer(t *testing.T) {
	cfg := validClusterConfig()

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if ve.HasErrors() {
		t.Fatalf("valid cluster config should not produce errors, got: %v", ve)
	}
}

func TestValidateCluster_MissingNodeID(t *testing.T) {
	cfg := validClusterConfig()
	cfg.NodeID = ""

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for missing node_id")
	}
	if !containsField(ve, "cluster.node_id") {
		t.Errorf("expected field cluster.node_id in errors, got: %v", ve)
	}
}

func TestValidateCluster_MissingBindAddr(t *testing.T) {
	cfg := validClusterConfig()
	cfg.BindAddr = ""

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for missing bind_addr")
	}
	if !containsField(ve, "cluster.bind_addr") {
		t.Errorf("expected field cluster.bind_addr in errors, got: %v", ve)
	}
}

func TestValidateCluster_MissingGossipAddr(t *testing.T) {
	cfg := validClusterConfig()
	cfg.GossipAddr = ""

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for missing gossip_addr")
	}
	if !containsField(ve, "cluster.gossip_addr") {
		t.Errorf("expected field cluster.gossip_addr in errors, got: %v", ve)
	}
}

func TestValidateCluster_MissingPeers(t *testing.T) {
	cfg := validClusterConfig()
	cfg.Peers = nil

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for empty peers")
	}
	if !containsField(ve, "cluster.peers") {
		t.Errorf("expected field cluster.peers in errors, got: %v", ve)
	}
}

func TestValidateCluster_EmptyPeersSlice(t *testing.T) {
	cfg := validClusterConfig()
	cfg.Peers = []ClusterPeer{}

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for empty peers slice")
	}
	if !containsField(ve, "cluster.peers") {
		t.Errorf("expected field cluster.peers in errors, got: %v", ve)
	}
}

func TestValidateCluster_AllMissing(t *testing.T) {
	cfg := ClusterConfig{Enabled: true}

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected multiple errors for empty enabled cluster")
	}

	// Should report at least 4 errors: node_id, bind_addr, gossip_addr, peers.
	wantFields := []string{"cluster.node_id", "cluster.bind_addr", "cluster.gossip_addr", "cluster.peers"}
	for _, field := range wantFields {
		if !containsField(ve, field) {
			t.Errorf("expected field %s in errors, got: %v", field, ve)
		}
	}
}

func TestValidateCluster_DuplicatePeerIDs(t *testing.T) {
	cfg := validClusterConfig()
	cfg.Peers = []ClusterPeer{
		{ID: "node-2", Addr: "10.0.0.2:7947"},
		{ID: "node-2", Addr: "10.0.0.3:7947"},
	}

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error for duplicate peer IDs")
	}
	if !containsFieldSubstring(ve, "duplicate") {
		t.Errorf("expected duplicate peer error, got: %v", ve)
	}
}

func TestValidateCluster_PeerMissingFields(t *testing.T) {
	cfg := validClusterConfig()
	cfg.Peers = []ClusterPeer{
		{ID: "", Addr: ""},
	}

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected errors for peer with empty fields")
	}
	if !containsField(ve, "cluster.peers[0].id") {
		t.Errorf("expected field cluster.peers[0].id in errors, got: %v", ve)
	}
	if !containsField(ve, "cluster.peers[0].addr") {
		t.Errorf("expected field cluster.peers[0].addr in errors, got: %v", ve)
	}
}

func TestValidateCluster_ElectionTimeoutReversed(t *testing.T) {
	cfg := validClusterConfig()
	cfg.ElectionTimeoutMin = 500 * time.Millisecond
	cfg.ElectionTimeoutMax = 100 * time.Millisecond

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error when election_timeout_min >= election_timeout_max")
	}
	if !containsField(ve, "cluster.election_timeout_min") {
		t.Errorf("expected field cluster.election_timeout_min in errors, got: %v", ve)
	}
}

func TestValidateCluster_HeartbeatTooHigh(t *testing.T) {
	cfg := validClusterConfig()
	cfg.HeartbeatInterval = 200 * time.Millisecond
	cfg.ElectionTimeoutMin = 150 * time.Millisecond

	ve := &ValidationError{}
	validateCluster(&cfg, ve)
	if !ve.HasErrors() {
		t.Fatal("expected error when heartbeat >= election_timeout_min")
	}
	if !containsField(ve, "cluster.heartbeat_interval") {
		t.Errorf("expected field cluster.heartbeat_interval in errors, got: %v", ve)
	}
}

func TestValidateCluster_ThroughFullValidate(t *testing.T) {
	// Verify that the top-level Validate() wires validateCluster correctly.
	cfg := DefaultConfig()
	cfg.Cluster = validClusterConfig()

	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate should pass for valid cluster config, got: %v", err)
	}

	// Now break it.
	cfg.Cluster.BindAddr = ""
	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate should fail when cluster.bind_addr is empty")
	}
	if !strings.Contains(err.Error(), "cluster.bind_addr") {
		t.Errorf("error should mention cluster.bind_addr, got: %v", err)
	}
}

// --- helpers ---

func containsField(ve *ValidationError, field string) bool {
	for _, fe := range ve.Errors {
		if fe.Field == field {
			return true
		}
	}
	return false
}

func containsFieldSubstring(ve *ValidationError, substr string) bool {
	for _, fe := range ve.Errors {
		if strings.Contains(fe.Message, substr) {
			return true
		}
	}
	return false
}
