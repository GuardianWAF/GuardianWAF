package config

import "testing"

// hasFieldError reports whether ve carries an error for the given field.
func hasFieldError(ve *ValidationError, field string) bool {
	for _, fe := range ve.Errors {
		if fe.Field == field {
			return true
		}
	}
	return false
}

// TestClusterSecretMinLenMatchesTransports pins the duplication of the minimum
// secret length. internal/config deliberately does not import the cluster
// packages, so the constant is repeated here; if raft.MinSecretLen or
// gossip.MinSecretLen changes, this must change with it or the config layer
// will accept a secret the transports then reject at startup.
func TestClusterSecretMinLenMatchesTransports(t *testing.T) {
	// Mirrors raft.MinSecretLen and gossip.MinSecretLen.
	const transportMinSecretLen = 32

	if ClusterSecretMinLen != transportMinSecretLen {
		t.Fatalf("ClusterSecretMinLen = %d, but the cluster transports require %d",
			ClusterSecretMinLen, transportMinSecretLen)
	}
}

// TestValidateCluster_RequiresSecret pins the fail-closed behaviour: enabling
// clustering without a secret must be a validation error, not a warning.
func TestValidateCluster_RequiresSecret(t *testing.T) {
	base := func() *ClusterConfig {
		return &ClusterConfig{
			Enabled:    true,
			NodeID:     "node-a",
			BindAddr:   "0.0.0.0:7947",
			GossipAddr: "0.0.0.0:7946",
			Peers:      []ClusterPeer{{ID: "node-b", Addr: "10.0.0.2:7947"}},
		}
	}

	t.Run("missing secret is rejected", func(t *testing.T) {
		ve := &ValidationError{}
		validateCluster(base(), ve)
		if !hasFieldError(ve, "cluster.secret") {
			t.Fatal("cluster.enabled without cluster.secret must be a validation error")
		}
	})

	t.Run("short secret is rejected", func(t *testing.T) {
		cfg := base()
		cfg.Secret = "too-short"
		ve := &ValidationError{}
		validateCluster(cfg, ve)
		if !hasFieldError(ve, "cluster.secret") {
			t.Fatal("a secret shorter than the minimum must be a validation error")
		}
	})

	t.Run("adequate secret is accepted", func(t *testing.T) {
		cfg := base()
		cfg.Secret = "0123456789abcdef0123456789abcdef"
		ve := &ValidationError{}
		validateCluster(cfg, ve)
		if hasFieldError(ve, "cluster.secret") {
			t.Fatalf("a %d-byte secret must be accepted", len(cfg.Secret))
		}
	})

	t.Run("disabled cluster needs no secret", func(t *testing.T) {
		cfg := base()
		cfg.Enabled = false
		ve := &ValidationError{}
		validateCluster(cfg, ve)
		if hasFieldError(ve, "cluster.secret") {
			t.Fatal("a disabled cluster must not require a secret")
		}
	})
}
