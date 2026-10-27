package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Regression: the Raft timing defaults were set on the removed waf.cluster
// block, so the top-level cluster block that cluster_runtime reads loaded
// with zero election timeouts and heartbeat. raft.New received zeros and its
// election loop started elections back to back. A config that omits the
// timing fields must get the documented defaults (docs/clustering.md).
func TestClusterTimingDefaultsApplyToTopLevelCluster(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	yaml := "cluster:\n" +
		"  enabled: true\n" +
		"  node_id: node-a\n" +
		"  bind_addr: 127.0.0.1:7947\n" +
		"  gossip_addr: 127.0.0.1:7946\n" +
		"  secret: 0123456789abcdef0123456789abcdef\n" +
		"  peers:\n" +
		"    - id: node-b\n" +
		"      addr: 127.0.0.2:7947\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Cluster
	if c.ElectionTimeoutMin != 2*time.Second || c.ElectionTimeoutMax != 4*time.Second || c.HeartbeatInterval != 50*time.Millisecond {
		t.Fatalf("cluster timings = %v/%v/%v, want 2s/4s/50ms", c.ElectionTimeoutMin, c.ElectionTimeoutMax, c.HeartbeatInterval)
	}
	ve := &ValidationError{}
	validateCluster(&cfg.Cluster, ve)
	if len(ve.Errors) > 0 {
		t.Fatalf("defaults fail cluster validation: %v", ve.Errors)
	}
}
