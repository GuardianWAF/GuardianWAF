package peersync

import "github.com/guardianwaf/guardianwaf/internal/cluster/raft"

// testClusterSecret is the shared secret these tests hand to the Raft and
// gossip constructors, which now refuse to start unauthenticated.
var testClusterSecret = []byte("peersync-test-cluster-secret-0123456789ab")

// testRaftConfig returns a Raft config carrying the shared test secret. The
// transport refuses to start without one, because the replicated log carries
// IP-ban and WAF-rule mutations.
func testRaftConfig(nodeID, bindAddr string) raft.Config {
	cfg := raft.DefaultConfig(nodeID, bindAddr)
	cfg.Secret = testClusterSecret
	return cfg
}
