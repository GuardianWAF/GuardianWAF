package clustersync

// testClusterSecret is the shared secret every Raft node in these tests uses.
// Peers authenticate each frame with it; a transport cannot start without one.
var testClusterSecret = []byte("clustersync-test-secret-0123456789abcdef")
