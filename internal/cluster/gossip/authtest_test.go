package gossip

// testSecret is the cluster secret used across this package's tests. Gossip
// nodes now refuse to start without one (see auth.go), because a member
// discovered over gossip is promoted into the Raft peer set.
var testSecret = []byte("gossip-test-cluster-secret-0123456789abcd")
