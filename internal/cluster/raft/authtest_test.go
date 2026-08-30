package raft

// testSecret is the cluster secret used across this package's tests. Raft
// transports now refuse to start without one (see auth.go), because the
// replicated log carries IP-ban and WAF-rule mutations.
var testSecret = []byte("raft-test-cluster-secret-0123456789abcdef")
