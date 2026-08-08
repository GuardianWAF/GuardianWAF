// Package cluster provides distributed coordination primitives for
// GuardianWAF multi-node deployments.
//
// The gossip sub-package implements SWIM-style membership protocol for
// failure detection and cluster topology awareness. Future sub-packages
// will add Raft consensus and cross-node state replication.
package cluster
