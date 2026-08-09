// Package clustersync provides the replicated state store that sits on top of
// the Raft consensus layer (internal/cluster/raft). It implements the
// StateMachine interface, decoding commands from committed Raft log entries
// and applying them to an in-memory store of ban lists, custom rules, and rate
// counters.
//
// The store is the single source of truth for cluster-wide state. WAF request
// processing reads from it synchronously (no Raft round-trip on the hot path);
// writes are proposed to the Raft leader and applied when the log entry
// commits.
package clustersync
