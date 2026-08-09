package engine

import "encoding/json"

// ClusterStore is the read-only interface that the WAF request pipeline uses
// to consult cluster-replicated state (ban lists, rules, rate counters).
//
// When clustering is disabled, the engine holds a nil ClusterStore and all
// lookups return false/zero — the pipeline falls back to its local state.
// When clustering is enabled, the clustersync.ReplicatedStore implements this
// interface and is wired into each layer via the BuildContext.
type ClusterStore interface {
	// IsBanned returns true if the IP is banned cluster-wide.
	IsBanned(ip string) bool

	// GetRule returns the rule definition for the given ID and true if it
	// exists in the cluster-replicated rule set.
	GetRule(ruleID string) (json.RawMessage, bool)

	// GetCounter returns the cluster-wide counter value for the given key
	// and window epoch. If the stored window differs, returns 0.
	GetCounter(key string, window int64) int64
}

// noopClusterStore is the default when clustering is disabled. All lookups
// return false/zero — the pipeline falls back to local state.
type noopClusterStore struct{}

func (noopClusterStore) IsBanned(string) bool                   { return false }
func (noopClusterStore) GetRule(string) (json.RawMessage, bool) { return nil, false }
func (noopClusterStore) GetCounter(string, int64) int64         { return 0 }
