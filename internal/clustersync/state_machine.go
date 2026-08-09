package clustersync

import (
	"log/slog"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// StoreStateMachine adapts a ReplicatedStore to the raft.StateMachine
// interface. Each committed log entry is decoded as a clustersync Command and
// dispatched to the corresponding store mutation.
type StoreStateMachine struct {
	store *ReplicatedStore
	log   *slog.Logger
}

// NewStoreStateMachine wraps store so it can be passed to raft.New.
// If logger is nil, slog.Default() is used.
func NewStoreStateMachine(store *ReplicatedStore, logger *slog.Logger) *StoreStateMachine {
	if logger == nil {
		logger = slog.Default()
	}
	return &StoreStateMachine{store: store, log: logger}
}

// Store returns the underlying ReplicatedStore for direct read access.
func (sm *StoreStateMachine) Store() *ReplicatedStore { return sm.store }

// Apply implements raft.StateMachine. It decodes the committed log entry's
// command and applies it to the store. Errors are logged but never panic — a
// malformed command is a data-integrity issue, not a reason to crash the node.
func (sm *StoreStateMachine) Apply(entry raft.LogEntry) {
	cmd, err := DecodeCommand(entry.Command)
	if err != nil {
		sm.log.Error("clustersync: failed to decode command",
			"index", entry.Index, "term", entry.Term, "err", err)
		return
	}
	sm.store.Apply(cmd)
}
