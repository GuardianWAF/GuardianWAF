package clustersync

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// ErrRaftNotLeader is returned when a write is attempted on a node that is not
// the Raft leader. Callers should retry on the leader node.
var ErrRaftNotLeader = errors.New("clustersync: not raft leader")

// API provides write methods that propose commands to the Raft cluster.
// Reads are served directly from the local ReplicatedStore (no Raft round-trip).
// Writes go through the Raft leader and are applied when the log entry commits.
type API struct {
	raft  *raft.Raft
	store *ReplicatedStore
}

// NewAPI creates an API that proposes commands to the given Raft node.
// The store is the local replicated state machine that receives committed
// entries.
func NewAPI(r *raft.Raft, store *ReplicatedStore) *API {
	return &API{raft: r, store: store}
}

// Store returns the underlying ReplicatedStore for direct read access.
func (a *API) Store() *ReplicatedStore {
	return a.store
}

// propose encodes a command and submits it to the Raft log.
func (a *API) propose(cmd Command) error {
	data, err := cmd.Encode()
	if err != nil {
		return fmt.Errorf("clustersync: encode command: %w", err)
	}
	if err := a.raft.Propose(data); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return ErrRaftNotLeader
		}
		return fmt.Errorf("clustersync: propose: %w", err)
	}
	return nil
}

// ProposeBan proposes banning an IP for the given duration. The ban takes
// effect on all cluster nodes once the Raft entry commits.
func (a *API) ProposeBan(ip string, duration time.Duration) error {
	cmd, err := NewBanCommand(ip, duration)
	if err != nil {
		return fmt.Errorf("clustersync: build ban command: %w", err)
	}
	return a.propose(cmd)
}

// ProposeUnban proposes removing an IP from the ban list.
func (a *API) ProposeUnban(ip string) error {
	cmd, err := NewUnbanCommand(ip)
	if err != nil {
		return fmt.Errorf("clustersync: build unban command: %w", err)
	}
	return a.propose(cmd)
}

// ProposeSetRule proposes creating or updating a custom rule. The rule body
// is stored as opaque JSON — the WAF pipeline is responsible for interpreting it.
func (a *API) ProposeSetRule(ruleID string, rule json.RawMessage) error {
	cmd, err := NewSetRuleCommand(ruleID, rule)
	if err != nil {
		return fmt.Errorf("clustersync: build set-rule command: %w", err)
	}
	return a.propose(cmd)
}

// ProposeDeleteRule proposes removing a custom rule by ID.
func (a *API) ProposeDeleteRule(ruleID string) error {
	cmd, err := NewDeleteRuleCommand(ruleID)
	if err != nil {
		return fmt.Errorf("clustersync: build delete-rule command: %w", err)
	}
	return a.propose(cmd)
}

// ProposeIncrCounter proposes incrementing a rate-limit counter by delta within
// the given window epoch. The window allows time-bucketed counting (e.g.,
// Unix-seconds / 60 for per-minute windows).
func (a *API) ProposeIncrCounter(key string, delta int64, window int64) error {
	cmd, err := NewIncrCounterCommand(key, delta, window)
	if err != nil {
		return fmt.Errorf("clustersync: build incr-counter command: %w", err)
	}
	return a.propose(cmd)
}

// ProposeResetCounter proposes resetting a rate-limit counter to zero.
func (a *API) ProposeResetCounter(key string) error {
	cmd, err := NewResetCounterCommand(key)
	if err != nil {
		return fmt.Errorf("clustersync: build reset-counter command: %w", err)
	}
	return a.propose(cmd)
}
