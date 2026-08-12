package clustersync

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// BanEntry represents a single banned IP.
type BanEntry struct {
	IP        string
	BannedAt  time.Time
	ExpiresAt time.Time // zero value = permanent
}

// IsExpired returns true if the ban has a finite duration and has passed.
func (b BanEntry) IsExpired(now time.Time) bool {
	if b.ExpiresAt.IsZero() {
		return false
	}
	return now.After(b.ExpiresAt)
}

// CounterEntry holds a rate-limit counter value for a specific epoch window.
type CounterEntry struct {
	Value  int64
	Window int64
}

// ReplicatedStore is the in-memory state machine that holds all replicated
// WAF state: the ban list, custom rules, and rate-limit counters.
//
// All methods are safe for concurrent access. The store is designed to be
// driven by Raft log entries (via Apply) but read directly by the WAF
// request pipeline with no Raft round-trip.
type ReplicatedStore struct {
	mu       sync.RWMutex
	bans     map[string]BanEntry        // key = IP
	rules    map[string]json.RawMessage // key = rule_id
	counters map[string]CounterEntry
}

// NewReplicatedStore creates an empty store.
func NewReplicatedStore() *ReplicatedStore {
	return &ReplicatedStore{
		bans:     make(map[string]BanEntry),
		rules:    make(map[string]json.RawMessage),
		counters: make(map[string]CounterEntry),
	}
}

// --- Ban list reads ---

// IsBanned returns true if the IP is in the ban list and not expired.
func (s *ReplicatedStore) IsBanned(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.bans[ip]
	if !ok {
		return false
	}
	return !entry.IsExpired(time.Now())
}

// BannedIPs returns a snapshot of all non-expired banned IPs.
func (s *ReplicatedStore) BannedIPs() []BanEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	result := make([]BanEntry, 0, len(s.bans))
	for _, b := range s.bans {
		if !b.IsExpired(now) {
			result = append(result, b)
		}
	}
	return result
}

// --- Rule reads ---

// GetRule returns the rule definition for the given ID, or nil if not found.
func (s *ReplicatedStore) GetRule(ruleID string) (json.RawMessage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[ruleID]
	return r, ok
}

// AllRules returns a snapshot of all custom rules.
func (s *ReplicatedStore) AllRules() map[string]json.RawMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]json.RawMessage, len(s.rules))
	for k, v := range s.rules {
		result[k] = v
	}
	return result
}

// --- Counter reads ---

// GetCounter returns the counter value for the given key.
// If the stored counter's window differs from the requested window, returns 0
// (the old window's data is stale).
func (s *ReplicatedStore) GetCounter(key string, window int64) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.counters[key]
	if !ok || c.Window != window {
		return 0
	}
	return c.Value
}

// IncrementCounter atomically increments the counter for the given key and
// window under the write lock, and returns the post-increment value. If the
// stored counter's window differs from the requested window, the counter is
// reset to 1 for the new window (rollover). This eliminates the read-then-check
// TOCTOU race that GetCounter + separate comparison introduces.
//
// Note: this operates on the local replica only. In a multi-node Raft cluster,
// each node increments its own replica independently — the aggregate rate is
// approximate (N nodes can each see Limit requests). For exact cluster-wide
// enforcement, use the Raft-replicated IncrCounter command via API.ProposeIncrCounter.
// The local atomic increment is the correct choice for the hot request path
// because it avoids a Raft round-trip per request.
func (s *ReplicatedStore) IncrementCounter(key string, window int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.counters[key]
	if existing.Window != window {
		// New window: reset counter to 1.
		s.counters[key] = CounterEntry{
			Value:  1,
			Window: window,
		}
		return 1
	}
	existing.Value++
	s.counters[key] = existing
	return existing.Value
}

// --- State mutations (called by Apply, not directly by clients) ---

func (s *ReplicatedStore) applyBanIP(payload BanIPPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := BanEntry{
		IP:       payload.IP,
		BannedAt: time.Now(),
	}
	if payload.Duration > 0 {
		entry.ExpiresAt = entry.BannedAt.Add(payload.Duration)
	}
	s.bans[payload.IP] = entry
}

func (s *ReplicatedStore) applyUnbanIP(payload UnbanIPPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bans, payload.IP)
}

func (s *ReplicatedStore) applySetRule(payload SetRulePayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[payload.RuleID] = payload.Rule
}

func (s *ReplicatedStore) applyDeleteRule(payload DeleteRulePayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, payload.RuleID)
}

func (s *ReplicatedStore) applyIncrCounter(payload IncrCounterPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.counters[payload.Key]
	if existing.Window != payload.Window {
		// New window: reset counter to delta.
		s.counters[payload.Key] = CounterEntry{
			Value:  payload.Delta,
			Window: payload.Window,
		}
		return
	}
	existing.Value += payload.Delta
	s.counters[payload.Key] = existing
}

func (s *ReplicatedStore) applyResetCounter(payload ResetCounterPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counters, payload.Key)
}

// Apply dispatches a decoded command to the appropriate mutation method.
// This is called by the RaftStateMachine adapter (state_machine.go) and is
// also used directly in tests.
func (s *ReplicatedStore) Apply(cmd Command) error {
	switch cmd.Type {
	case CmdBanIP:
		var p BanIPPayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode ban payload: %w", err)
		}
		s.applyBanIP(p)
	case CmdUnbanIP:
		var p UnbanIPPayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode unban payload: %w", err)
		}
		s.applyUnbanIP(p)
	case CmdSetRule:
		var p SetRulePayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode set-rule payload: %w", err)
		}
		s.applySetRule(p)
	case CmdDeleteRule:
		var p DeleteRulePayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode delete-rule payload: %w", err)
		}
		s.applyDeleteRule(p)
	case CmdIncrCounter:
		var p IncrCounterPayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode incr-counter payload: %w", err)
		}
		s.applyIncrCounter(p)
	case CmdResetCounter:
		var p ResetCounterPayload
		if err := cmd.DecodePayload(&p); err != nil {
			return fmt.Errorf("clustersync: decode reset-counter payload: %w", err)
		}
		s.applyResetCounter(p)
	default:
		return fmt.Errorf("clustersync: unknown command type %d", cmd.Type)
	}
	return nil
}

// PurgeExpiredBans removes all expired ban entries. This is safe to call
// periodically (e.g., every 60 seconds) to reclaim memory.
func (s *ReplicatedStore) PurgeExpiredBans(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for ip, entry := range s.bans {
		if entry.IsExpired(now) {
			delete(s.bans, ip)
			n++
		}
	}
	return n
}

// Stats returns summary statistics for observability.
func (s *ReplicatedStore) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StoreStats{
		Bans:     len(s.bans),
		Rules:    len(s.rules),
		Counters: len(s.counters),
	}
}

// StoreStats is a point-in-time snapshot of store sizes.
type StoreStats struct {
	Bans     int
	Rules    int
	Counters int
}

// String formats StoreStats for logging.
func (s StoreStats) String() string {
	return fmt.Sprintf("bans=%d rules=%d counters=%d", s.Bans, s.Rules, s.Counters)
}
