package clustersync

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Regression tests: ReplicatedStore counters must be reclaimed at window-epoch
// advance. The rate limiter feeds per rule×tenant×IP×path keys into the store
// on every request (adversarial cardinality), and window rollover resets a
// key's VALUE but used to leave stale-window keys in the map forever — no
// sweep, no cap, no TTL — so s.counters grew unboundedly for the process
// lifetime on every node. sweepStaleCounters now runs at epoch advance on
// both mutation seams (hot-path IncrementCounter and Raft-replay
// applyIncrCounter), mirroring PurgeExpiredBans for the bans map. The sweep
// only removes entries whose window differs from the newest epoch, so active
// counters are never touched and a mid-window reset (rate-limit bypass) is
// impossible; the monotonic guard prevents an old-window replayed command
// from wiping newer counters.

func TestIncrementCounterSweepsStaleWindows(t *testing.T) {
	s := NewReplicatedStore()

	for i := 0; i < 500; i++ {
		s.IncrementCounter(fmt.Sprintf("rl:%d", i), 100)
	}
	if got := s.Stats().Counters; got != 500 {
		t.Fatalf("setup: expected 500 counters, got %d", got)
	}

	// Epoch advances to 200: stale-window entries must be reclaimed.
	if v := s.IncrementCounter("rl:active", 200); v != 1 {
		t.Fatalf("active counter value = %d, want 1", v)
	}
	if got := s.Stats().Counters; got != 1 {
		t.Fatalf("FAIL: %d counter entries retained after epoch advance (want 1) — stale-window keys leak", got)
	}

	// Stale-window read semantics unchanged.
	if v := s.GetCounter("rl:0", 100); v != 0 {
		t.Fatalf("stale-window counter reads %d, want 0", v)
	}
	// Active counter continues within its window.
	if v := s.IncrementCounter("rl:active", 200); v != 2 {
		t.Fatalf("active counter continued to %d, want 2", v)
	}
	// A pruned key returning in the new window starts fresh.
	if v := s.IncrementCounter("rl:0", 200); v != 1 {
		t.Fatalf("returning key value = %d, want 1", v)
	}
}

func TestApplyIncrCounterSweepsStaleWindows(t *testing.T) {
	s := NewReplicatedStore()

	apply := func(key string, delta, window int64) {
		t.Helper()
		payload, err := json.Marshal(IncrCounterPayload{Key: key, Delta: delta, Window: window})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if err := s.Apply(Command{Type: CmdIncrCounter, Payload: payload}); err != nil {
			t.Fatalf("Apply incr %s@%d: %v", key, window, err)
		}
	}

	for i := 0; i < 100; i++ {
		apply(fmt.Sprintf("raft:%d", i), 1, 300)
	}
	if got := s.Stats().Counters; got != 100 {
		t.Fatalf("setup: expected 100 counters, got %d", got)
	}

	// Raft-replay path must sweep too.
	apply("raft:active", 1, 400)
	if got := s.Stats().Counters; got != 1 {
		t.Fatalf("FAIL: %d entries retained after epoch advance via Apply (want 1)", got)
	}
	if v := s.GetCounter("raft:active", 400); v != 1 {
		t.Fatalf("active replicated counter reads %d, want 1", v)
	}
}

// An old-window replayed command must not wipe newer, live counters
// (monotonic sweep guard).
func TestOldWindowReplayDoesNotWipeActiveCounters(t *testing.T) {
	s := NewReplicatedStore()

	apply := func(key string, delta, window int64) {
		t.Helper()
		payload, err := json.Marshal(IncrCounterPayload{Key: key, Delta: delta, Window: window})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		if err := s.Apply(Command{Type: CmdIncrCounter, Payload: payload}); err != nil {
			t.Fatalf("Apply incr %s@%d: %v", key, window, err)
		}
	}

	apply("live", 3, 400)
	// Stale epoch-300 command arrives after epoch 400 is active.
	apply("stale-cmd", 5, 300)

	if v := s.GetCounter("live", 400); v != 3 {
		t.Fatalf("FAIL: old-window replay wiped the active counter (got %d, want 3)", v)
	}
}
