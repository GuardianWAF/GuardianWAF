package raft

// Regression test for the startup election-timeout contract (round
// round2-election-timeout). New() must initialize electionResetTime so the
// FIRST election also waits the randomized [ElectionTimeoutMin,
// ElectionTimeoutMax] window. Before the fix the field was zero-valued, the
// election loop computed waitDuration <= 0, and every fresh node fired
// startElection() immediately — all cluster nodes became simultaneous
// candidates at process start and the randomized tie-breaker (Raft §5.2)
// was bypassed for the first round.

import (
	"bytes"
	"testing"
	"time"
)

func TestFirstElectionRespectsRandomizedTimeout(t *testing.T) {
	cfg := DefaultConfig("n1", "127.0.0.1:0")
	cfg.Secret = bytes.Repeat([]byte("s"), 32) // transport requires a >=32-byte cluster secret
	cfg.ElectionTimeoutMin = 2 * time.Second
	cfg.ElectionTimeoutMax = 3 * time.Second

	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Stop()

	// Root-cause anchor: the reset time must be initialized at construction.
	r.mu.Lock()
	zeroReset := r.electionResetTime.IsZero()
	r.mu.Unlock()
	if zeroReset {
		t.Errorf("electionResetTime was never initialized in New() — the first election timeout fires immediately")
	}

	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// With ElectionTimeoutMin=2s the node must still be a follower 300ms
	// after Start(). Pre-fix it was a candidate (even leader with zero
	// peers) within microseconds.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if role := r.Role(); role != RoleFollower {
			t.Fatalf("fresh node became %s within 300ms of Start() despite ElectionTimeoutMin=2s — the startup election timeout is not gated by the randomized window", role)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
