package raft

import (
	"runtime"
	"testing"
	"time"
)

// Regression: a Config with zero election timeouts (built without the config
// package's defaults) made electionLoop start elections back to back, each
// spawning RequestVote goroutines against a zero-timeout transport. Goroutines
// and memory grew without bound (gigabytes within seconds in cmd tests).
func TestZeroTimingsDoNotCauseElectionStorm(t *testing.T) {
	before := runtime.NumGoroutine()
	r, err := New(Config{
		NodeID:   "n1",
		BindAddr: "127.0.0.1:0",
		Secret:   []byte("0123456789abcdef0123456789abcdef"),
		// An unreachable peer keeps the node a candidate forever.
		Peers: []Peer{{ID: "n2", Addr: "127.0.0.1:1"}, {ID: "n3", Addr: "127.0.0.1:2"}},
	}, &noopStateMachine{})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	term, goroutines := r.CurrentTerm(), runtime.NumGoroutine()-before
	r.Stop()

	// Default timings allow at most ~1s/150ms ≈ 7 elections per second.
	if term > 10 {
		t.Fatalf("term reached %d within 1s: elections are not rate limited", term)
	}
	if goroutines > 50 {
		t.Fatalf("%d extra goroutines after 1s: RequestVote goroutines are piling up", goroutines)
	}
}

func TestNormalizeTimings(t *testing.T) {
	cases := []struct{ in, want Config }{
		{Config{}, Config{ElectionTimeoutMin: 150 * time.Millisecond, ElectionTimeoutMax: 300 * time.Millisecond, HeartbeatInterval: 50 * time.Millisecond}},
		{Config{ElectionTimeoutMin: time.Second}, Config{ElectionTimeoutMin: time.Second, ElectionTimeoutMax: 2 * time.Second, HeartbeatInterval: time.Second / 3}},
		{Config{ElectionTimeoutMin: 500 * time.Millisecond, ElectionTimeoutMax: time.Second, HeartbeatInterval: 100 * time.Millisecond},
			Config{ElectionTimeoutMin: 500 * time.Millisecond, ElectionTimeoutMax: time.Second, HeartbeatInterval: 100 * time.Millisecond}},
	}
	for _, tc := range cases {
		got := normalizeTimings(tc.in)
		if got.ElectionTimeoutMin != tc.want.ElectionTimeoutMin || got.ElectionTimeoutMax != tc.want.ElectionTimeoutMax || got.HeartbeatInterval != tc.want.HeartbeatInterval {
			t.Errorf("normalizeTimings(%+v) = %v/%v/%v", tc.in, got.ElectionTimeoutMin, got.ElectionTimeoutMax, got.HeartbeatInterval)
		}
	}
}
