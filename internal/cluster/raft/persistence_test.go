package raft

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRaft_PersistenceSurvivesRestart creates a Raft node with a DataDir,
// mutates its state, stops it, creates a new node with the same DataDir,
// and verifies the state was recovered from the WAL.
func TestRaft_PersistenceSurvivesRestart(t *testing.T) {
	dataDir := t.TempDir()

	cfg := Config{
		NodeID:             "persist-test",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 2 * time.Second,
		ElectionTimeoutMax: 4 * time.Second,
		HeartbeatInterval:  100 * time.Millisecond,
		DataDir:            dataDir,
	}

	// Phase 1: Create node, mutate state, stop it.
	sm := &noopStateMachine{}
	r1, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create r1: %v", err)
	}

	// Mutate persistent state directly.
	r1.persist.SetCurrentTerm(7)
	r1.persist.SetVotedFor("node-x")

	// Append some log entries.
	r1.persist.Log().Append(1, []byte("entry-1"))
	r1.persist.Log().Append(1, []byte("entry-2"))
	r1.persist.Log().Append(1, []byte("entry-3"))

	// Verify state before stop.
	if r1.persist.CurrentTerm() != 7 {
		t.Fatalf("term before stop = %d, want 7", r1.persist.CurrentTerm())
	}
	if r1.persist.VotedFor() != "node-x" {
		t.Fatalf("votedFor before stop = %q, want %q", r1.persist.VotedFor(), "node-x")
	}
	if r1.persist.Log().Len() != 3 {
		t.Fatalf("log len before stop = %d, want 3", r1.persist.Log().Len())
	}

	r1.Stop()

	// Phase 2: Create a new node with the same DataDir.
	r2, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create r2: %v", err)
	}
	defer r2.Stop()

	// Verify state was recovered.
	if r2.persist.CurrentTerm() != 7 {
		t.Errorf("term after restart = %d, want 7", r2.persist.CurrentTerm())
	}
	if r2.persist.VotedFor() != "node-x" {
		t.Errorf("votedFor after restart = %q, want %q", r2.persist.VotedFor(), "node-x")
	}
	if r2.persist.Log().Len() != 3 {
		t.Errorf("log len after restart = %d, want 3", r2.persist.Log().Len())
	}

	// Verify log content.
	e1, ok := r2.persist.Log().Get(1)
	if !ok || string(e1.Command) != "entry-1" {
		t.Errorf("entry 1 after restart = %q, ok=%v", e1.Command, ok)
	}
	e3, ok := r2.persist.Log().Get(3)
	if !ok || string(e3.Command) != "entry-3" {
		t.Errorf("entry 3 after restart = %q, ok=%v", e3.Command, ok)
	}
}

// TestRaft_PersistenceTruncateAfterRestart verifies that a log truncation
// persists across restarts. This is critical for Raft correctness: a node
// must not re-apply entries that were truncated.
func TestRaft_PersistenceTruncateAfterRestart(t *testing.T) {
	dataDir := t.TempDir()

	cfg := Config{
		NodeID:             "trunc-test",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 2 * time.Second,
		ElectionTimeoutMax: 4 * time.Second,
		HeartbeatInterval:  100 * time.Millisecond,
		DataDir:            dataDir,
	}

	sm := &noopStateMachine{}
	r1, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create r1: %v", err)
	}

	// Append 5 entries.
	for i := 0; i < 5; i++ {
		r1.persist.Log().Append(1, []byte("entry"))
	}

	// Truncate from index 3 (removes entries 3, 4, 5).
	if !r1.persist.Log().TruncateFrom(3) {
		t.Fatal("TruncateFrom(3) returned false")
	}

	if r1.persist.Log().Len() != 2 {
		t.Fatalf("log len after truncate = %d, want 2", r1.persist.Log().Len())
	}

	r1.Stop()

	// Restart — verify truncation persisted.
	r2, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create r2: %v", err)
	}
	defer r2.Stop()

	if r2.persist.Log().Len() != 2 {
		t.Errorf("log len after restart = %d, want 2 (truncation not persisted)", r2.persist.Log().Len())
	}

	// Entries 3+ should not exist.
	if _, ok := r2.persist.Log().Get(3); ok {
		t.Error("entry 3 should not exist after truncation + restart")
	}
}

// TestRaft_PersistenceDisabledByDefault verifies that when DataDir is empty,
// the Raft node works without any disk persistence (backward compatibility).
func TestRaft_PersistenceDisabledByDefault(t *testing.T) {
	cfg := Config{
		NodeID:             "no-persist",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 2 * time.Second,
		ElectionTimeoutMax: 4 * time.Second,
		HeartbeatInterval:  100 * time.Millisecond,
		// DataDir intentionally empty
	}

	sm := &noopStateMachine{}
	r, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer r.Stop()

	// Mutations should work without error.
	r.persist.SetCurrentTerm(5)
	r.persist.SetVotedFor("test")
	r.persist.Log().Append(1, []byte("test"))

	if r.persist.CurrentTerm() != 5 {
		t.Errorf("term = %d, want 5", r.persist.CurrentTerm())
	}
	if r.persist.VotedFor() != "test" {
		t.Errorf("votedFor = %q, want test", r.persist.VotedFor())
	}
	if r.persist.Log().Len() != 1 {
		t.Errorf("log len = %d, want 1", r.persist.Log().Len())
	}
}

// TestRaft_WALEmptyDirRecover verifies that a node can start with an empty
// DataDir (no WAL file yet) and create one on first write.
func TestRaft_WALEmptyDirRecover(t *testing.T) {
	dataDir := t.TempDir()

	// DataDir exists but has no WAL file.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("read dataDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty dir, got %d entries", len(entries))
	}

	cfg := Config{
		NodeID:             "empty-dir-test",
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 2 * time.Second,
		ElectionTimeoutMax: 4 * time.Second,
		HeartbeatInterval:  100 * time.Millisecond,
		DataDir:            dataDir,
	}

	sm := &noopStateMachine{}
	r, err := New(cfg, sm)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer r.Stop()

	// Write something.
	r.persist.SetCurrentTerm(1)
	r.persist.Log().Append(1, []byte("first"))

	// WAL file should exist.
	walPath := filepath.Join(dataDir, "raft-wal.log")
	if _, err := os.Stat(walPath); err != nil {
		t.Errorf("WAL file not created: %v", err)
	}
}

// noopStateMachine is a minimal StateMachine for persistence tests.
type noopStateMachine struct{}

func (s *noopStateMachine) Apply(entry LogEntry) {}
