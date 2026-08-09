package raft

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWAL_CompactionReducesRecords verifies that Compact() writes a single
// snapshot record that replaces all prior incremental records.
func TestWAL_CompactionReducesRecords(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer w.Close()

	// Append 50 state + log records.
	for i := 0; i < 25; i++ {
		if err := w.AppendRecord(WALRecord{
			Type:     WALState,
			Term:     uint64(i + 1),
			VotedFor: "node-a",
		}); err != nil {
			t.Fatalf("AppendRecord state %d: %v", i, err)
		}
		if err := w.AppendRecord(WALRecord{
			Type: WALLog,
			Entry: LogEntry{
				Term:    uint64(i + 1),
				Index:   uint64(i + 1),
				Command: []byte("cmd"),
			},
		}); err != nil {
			t.Fatalf("AppendRecord log %d: %v", i, err)
		}
	}

	if rc := w.RecordCount(); rc != 50 {
		t.Fatalf("RecordCount = %d, want 50", rc)
	}

	// Compact using the PersistentState as the snapshot source.
	ps := NewPersistentState()
	ps.SetWAL(w)
	// Populate the state with entries so the snapshot has content.
	for i := 0; i < 25; i++ {
		ps.log.appendNoPersist(LogEntry{
			Term:    uint64(i + 1),
			Index:   uint64(i + 1),
			Command: []byte("cmd"),
		})
	}
	ps.setTermNoPersist(25, "node-a")

	if err := w.Compact(ps); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	if rc := w.RecordCount(); rc != 1 {
		t.Fatalf("after compaction RecordCount = %d, want 1", rc)
	}
}

// TestWAL_ShouldCompact verifies the threshold check.
func TestWAL_ShouldCompact(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer w.Close()

	// Empty WAL should not compact.
	if w.ShouldCompact(100) {
		t.Error("ShouldCompact(100) = true, want false for empty WAL")
	}

	// Add 50 records.
	for i := 0; i < 50; i++ {
		if err := w.AppendRecord(WALRecord{Type: WALState, Term: 1}); err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
	}

	// Below threshold.
	if w.ShouldCompact(100) {
		t.Error("ShouldCompact(100) = true with 50 records, want false")
	}
	// At threshold.
	if !w.ShouldCompact(50) {
		t.Error("ShouldCompact(50) = false with 50 records, want true")
	}
	// Threshold 0 = disabled.
	if w.ShouldCompact(0) {
		t.Error("ShouldCompact(0) = true, want false (disabled)")
	}
}

// TestWAL_ReplayAfterCompaction verifies that a compacted WAL replays into
// the exact same state as before compaction.
func TestWAL_ReplayAfterCompaction(t *testing.T) {
	dir := t.TempDir()

	// Phase 1: Write state, compact, close.
	{
		w, err := OpenWAL(dir)
		if err != nil {
			t.Fatalf("OpenWAL: %v", err)
		}
		ps := NewPersistentState()
		ps.SetWAL(w)
		ps.setTermNoPersist(7, "node-x")
		for i := 1; i <= 5; i++ {
			ps.Log().appendNoPersist(LogEntry{
				Term:    7,
				Index:   uint64(i),
				Command: []byte("entry"),
			})
		}
		if err := w.Compact(ps); err != nil {
			t.Fatalf("Compact: %v", err)
		}
		w.Close()
	}

	// Phase 2: Reopen, replay, verify state is intact.
	{
		w, err := OpenWAL(dir)
		if err != nil {
			t.Fatalf("OpenWAL replay: %v", err)
		}
		defer w.Close()

		ps := NewPersistentState()
		if err := w.Replay(ps); err != nil {
			t.Fatalf("Replay: %v", err)
		}

		if ps.CurrentTerm() != 7 {
			t.Errorf("term = %d, want 7", ps.CurrentTerm())
		}
		if ps.VotedFor() != "node-x" {
			t.Errorf("votedFor = %q, want %q", ps.VotedFor(), "node-x")
		}
		if got := ps.Log().Len(); got != 5 {
			t.Errorf("log length = %d, want 5", got)
		}
		for i := 0; i < 5; i++ {
			e, ok := ps.Log().Get(uint64(i + 1))
			if !ok {
				t.Errorf("entry %d missing", i+1)
				continue
			}
			if e.Term != 7 {
				t.Errorf("entry %d term = %d, want 7", i+1, e.Term)
			}
		}
	}
}

// TestWAL_CompactFileRotation verifies the WAL file is atomically rotated
// during compaction — the old file is replaced, not appended to.
func TestWAL_CompactFileRotation(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "raft.wal")

	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	// Write 100 records.
	for i := 0; i < 100; i++ {
		if err := w.AppendRecord(WALRecord{Type: WALState, Term: 1}); err != nil {
			t.Fatalf("AppendRecord %d: %v", i, err)
		}
	}

	// File should be large (100 records).
	before, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}

	// Compact.
	ps := NewPersistentState()
	ps.SetWAL(w)
	ps.setTermNoPersist(1, "")
	if err := w.Compact(ps); err != nil {
		t.Fatalf("Compact: %v", err)
	}

	// File should be much smaller (1 snapshot record).
	after, err := os.Stat(walPath)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}

	if after.Size() >= before.Size() {
		t.Errorf("WAL not smaller after compaction: before=%d after=%d",
			before.Size(), after.Size())
	}

	w.Close()

	// Verify the compacted WAL is still readable.
	w2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL after compaction: %v", err)
	}
	defer w2.Close()

	if rc := w2.RecordCount(); rc != 1 {
		t.Errorf("RecordCount after reopen = %d, want 1", rc)
	}
}
