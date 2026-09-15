package raft

import "testing"

// Compaction-straddling persists: LogStore.Append writes the entry to memory
// under l.mu and persists it to the WAL after releasing l.mu (holding l.mu
// across the persist would deadlock compactLocked, whose gather takes l.mu.RLock
// under w.mu). An append whose memory-write lands before a compaction gather but
// whose persist fires after the snapshot swap must NOT be written again — the
// snapshot record already contains it (the observed 22001-vs-22000
// TestWALCompactionCrashWindowKeepsCommittedEntries flake; recovery also dedups
// by index, this pins the write-side skip).

func TestWAL_StraddlingPersistSkipped(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	ps := NewPersistentState()
	ps.SetWAL(wal)

	ps.Log().Append(1, []byte("e1"))
	ps.Log().Append(1, []byte("e2"))
	if err := ps.Snapshot(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if wal.snapLastIndex != 2 {
		t.Fatalf("snapLastIndex = %d, want 2", wal.snapLastIndex)
	}

	// The straddling persist: index 2 is already covered by the snapshot.
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Term: 1, Entry: LogEntry{Term: 1, Index: 2, Command: []byte("e2")}}); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}
	// A post-boundary record must still persist.
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Term: 1, Entry: LogEntry{Term: 1, Index: 3, Command: []byte("e3")}}); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}

	ps2 := NewPersistentState()
	if err := wal.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := ps2.Log().Len(); got != 3 {
		t.Fatalf("replayed log = %d entries, want 3 (snapshot e1,e2 + e3)", got)
	}
	if e, _ := ps2.Log().Get(3); string(e.Command) != "e3" {
		t.Errorf("entry 3 = %q, want e3", string(e.Command))
	}
}

func TestWAL_TruncateShrinksSnapshotBoundary(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()
	ps := NewPersistentState()
	ps.SetWAL(wal)

	ps.Log().Append(1, []byte("e1"))
	ps.Log().Append(1, []byte("e2"))
	if err := ps.Snapshot(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Truncate from 2: log = [e1]; the boundary must shrink to 1 so the
	// next append (which reuses index 2) is persisted, not skipped.
	if !ps.Log().TruncateFrom(2) {
		t.Fatal("TruncateFrom(2): unexpected no-op")
	}
	if wal.snapLastIndex != 1 {
		t.Fatalf("snapLastIndex after truncate = %d, want 1", wal.snapLastIndex)
	}
	if idx := ps.Log().Append(1, []byte("e2b")); idx != 2 {
		t.Fatalf("append index = %d, want 2", idx)
	}

	ps2 := NewPersistentState()
	if err := wal.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if ps2.Log().Len() != 2 {
		t.Fatalf("replayed log = %d entries, want 2 (post-truncate append must not be skipped)", ps2.Log().Len())
	}
	if e, _ := ps2.Log().Get(2); string(e.Command) != "e2b" {
		t.Errorf("entry 2 = %q, want e2b (post-truncation append lost — boundary not shrunk)", string(e.Command))
	}
}
