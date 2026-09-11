package raft

// Regression tests for the WAL record-size bound contract (round
// wal-size-bound). The bounds must be IDENTICAL on both sides of the file:
// AppendRecord/Compact enforce maxWALRecordSize at write time, and
// countRecords/decodeWALRecord (Replay) enforce the same constant at read
// time. Before the fix, writes were unbounded while Replay rejected payloads
// over 16 MB — a legitimately-written >16 MB snapshot record (exactly what
// Compact produces for a large log) was treated as corruption on restart and
// truncated away, resetting the node's Raft term/votedFor (safety violation)
// and discarding every record after it.

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func walRegFileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// walRegSnapshotRecord builds a WALSnapshot record with count entries of the
// given command size (payload ≈ count × (20 + cmdSize) + 15 bytes).
func walRegSnapshotRecord(term uint64, count, cmdSize int) WALRecord {
	entries := make([]LogEntry, 0, count)
	for i := 1; i <= count; i++ {
		entries = append(entries, LogEntry{
			Term:    term,
			Index:   uint64(i),
			Command: bytes.Repeat([]byte("x"), cmdSize),
		})
	}
	return WALRecord{Type: WALSnapshot, Term: term, VotedFor: "n1", Entries: entries}
}

// TestWALRoundTripsLargeSnapshotRecord pins the proof scenario: a >16 MB
// (but within-bound) snapshot record written by this node must survive a
// close/reopen/replay cycle losslessly — never treated as corruption.
func TestWALRoundTripsLargeSnapshotRecord(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	ps := NewPersistentState()
	ps.SetWAL(wal)

	ps.SetCurrentTerm(5)
	ps.SetVotedFor("n1")
	ps.Log().Append(5, []byte("genesis"))

	// 1200 × 14020 ≈ 16.8 MB payload: above the old 16 MB replay bound,
	// below the 32 MB write/count bound.
	if err := wal.AppendRecord(walRegSnapshotRecord(7, 1200, 14000)); err != nil {
		t.Fatalf("AppendRecord: %v", err)
	}
	sizeBefore := walRegFileSize(t, wal.path)

	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wal2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	ps2 := NewPersistentState()
	ps2.SetWAL(wal2)
	if err := wal2.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if got := ps2.CurrentTerm(); got != 7 {
		t.Errorf("currentTerm = %d, want 7 — the large snapshot record was discarded", got)
	}
	if ps2.VotedFor() != "n1" {
		t.Errorf("votedFor = %q, want %q", ps2.VotedFor(), "n1")
	}
	if got := ps2.Log().Len(); got != 1200 {
		t.Errorf("log length = %d, want 1200", got)
	}
	if sizeAfter := walRegFileSize(t, wal2.path); sizeAfter < sizeBefore-1024 {
		t.Errorf("WAL shrank from %d to %d bytes — Replay truncated a legitimate record", sizeBefore, sizeAfter)
	}
}

// TestWALRejectsOversizedAppendRecord pins the write-time bound: a record
// above maxWALRecordSize is refused instead of being written and silently
// doomed to truncation on the next restart.
func TestWALRejectsOversizedAppendRecord(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	if err := wal.AppendRecord(WALRecord{Type: WALState, Term: 1, VotedFor: "n1"}); err != nil {
		t.Fatalf("baseline append: %v", err)
	}
	sizeBefore := walRegFileSize(t, wal.path)

	// 2400 × 14020 ≈ 33.6 MB payload — just above maxWALRecordSize.
	oversized := walRegSnapshotRecord(2, 2400, 14000)
	if err := wal.AppendRecord(oversized); err == nil {
		t.Fatal("AppendRecord of a >32MB record succeeded — the write-time bound is not enforced")
	} else if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error shape: %v", err)
	}

	if got := wal.RecordCount(); got != 1 {
		t.Errorf("RecordCount = %d, want 1 (the refused record must not be counted)", got)
	}
	if sizeAfter := walRegFileSize(t, wal.path); sizeAfter != sizeBefore {
		t.Errorf("WAL size changed on refused append: %d -> %d", sizeBefore, sizeAfter)
	}

	// The WAL still replays its intact prior state.
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wal2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	ps2 := NewPersistentState()
	ps2.SetWAL(wal2)
	if err := wal2.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := ps2.CurrentTerm(); got != 1 {
		t.Errorf("currentTerm = %d, want 1 — prior state lost", got)
	}
}

// TestWALCompactRefusesOversizedSnapshot pins the compaction bound: Compact
// must refuse to write a snapshot record the replay path would reject, and
// must leave the live WAL (and its state) untouched.
func TestWALCompactRefusesOversizedSnapshot(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	defer wal.Close()

	if err := wal.AppendRecord(WALRecord{Type: WALState, Term: 4, VotedFor: "n1"}); err != nil {
		t.Fatalf("baseline append: %v", err)
	}
	sizeBefore := walRegFileSize(t, wal.path)

	// A log whose snapshot payload exceeds maxWALRecordSize (no WAL attached,
	// so building the log is cheap).
	ps := NewPersistentState()
	for i := 0; i < 2400; i++ {
		ps.Log().Append(3, bytes.Repeat([]byte("y"), 14000))
	}

	if err := wal.Compact(ps); err == nil {
		t.Fatal("Compact of a >32MB snapshot succeeded — the compaction bound is not enforced")
	} else if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("unexpected error shape: %v", err)
	}

	// The live WAL is untouched and no temp file leaked.
	if sizeAfter := walRegFileSize(t, wal.path); sizeAfter != sizeBefore {
		t.Errorf("WAL size changed on refused compaction: %d -> %d", sizeBefore, sizeAfter)
	}
	if _, err := os.Stat(wal.path + ".compact.tmp"); !os.IsNotExist(err) {
		t.Errorf("compaction temp file leaked: %v", err)
	}

	// The state still replays from the intact WAL.
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wal2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	ps2 := NewPersistentState()
	ps2.SetWAL(wal2)
	if err := wal2.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := ps2.CurrentTerm(); got != 4 {
		t.Errorf("currentTerm = %d, want 4 — prior state lost after refused compaction", got)
	}
}

// TestWALSmallRecordRoundTrip is the control: ordinary records still
// round-trip through close/reopen/replay.
func TestWALSmallRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	if err := wal.AppendRecord(WALRecord{Type: WALState, Term: 9, VotedFor: "n2"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 9, Index: 1, Command: []byte("cmd")}}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wal2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	ps2 := NewPersistentState()
	ps2.SetWAL(wal2)
	if err := wal2.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := ps2.CurrentTerm(); got != 9 {
		t.Errorf("currentTerm = %d, want 9", got)
	}
	if ps2.VotedFor() != "n2" {
		t.Errorf("votedFor = %q, want %q", ps2.VotedFor(), "n2")
	}
	if got := ps2.Log().Len(); got != 1 {
		t.Errorf("log length = %d, want 1", got)
	}
}
