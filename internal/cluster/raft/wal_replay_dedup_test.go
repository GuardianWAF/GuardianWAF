package raft

import (
	"fmt"
	"path/filepath"
	"testing"
)

// Regression (round 83): a WAL record whose in-memory append landed before a
// compaction gather but whose persist fired after the snapshot swap was
// written to the new file even though the snapshot already contained that
// entry — replay applied it twice, so the reopened log carried one more
// entry than was committed (the observed 22001-vs-22000 crash-window gate
// failure). appendNoPersist now skips records whose index is already
// present: the snapshot is authoritative up to its last entry's index, and
// LogStore indices are dense (Append assigns len+1).
func TestWALReplayDeduplicatesCompactionStraddler(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	const snapshotN = 200
	entries := make([]LogEntry, 0, snapshotN)
	for i := 1; i <= snapshotN; i++ {
		entries = append(entries, LogEntry{Term: 1, Index: uint64(i), Command: []byte(fmt.Sprintf("e-%d", i))})
	}

	// The exact post-race WAL: the snapshot gathered through the straddler
	// (entry 200), then the straddler's queued persist fired on the new file,
	// then the remaining burst entries continued.
	if err := wal.AppendRecord(WALRecord{Type: WALSnapshot, Term: 1, Entries: entries}); err != nil {
		t.Fatalf("snapshot record: %v", err)
	}
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: snapshotN, Command: []byte("straddler")}}); err != nil {
		t.Fatalf("straddler record: %v", err)
	}
	for i := snapshotN + 1; i <= snapshotN+5; i++ {
		if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: uint64(i), Command: []byte(fmt.Sprintf("post-%d", i))}}); err != nil {
			t.Fatalf("post record %d: %v", i, err)
		}
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Crash-reopen: replay must reconstruct exactly snapshotN+5 unique
	// entries — the straddler is already contained in the snapshot.
	ps := NewPersistentState()
	wal2, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	if err := wal2.Replay(ps); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	const want = snapshotN + 5
	if got := ps.Log().Len(); got != want {
		t.Fatalf("replay produced %d entries, want %d — a compaction-straddling record was applied twice (duplicate index %d)", got, want, snapshotN)
	}
	seen := make(map[uint64]int)
	for _, e := range ps.Log().AllEntries() {
		seen[e.Index]++
	}
	for idx, n := range seen {
		if n != 1 {
			t.Fatalf("index %d appears %d times after replay — the duplicate was not deduplicated", idx, n)
		}
	}
	if last := ps.Log().LastIndex(); last != want {
		t.Fatalf("LastIndex = %d, want %d", last, want)
	}
}

// The dedup guard's boundary on the truncate path: after a truncation to
// index T-1, a record at index T is a legitimate re-append and must NOT be
// skipped, while a second record at index T is a duplicate and must be.
func TestWALReplayDedupWithTruncateInterleave(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}

	const snapshotN = 200
	entries := make([]LogEntry, 0, snapshotN)
	for i := 1; i <= snapshotN; i++ {
		entries = append(entries, LogEntry{Term: 1, Index: uint64(i), Command: []byte(fmt.Sprintf("e-%d", i))})
	}
	if err := wal.AppendRecord(WALRecord{Type: WALSnapshot, Term: 1, Entries: entries}); err != nil {
		t.Fatalf("snapshot record: %v", err)
	}
	for i := snapshotN + 1; i <= 220; i++ {
		if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: uint64(i), Command: []byte(fmt.Sprintf("b-%d", i))}}); err != nil {
			t.Fatalf("burst record %d: %v", i, err)
		}
	}
	if err := wal.AppendRecord(WALRecord{Type: WALTruncate, Index: 150}); err != nil {
		t.Fatalf("truncate record: %v", err)
	}
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: 150, Command: []byte("re-appended-150")}}); err != nil {
		t.Fatalf("re-append record: %v", err)
	}
	if err := wal.AppendRecord(WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: 150, Command: []byte("duplicate-150")}}); err != nil {
		t.Fatalf("duplicate record: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ps := NewPersistentState()
	wal2, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	if err := wal2.Replay(ps); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if got := ps.Log().Len(); got != 150 {
		t.Fatalf("FAIL: replay produced %d entries, want 150 (truncate to 150 + one re-append, duplicate skipped)", got)
	}
	if last := ps.Log().LastIndex(); last != 150 {
		t.Fatalf("FAIL: LastIndex = %d, want 150", last)
	}
	e, ok := ps.Log().Get(150)
	if !ok || string(e.Command) != "re-appended-150" {
		t.Fatalf("FAIL: index 150 = %+v, want the re-appended command (the legitimate re-append must not be deduplicated)", e)
	}
	seen := make(map[uint64]int)
	for _, en := range ps.Log().AllEntries() {
		seen[en.Index]++
	}
	for idx, n := range seen {
		if n != 1 {
			t.Fatalf("FAIL: index %d appears %d times after replay — the duplicate was not deduplicated", idx, n)
		}
	}
}
