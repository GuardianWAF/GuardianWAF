package raft

import (
	"fmt"
	"path/filepath"
	"testing"
)

// Round 85 fresh-eyes proofs over the WAL replay paths that the round-83
// dedup fix did not pin: term/vote continuity across snapshot/state
// interleavings, truncate-to-empty + rebuild, multi-snapshot files, and
// multi-straddler duplicates. Each test constructs the WAL through the
// exported API, closes it (crash), reopens, replays, and asserts the
// reconstructed state.

// replayFile is the crash-reopen helper: append records, close (crash),
// reopen, replay into a fresh PersistentState.
func replayFile(t *testing.T, dir string, records []WALRecord) *PersistentState {
	t.Helper()
	wal, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	for i, rec := range records {
		if err := wal.AppendRecord(rec); err != nil {
			t.Fatalf("record %d (%d): %v", i, rec.Type, err)
		}
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wal2, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = wal2.Close() })

	ps := NewPersistentState()
	if err := wal2.Replay(ps); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return ps
}

func rangeEntries(from, to uint64) []LogEntry {
	entries := make([]LogEntry, 0, to-from+1)
	for i := from; i <= to; i++ {
		entries = append(entries, LogEntry{Term: 1, Index: i, Command: []byte(fmt.Sprintf("e-%d", i))})
	}
	return entries
}

func logRecords(from, to uint64) []WALRecord {
	records := make([]WALRecord, 0, to-from+1)
	for i := from; i <= to; i++ {
		records = append(records, WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: i, Command: []byte(fmt.Sprintf("e-%d", i))}})
	}
	return records
}

func assertNoDuplicateIndices(t *testing.T, ps *PersistentState) {
	t.Helper()
	seen := make(map[uint64]int)
	for _, e := range ps.Log().AllEntries() {
		seen[e.Index]++
	}
	for idx, n := range seen {
		if n != 1 {
			t.Fatalf("FAIL: index %d appears %d times after replay", idx, n)
		}
	}
}

// T1: term/vote continuity — the LAST state-bearing record (snapshot or
// state) wins, across an interleaving of both.
func TestRound85ReplayTermVoteContinuity(t *testing.T) {
	ps := replayFile(t, t.TempDir(), []WALRecord{
		{Type: WALState, Term: 2, VotedFor: "a"},
		{Type: WALSnapshot, Term: 2, VotedFor: "a", Entries: rangeEntries(1, 3)},
		{Type: WALState, Term: 5, VotedFor: "b"},
		{Type: WALLog, Entry: LogEntry{Term: 5, Index: 4}},
		{Type: WALLog, Entry: LogEntry{Term: 5, Index: 5}},
	})

	if got := ps.CurrentTerm(); got != 5 {
		t.Fatalf("FAIL: CurrentTerm = %d, want 5 (the last state-bearing record wins)", got)
	}
	if got := ps.VotedFor(); got != "b" {
		t.Fatalf("FAIL: VotedFor = %q, want %q", got, "b")
	}
	if ps.Log().Len() != 5 {
		t.Fatalf("FAIL: log has %d entries, want 5", ps.Log().Len())
	}
	assertNoDuplicateIndices(t, ps)
}

// T2: truncate-to-empty + rebuild — after a truncation to empty, fresh
// records restarting at index 1 must append (the dedup guard must not treat
// index 1 as already-present), and a trailing duplicate must be skipped.
func TestRound85ReplayTruncateToEmptyRebuild(t *testing.T) {
	ps := replayFile(t, t.TempDir(), []WALRecord{
		{Type: WALLog, Entry: LogEntry{Term: 1, Index: 1, Command: []byte("old-1")}},
		{Type: WALLog, Entry: LogEntry{Term: 1, Index: 2, Command: []byte("old-2")}},
		{Type: WALTruncate, Index: 1}, // truncate to empty
		{Type: WALLog, Entry: LogEntry{Term: 2, Index: 1, Command: []byte("new-1")}},
		{Type: WALLog, Entry: LogEntry{Term: 2, Index: 2, Command: []byte("new-2")}},
		{Type: WALLog, Entry: LogEntry{Term: 2, Index: 2, Command: []byte("dup-2")}}, // straddler-style duplicate
	})

	if got := ps.Log().Len(); got != 2 {
		t.Fatalf("FAIL: log has %d entries, want 2 (rebuild after truncate-to-empty, duplicate skipped)", got)
	}
	e, ok := ps.Log().Get(1)
	if !ok || string(e.Command) != "new-1" {
		t.Fatalf("FAIL: index 1 = %+v, want the post-truncate rebuild entry", e)
	}
	e, ok = ps.Log().Get(2)
	if !ok || string(e.Command) != "new-2" {
		t.Fatalf("FAIL: index 2 = %+v, want new-2 (the duplicate must be skipped)", e)
	}
	assertNoDuplicateIndices(t, ps)
}

// T3: a file containing successive snapshot epochs replays to the last
// epoch's state.
func TestRound85ReplayMultipleSnapshots(t *testing.T) {
	ps := replayFile(t, t.TempDir(), []WALRecord{
		{Type: WALSnapshot, Term: 1, VotedFor: "a", Entries: rangeEntries(1, 5)},
		{Type: WALSnapshot, Term: 1, VotedFor: "a", Entries: rangeEntries(1, 7)},
		{Type: WALSnapshot, Term: 1, VotedFor: "a", Entries: rangeEntries(1, 8)},
	})

	if got := ps.Log().Len(); got != 8 {
		t.Fatalf("FAIL: log has %d entries, want 8 (the last snapshot epoch wins)", got)
	}
	if last := ps.Log().LastIndex(); last != 8 {
		t.Fatalf("FAIL: LastIndex = %d, want 8", last)
	}
	assertNoDuplicateIndices(t, ps)
}

// T4: MULTIPLE compaction-straddler duplicates in one file — the round-83
// dedup must skip every one of them, not just the first.
func TestRound85ReplayMultipleStraddlerDuplicates(t *testing.T) {
	records := []WALRecord{
		{Type: WALSnapshot, Term: 1, VotedFor: "", Entries: rangeEntries(1, 10)},
	}
	// Three straddlers (indices 10, 11, 12 — all inside the snapshot),
	// interleaved with fresh burst records.
	records = append(records,
		WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: 10, Command: []byte("dup-10")}},
		WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: 11, Command: []byte("dup-11")}},
		WALRecord{Type: WALLog, Entry: LogEntry{Term: 1, Index: 12, Command: []byte("dup-12")}},
	)
	records = append(records, logRecords(13, 15)...)

	ps := replayFile(t, t.TempDir(), records)

	if got := ps.Log().Len(); got != 15 {
		t.Fatalf("FAIL: log has %d entries, want 15 (all three straddlers must be deduplicated)", got)
	}
	if last := ps.Log().LastIndex(); last != 15 {
		t.Fatalf("FAIL: LastIndex = %d, want 15", last)
	}
	assertNoDuplicateIndices(t, ps)
}
