package raft

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Regression: WAL compaction orphaned records fsynced between Compact's
// state gather and the snapshot rename. A crash (process death) before the
// next successful compaction permanently lost committed entries: their
// records were written to the old file that the rename replaced. A post-run
// reopen check cannot see this — each later compaction re-snapshots from
// memory and heals intermediate gaps — so this test simulates the crash at
// window close via the .compact.tmp rename marker and audits the reopened
// log.
//
// compactLocked now holds w.mu across the whole gather→rename window and
// Snapshot holds ps.mu for writing, so a concurrent append either lands
// inside the snapshot or blocks until the swap and lands on the new file —
// never orphaned.
func TestWALCompactionCrashWindowKeepsCommittedEntries(t *testing.T) {
	dir := t.TempDir()
	ps := NewPersistentState()
	wal, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	ps.SetWAL(wal)
	defer wal.Close()

	// Seed phase: committed entries, then one compaction so the WAL is a
	// snapshot record and subsequent compactions re-gather from memory.
	const seedN = 20000
	for i := 1; i <= seedN; i++ {
		ps.Log().Append(1, []byte(fmt.Sprintf("seed-%d", i)))
	}
	if err := ps.Snapshot(); err != nil {
		t.Fatalf("seed Snapshot: %v", err)
	}

	// Crash-window phase: compact back-to-back; the instant the compaction
	// window opens (tmp marker visible), append a burst; simulate the crash
	// when the window closes (marker renamed away) — no further compaction
	// may heal the gap.
	compacted := make(chan struct{})
	compactorDone := make(chan struct{})
	go func() {
		defer close(compactorDone)
		for {
			select {
			case <-compacted:
				return
			default:
			}
			if err := ps.Snapshot(); err != nil {
				return
			}
		}
	}()

	tmpPath := filepath.Join(dir, "wal", "raft.wal.compact.tmp")
	deadline := time.Now().Add(10 * time.Second)
	windowOpen := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tmpPath); err == nil {
			windowOpen = true
			break
		}
	}
	if !windowOpen {
		t.Fatal("compaction window never opened (no .compact.tmp marker)")
	}

	// Window open: fire the burst of committed entries.
	const burstN = 2000
	burstDone := make(chan struct{})
	go func() {
		defer close(burstDone)
		for i := 1; i <= burstN; i++ {
			ps.Log().Append(1, []byte(fmt.Sprintf("burst-%d", i)))
		}
	}()
	<-burstDone

	// Crash at window close: wait for the marker to disappear (rename done),
	// then stop the compactor so nothing can heal the gap.
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tmpPath); err != nil {
			break
		}
	}
	close(compacted)
	<-compactorDone

	// Reopen: replay must contain every fsynced-acknowledged entry.
	if err := wal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ps2 := NewPersistentState()
	wal2, err := OpenWAL(filepath.Join(dir, "wal"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer wal2.Close()
	if err := wal2.Replay(ps2); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got, want := ps2.Log().Len(), seedN+burstN; got != want {
		t.Fatalf("crash lost committed entries: reopened log has %d entries, want %d (compaction window orphaning)", got, want)
	}
}
