package raft

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestWALCountsOnlyCompleteRecordsAfterRestart(t *testing.T) {
	control, err := OpenWAL(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = control.AppendRecord(WALRecord{Type: WALState, Term: 1}); err != nil {
			t.Fatal(err)
		}
	}
	controlDir := control.dataDir
	if err = control.Close(); err != nil {
		t.Fatal(err)
	}
	control, err = OpenWAL(controlDir)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if control.RecordCount() != 2 {
		t.Fatal("unaffected complete-record control failed")
	}
	t.Log("CONTROL: two complete records counted as two")
	dir := t.TempDir()
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.AppendRecord(WALRecord{Type: WALState, Term: 7}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "raft.wal"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var tail [6]byte
	binary.BigEndian.PutUint32(tail[:4], 20)
	if _, err = f.Write(tail[:]); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	got := w.RecordCount()
	t.Logf("EXPECTED: 1 complete record; ACTUAL: %d", got)
	if got != 1 {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}

func TestWALCountsOnlyCompleteRecordsAfterRestartEdges(t *testing.T) {
	record := encodeWALRecord(WALRecord{Type: WALState, Term: 9})
	for _, n := range []int{0, 1, 4, 5, len(record) - 4, len(record) - 1, len(record)} {
		dir := t.TempDir()
		w, err := OpenWAL(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(filepath.Join(dir, "raft.wal"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(record[:n]); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		w, err = OpenWAL(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if n == len(record) {
			want = 1
		}
		if got := w.RecordCount(); got != want {
			t.Fatalf("prefix length %d: count=%d want %d", n, got, want)
		}
		ps := NewPersistentState()
		if err = w.Replay(ps); err != nil {
			t.Fatal(err)
		}
		if w.RecordCount() != want {
			t.Fatal("recovery changed complete record count")
		}
		if w.ShouldCompact(want + 1) {
			t.Fatal("premature compaction")
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
