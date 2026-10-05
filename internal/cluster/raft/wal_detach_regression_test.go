package raft

import "testing"

func TestSetWALNilDisablesLogPersistence(t *testing.T) {
	old, err := OpenWAL(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	next, err := OpenWAL(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	ps := NewPersistentState()
	ps.SetWAL(old)
	ps.Log().Append(1, []byte("control"))
	before := old.RecordCount()
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-release
		ps.Log().Append(1, []byte("detached"))
		ps.Log().TruncateFrom(2)
		ps.SetCurrentTerm(2)
		close(done)
	}()
	ps.SetWAL(nil)
	ps.SetWAL(nil)
	close(release)
	<-done
	if got := old.RecordCount(); got != before {
		t.Fatalf("detached WAL received writes: %d -> %d", before, got)
	}
	ps.SetWAL(next)
	ps.Log().Append(2, []byte("reattached"))
	if next.RecordCount() != 1 || old.RecordCount() != before {
		t.Fatal("reattachment used wrong WAL")
	}
	ps.SetWAL(nil)
	ps.Log().TruncateFrom(1)
	if next.RecordCount() != 1 {
		t.Fatal("detached truncate persisted")
	}
	t.Log("FIX VERIFIED")
}
