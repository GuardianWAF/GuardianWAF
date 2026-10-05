package raft

import "testing"

func TestLogStoreOwnsCommandSnapshots(t *testing.T) {
	for _, mode := range []string{"append", "appendentry", "get", "from", "all", "slice", "persist"} {
		l := NewLogStore()
		input := []byte("stable")
		var borrowed []byte
		if mode == "persist" {
			l.SetPersistence(func(e LogEntry) { borrowed = e.Command }, nil)
		}
		if mode == "appendentry" {
			l.AppendEntry(LogEntry{Term: 1, Index: 1, Command: input})
		} else {
			l.Append(1, input)
		}
		switch mode {
		case "append", "appendentry":
			borrowed = input
		case "get":
			e, _ := l.Get(1)
			borrowed = e.Command
		case "from":
			borrowed = l.EntriesFrom(1)[0].Command
		case "all":
			borrowed = l.AllEntries()[0].Command
		case "slice":
			borrowed = l.Slice(1, 1)[0].Command
		}
		release := make(chan struct{})
		done := make(chan struct{})
		go func() { <-release; borrowed[0] = 'X'; close(done) }()
		close(release)
		<-done
		e, _ := l.Get(1)
		if string(e.Command) != "stable" {
			t.Fatalf("%s changed live command: %q", mode, e.Command)
		}
	}
	l := NewLogStore()
	l.Append(1, []byte("old"))
	stale, _ := l.Get(1)
	release := make(chan struct{})
	done := make(chan struct{})
	go func() { <-release; stale.Command[0] = 'X'; close(done) }()
	l.TruncateFrom(1)
	l.Append(2, stale.Command)
	close(release)
	<-done
	e, _ := l.Get(1)
	if string(e.Command) != "old" || e.Term != 2 {
		t.Fatalf("stale snapshot changed replacement: %+v", e)
	}
	l.ResetNoPersist()
	l.Append(1, nil)
	e, _ = l.Get(1)
	if e.Command != nil {
		t.Fatal("nil changed")
	}
	if l.EntriesFrom(0) != nil || l.Slice(0, 1) != nil {
		t.Fatal("invalid range changed")
	}
	t.Log("FIX VERIFIED")
}
