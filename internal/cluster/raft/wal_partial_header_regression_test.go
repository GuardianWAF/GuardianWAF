package raft

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWALReplayRejectsPartialHeader(t *testing.T) {
	for size := 0; size <= len(magicWALHeader); size++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "raft.wal")
		input := []byte(magicWALHeader[:size])
		if err := os.WriteFile(path, input, 0600); err != nil {
			t.Fatal(err)
		}
		w, err := OpenWAL(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = w.Replay(NewPersistentState())
		if size > 0 && size < len(magicWALHeader) {
			if err == nil {
				t.Fatalf("size=%d accepted", size)
			}
		} else if err != nil {
			t.Fatalf("size=%d: %v", size, err)
		}
		if closeErr := w.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if size == 0 {
			input = []byte(magicWALHeader)
		}
		if !bytes.Equal(got, input) {
			t.Fatalf("size=%d file mutated", size)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "raft.wal"), []byte("BADMAGIC"), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Replay(NewPersistentState()) == nil {
		t.Fatal("bad full header accepted")
	}
	t.Log("FIX VERIFIED")
}
