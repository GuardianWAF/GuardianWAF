package events

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCheckRotation_SameSecondCollisionPreservesPreviousRotation pins the fix
// for silent audit-event loss: rotated names use SECOND granularity, so two
// rotations within one wall-clock second computed the SAME destination name
// and os.Rename silently REPLACED the existing regular file — the earlier
// rotation's events were destroyed with no error and no dropped-counter
// increment. The fix bumps a numeric suffix over occupied regular-file
// destinations. Directory destinations are left alone so the rename still
// fails into the existing recovery path (pinned by
// TestCheckRotation_RenameError).
func TestCheckRotation_SameSecondCollisionPreservesPreviousRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		filePath: path,
		maxSize:  1,
	}
	t.Cleanup(func() { fs.file.Close() })

	// Align just past a second boundary so both rotations land in the same
	// second with ~980ms of headroom (same pattern as
	// TestCheckRotation_RenameError).
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)
	ts := time.Now().Format("20060102-150405")

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	plain := base + "-" + ts + ext
	bumped := base + "-" + ts + "-1" + ext

	// Rotation 1: the plain destination is free, so the plain name is used.
	if _, err := fs.writer.WriteString("first-rotation-data\n"); err != nil {
		t.Fatal(err)
	}
	if err := fs.writer.Flush(); err != nil {
		t.Fatal(err)
	}
	fs.checkRotation()

	got, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("rotation 1 produced no %s: %v", filepath.Base(plain), err)
	}
	if !strings.Contains(string(got), "first-rotation-data") {
		t.Fatalf("rotation 1 file has unexpected content: %q", string(got))
	}

	// Rotation 2 in the same second: its destination equals rotation 1's
	// file. The rename must bump to the -1 sibling instead of replacing it.
	if _, err := fs.writer.WriteString("second-rotation-data\n"); err != nil {
		t.Fatal(err)
	}
	if err := fs.writer.Flush(); err != nil {
		t.Fatal(err)
	}
	fs.checkRotation()

	got, err = os.ReadFile(plain)
	if err != nil {
		t.Fatalf("rotation 1 file destroyed by same-second collision: %v", err)
	}
	if !strings.Contains(string(got), "first-rotation-data") {
		t.Fatalf("rotation 1 file was replaced by rotation 2 (data loss): %q", string(got))
	}
	got, err = os.ReadFile(bumped)
	if err != nil {
		t.Fatalf("rotation 2 was not bumped into %s: %v", filepath.Base(bumped), err)
	}
	if !strings.Contains(string(got), "second-rotation-data") {
		t.Fatalf("bumped file has unexpected content: %q", string(got))
	}

	// The store must remain fully operational after the bumped rotation:
	// checkRotation swaps in a fresh file+writer for the (new) main path.
	if fs.file == nil {
		t.Fatal("expected fs.file to be replaced after rotation")
	}
	if _, err := fs.writer.WriteString("post-rotation-data\n"); err != nil {
		t.Fatal(err)
	}
	if err := fs.writer.Flush(); err != nil {
		t.Fatal(err)
	}
}
