package events

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestPersistentMemoryStore_RecoversAfterFailedCompaction is the regression
// for the silent-persistence-death defect: compactLocked closes the append
// handle before rewriting, and when rewriteFile failed it returned with
// ps.file == nil and never reopened — every event stored afterwards went
// ring-only (no error, no drop accounting) until process restart.
//
// Correct behavior: Store recovers by reopening the append handle on the next
// call (the original file is intact — the failed rewrite never renamed), so
// events stored after a failed compaction still reach the persistence file,
// and the next threshold crossing retries compaction.
func TestPersistentMemoryStore_RecoversAfterFailedCompaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	// Sabotage compaction deterministically: the rewrite temp path is a
	// directory, so rewriteFile's OpenFile fails with EISDIR. The main data
	// file stays a normal file, so append recovery remains possible.
	if err := os.Mkdir(path+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	ps, err := NewPersistentMemoryStore(4, path)
	if err != nil {
		t.Fatal(err)
	}
	ps.maxFileBytes = 64 // force a compaction attempt after the first event

	mk := func(id string) engine.Event {
		return engine.Event{
			ID:        id,
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/x",
			UserAgent: strings.Repeat("A", 64),
			ClientIP:  "10.0.0.1",
			Action:    engine.ActionBlock,
			Score:     50,
		}
	}

	// Drive fileBytes past the threshold: the compaction attempt fails
	// (sabotage) and, pre-fix, left the append handle closed.
	for i := 0; i < 8; i++ {
		if err := ps.Store(mk("pre")); err != nil {
			t.Fatalf("pre-failure store %d: %v", i, err)
		}
	}

	// Main case: the next Store must recover the append handle and persist
	// the event instead of silently degrading to ring-only.
	marker := mk("post-failure-marker")
	if err := ps.Store(marker); err != nil {
		t.Fatalf("post-failure store: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"id":"post-failure-marker"`) {
		t.Fatalf("event stored after failed compaction was not persisted (file is %d bytes)", len(raw))
	}
}
