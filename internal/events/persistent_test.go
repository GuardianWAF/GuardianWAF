package events

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestPersistentMemoryStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	ps, err := NewPersistentMemoryStore(100, path)
	if err != nil {
		t.Fatal(err)
	}

	// Store some events
	for i := range 5 {
		ps.Store(engine.Event{ID: string(rune('A' + i)), Score: i * 10})
	}
	ps.Close()

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("persistence file should exist")
	}

	// Reload from file
	ps2, err := NewPersistentMemoryStore(100, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps2.Close()

	recent, err := ps2.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected 5 events, got %d", len(recent))
	}
	// Most recent first
	if recent[0].ID != "E" {
		t.Errorf("first event ID = %q, want %q", recent[0].ID, "E")
	}
}

func TestPersistentMemoryStore_Truncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	// Store 10 events with capacity 5
	ps, _ := NewPersistentMemoryStore(5, path)
	for i := range 10 {
		ps.Store(engine.Event{ID: string(rune('A' + i))})
	}
	ps.Close()

	// Reload — only last 5 should be present
	ps2, _ := NewPersistentMemoryStore(5, path)
	defer ps2.Close()

	recent, _ := ps2.Recent(10)
	if len(recent) != 5 {
		t.Fatalf("expected 5 events, got %d", len(recent))
	}
	if recent[0].ID != "J" {
		t.Errorf("most recent = %q, want %q", recent[0].ID, "J")
	}
	if recent[4].ID != "F" {
		t.Errorf("oldest = %q, want %q", recent[4].ID, "F")
	}
}

func TestPersistentMemoryStore_RuntimeCompaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	ps, err := NewPersistentMemoryStore(5, path)
	if err != nil {
		t.Fatal(err)
	}
	// Force compaction after a tiny amount of data.
	ps.fileMu.Lock()
	ps.maxFileBytes = 256
	ps.fileMu.Unlock()

	for i := range 200 {
		if err := ps.Store(engine.Event{ID: string(rune('A' + i%26)), Score: i}); err != nil {
			t.Fatalf("store: %v", err)
		}
	}

	// The file must have been compacted well below what 200 appends would
	// produce, and bounded near the ring-buffer contents (capacity 5).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 4096 {
		t.Fatalf("expected compacted file, got %d bytes", info.Size())
	}
	ps.Close()

	// Reload: only the last `capacity` events survive, in order.
	ps2, err := NewPersistentMemoryStore(5, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps2.Close()
	recent, err := ps2.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected 5 events after compaction+reload, got %d", len(recent))
	}
	if recent[0].Score != 199 {
		t.Fatalf("most recent Score = %d, want 199", recent[0].Score)
	}
}

func TestPersistentMemoryStore_RewriteFileReturnsCommitError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events-dir")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	ps := &PersistentMemoryStore{
		MemoryStore: NewMemoryStore(1),
		path:        path,
	}
	err := ps.rewriteFile([]engine.Event{{ID: "kept"}})
	if err == nil {
		t.Fatal("expected rewrite commit error")
	}
	if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("expected failed rewrite temp file to be removed, stat error = %v", statErr)
	}
}

func TestPersistentMemoryStore_NoPath(t *testing.T) {
	ps, err := NewPersistentMemoryStore(10, "")
	if err != nil {
		t.Fatal(err)
	}
	ps.Store(engine.Event{ID: "test"})
	ps.Close()

	recent, _ := ps.Recent(1)
	if len(recent) != 1 || recent[0].ID != "test" {
		t.Error("should work without file path")
	}
}

func TestPersistentMemoryStore_RejectsNULPath(t *testing.T) {
	if _, err := NewPersistentMemoryStore(10, "bad\x00events.jsonl"); err == nil {
		t.Fatal("expected error for NUL persistence path")
	}
}

func TestPersistentMemoryStore_ConcurrentStoreAndClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	ps, err := NewPersistentMemoryStore(1000, path)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errCh := make(chan any, 16)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errCh <- r
				}
			}()
			<-start
			for i := range 100 {
				_ = ps.Store(engine.Event{ID: string(rune('a'+worker)) + "-" + string(rune('A'+i%26))})
			}
		}(worker)
	}

	close(start)
	time.Sleep(time.Millisecond)
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errCh)
	for r := range errCh {
		t.Fatalf("Store panicked during concurrent Close: %v", r)
	}
}

func TestPersistentMemoryStore_CloseReturnsPersistenceErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(10, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Store(engine.Event{ID: "close-error"}); err != nil {
		t.Fatal(err)
	}

	ps.fileMu.Lock()
	if err := ps.file.Close(); err != nil {
		ps.fileMu.Unlock()
		t.Fatal(err)
	}
	ps.fileMu.Unlock()

	if err := ps.Close(); err == nil {
		t.Fatal("expected Close to return persistence flush/close error")
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got %v", err)
	}
	if got := ps.DroppedEvents(); got != 0 {
		t.Fatalf("close error should not be counted as a dropped accepted event, got %d", got)
	}
}

func TestPersistentMemoryStore_StoreReturnsPersistenceWriteErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(10, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	ps.fileMu.Lock()
	if err := ps.file.Close(); err != nil {
		ps.fileMu.Unlock()
		t.Fatal(err)
	}
	ps.fileMu.Unlock()

	if err := ps.Store(engine.Event{ID: "write-error"}); err == nil {
		t.Fatal("expected Store to return persistence write error")
	}
	if got := ps.DroppedEvents(); got != 1 {
		t.Fatalf("expected 1 dropped persisted event after write error, got %d", got)
	}
	if _, err := ps.Get("write-error"); err == nil {
		t.Fatal("event with failed durable append should not be added to memory")
	}
}
