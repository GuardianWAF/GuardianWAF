package events

import (
	"bufio"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestEventBus_StatsDefaultsMaxSubscribersWhenUnset(t *testing.T) {
	bus := &EventBus{}

	if got := bus.Stats().MaxSubscribers; got != defaultMaxEventBusSubscribers {
		t.Fatalf("MaxSubscribers = %d, want %d", got, defaultMaxEventBusSubscribers)
	}
}

func TestEventBus_SubscribeAppliesDefaultMaxSubscribersWhenUnset(t *testing.T) {
	bus := &EventBus{}
	ch := make(chan engine.Event, 1)

	bus.Subscribe(ch)

	if got := bus.maxSubscribers; got != defaultMaxEventBusSubscribers {
		t.Fatalf("maxSubscribers = %d, want %d", got, defaultMaxEventBusSubscribers)
	}
	if got := bus.Stats().Subscribers; got != 1 {
		t.Fatalf("Subscribers = %d, want 1", got)
	}
	bus.Close()
}

func TestFileStore_CheckRotationCloseAfterRotationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		filePath: path,
		maxSize:  1,
	}
	if _, err := fs.writer.WriteString("xxx"); err != nil {
		t.Fatal(err)
	}
	if err := fs.writer.Flush(); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)

	rotated := filepath.Join(dir, "events-"+time.Now().Format("20060102-150405")+".jsonl")
	if err := os.Mkdir(rotated, 0o755); err != nil {
		t.Fatalf("setup rotated dir: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}

	fs.checkRotation()

	if !fs.closed {
		t.Fatal("expected file store to close after rotation reopen failure")
	}
	select {
	case _, ok := <-fs.ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	default:
		t.Fatal("expected closed channel read to proceed immediately")
	}
	if got := fs.DroppedEvents(); got < 2 {
		t.Fatalf("DroppedEvents = %d, want at least 2", got)
	}
	_ = os.Chmod(path, 0o600)
}

func TestFileStore_CleanupRotatedReadDirError(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{}
	fs.cleanupRotated(filepath.Join(filePath, "events"), ".jsonl")

	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

func TestPersistentMemoryStore_StoreFallsBackToMemoryWhenFileNil(t *testing.T) {
	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(4)}
	ev := engine.Event{ID: "memory-only", Timestamp: time.Now(), Action: engine.ActionPass}

	if err := ps.Store(ev); err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	got, err := ps.Get("memory-only")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.ID != ev.ID {
		t.Fatalf("Get().ID = %q, want %q", got.ID, ev.ID)
	}
}

func TestPersistentMemoryStore_StoreMarshalErrorDropsEvent(t *testing.T) {
	ps := &PersistentMemoryStore{
		MemoryStore: NewMemoryStore(4),
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ev := engine.Event{
		ID:       "bad-json",
		Timestamp: time.Now(),
		Action:   engine.ActionPass,
		Findings: []engine.Finding{{Confidence: math.NaN()}},
	}

	if err := ps.Store(ev); err != nil {
		t.Fatalf("Store marshal error should be swallowed, got %v", err)
	}
	if got := ps.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
	if _, err := ps.Get("bad-json"); err == nil {
		t.Fatal("marshal-failed event should not be added to memory")
	}
}

func TestPersistentMemoryStore_DroppedEventsNilReceiver(t *testing.T) {
	var ps *PersistentMemoryStore
	if got := ps.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents(nil) = %d, want 0", got)
	}
}

func TestPersistentMemoryStore_CompactLockedReturnsCloseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	if err := ps.Store(engine.Event{ID: "first", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatal(err)
	}

	ps.fileMu.Lock()
	if err := ps.file.Close(); err != nil {
		ps.fileMu.Unlock()
		t.Fatal(err)
	}
	err = ps.compactLocked()
	ps.fileMu.Unlock()
	if err == nil {
		t.Fatal("expected compactLocked close error")
	}
}

func TestPersistentMemoryStore_ReplayScannerError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	tooLongLine := strings.Repeat("a", 1024*1024+1)
	if err := os.WriteFile(path, []byte(tooLongLine), 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(1), path: path}
	if err := ps.replay(); err == nil {
		t.Fatal("expected scanner error for oversized JSONL line")
	}
}

func TestPersistentMemoryStore_RewriteFileEncodeError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps := &PersistentMemoryStore{path: path}

	err := ps.rewriteFile([]engine.Event{{
		ID:        "bad-encode",
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{Confidence: math.NaN()}},
	}})
	if err == nil {
		t.Fatal("expected rewrite encode error")
	}
	if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp file cleanup after encode error, stat error = %v", statErr)
	}
}

func TestFileStore_CloseAfterRotationFailureNoopWhenAlreadyClosed(t *testing.T) {
	fs := &FileStore{closed: true, ch: make(chan engine.Event)}

	fs.closeAfterRotationFailure()

	if !fs.closed {
		t.Fatal("expected closed flag to remain true")
	}
	select {
	case _, ok := <-fs.ch:
		if !ok {
			t.Fatal("channel should remain open on early return")
		}
	default:
	}
}

func TestPersistentMemoryStore_NewReturnsReplayError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	tooLongLine := strings.Repeat("a", 1024*1024+1)
	if err := os.WriteFile(path, []byte(tooLongLine), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewPersistentMemoryStore(1, path); err == nil {
		t.Fatal("expected replay error from oversized persisted line")
	}
}

func TestPersistentMemoryStore_StoreCompactionErrorIsLoggedAndSwallowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	ps.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	ps.fileMu.Lock()
	ps.maxFileBytes = 1
	ps.path = "bad\x00path"
	ps.fileMu.Unlock()

	if err := ps.Store(engine.Event{ID: "compact-warn", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatalf("Store should swallow compaction error, got %v", err)
	}
	if got := ps.DroppedEvents(); got != 0 {
		t.Fatalf("DroppedEvents = %d, want 0", got)
	}
}

func TestPersistentMemoryStore_CompactLockedRewriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	ps, err := NewPersistentMemoryStore(2, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()

	if err := ps.Store(engine.Event{ID: "first", Timestamp: time.Now(), Action: engine.ActionPass}); err != nil {
		t.Fatal(err)
	}

	ps.fileMu.Lock()
	ps.path = "bad\x00path"
	err = ps.compactLocked()
	ps.fileMu.Unlock()
	if err == nil {
		t.Fatal("expected compactLocked rewrite error")
	}
}

func TestPersistentMemoryStore_ReplayRejectsInvalidPath(t *testing.T) {
	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(1), path: "bad\x00path"}
	if err := ps.replay(); err == nil {
		t.Fatal("expected replay path cleaning error")
	}
}

func TestPersistentMemoryStore_ReplaySkipsInvalidJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	content := "not-json\n{\"id\":\"kept\",\"timestamp\":\"2025-01-01T00:00:00Z\",\"action\":\"pass\"}\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	ps := &PersistentMemoryStore{MemoryStore: NewMemoryStore(2), path: path}
	if err := ps.replay(); err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if _, err := ps.Get("kept"); err != nil {
		t.Fatal("expected valid JSON line to be replayed")
	}
}

func TestPersistentMemoryStore_RewriteFileRejectsInvalidPath(t *testing.T) {
	ps := &PersistentMemoryStore{path: "bad\x00path"}
	if err := ps.rewriteFile(nil); err == nil {
		t.Fatal("expected rewriteFile path cleaning error")
	}
}

func TestPersistentMemoryStore_RewriteFileOpenTempError(t *testing.T) {
	ps := &PersistentMemoryStore{path: filepath.Join(t.TempDir(), "missing", "events.jsonl")}
	if err := ps.rewriteFile(nil); err == nil {
		t.Fatal("expected rewriteFile temp open error")
	}
}
