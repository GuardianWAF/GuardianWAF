package events

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- errorWriter makes bufio.Writer flush fail ---

type errorWriter struct {
	n      int
	failAt int
}

func (e *errorWriter) Write(p []byte) (int, error) {
	if e.failAt >= 0 && e.n >= e.failAt {
		return 0, errors.New("write error")
	}
	e.n += len(p)
	return len(p), nil
}

// --- EventBus.Close double close ---

func TestEventBus_DoubleClose(t *testing.T) {
	bus := NewEventBus()
	bus.Close()
	// Second close should be a no-op and not panic
	bus.Close()
}

// --- drainRemaining loop body ---

func TestDrainRemaining_WithBufferedEvents(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event, fileChannelBufSize),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}

	// Put events directly into the channel
	ev1 := engine.Event{ID: "drain-1", Timestamp: time.Now(), Action: engine.ActionPass}
	ev2 := engine.Event{ID: "drain-2", Timestamp: time.Now(), Action: engine.ActionBlock}
	fs.ch <- ev1
	fs.ch <- ev2
	close(fs.ch)

	// Manually drain (bypasses writeLoop goroutine)
	fs.drainRemaining()

	// Close file so Windows temp dir can be cleaned up
	fs.file.Close()

	// Verify events were written by reading file
	f2, _ := os.Open(path)
	defer f2.Close()
	data := make([]byte, 4096)
	n, _ := f2.Read(data)
	content := string(data[:n])
	if !strings.Contains(content, "drain-1") {
		t.Error("expected drain-1 in output")
	}
	if !strings.Contains(content, "drain-2") {
		t.Error("expected drain-2 in output")
	}
}

// --- writeEvent WriteString error ---

func TestWriteEvent_WriteStringError(t *testing.T) {
	ew := &errorWriter{failAt: 0}
	fs := &FileStore{
		writer: bufio.NewWriterSize(ew, 1), // 1-byte buffer forces immediate flush
	}
	ev := engine.Event{ID: "err", Timestamp: time.Now(), Action: engine.ActionPass}
	fs.writeEvent(ev) // should return early due to WriteString error without panicking
}

// --- writeEvent WriteByte error ---

func TestWriteEvent_WriteByteError(t *testing.T) {
	ev := engine.Event{ID: "err", Timestamp: time.Now(), Action: engine.ActionPass}
	line := marshalEventJSON(ev)
	// Buffer size exactly fits the JSON line so WriteByte triggers flush
	ew := &errorWriter{failAt: 0}
	fs := &FileStore{
		writer: bufio.NewWriterSize(ew, len(line)),
	}
	fs.writeEvent(ev) // WriteString fits, WriteByte triggers flush and fails
}

func TestWriteJSONFloat_WritesBoundedDecimalDigits(t *testing.T) {
	var b strings.Builder
	writeJSONFloat(&b, 12.125)
	if got, want := b.String(), "12.125"; got != want {
		t.Fatalf("writeJSONFloat() = %q, want %q", got, want)
	}

	for digit := 0; digit <= 9; digit++ {
		if got, want := decimalDigitByte(digit), byte('0'+digit); got != want {
			t.Fatalf("decimalDigitByte(%d) = %q, want %q", digit, got, want)
		}
	}
	if got := decimalDigitByte(10); got != '0' {
		t.Fatalf("decimalDigitByte overflow fallback = %q, want '0'", got)
	}
}

func TestCleanEventFilePath(t *testing.T) {
	cleaned, err := cleanEventFilePath(filepath.Join("events", "..", "events.jsonl"), false)
	if err != nil {
		t.Fatalf("cleanEventFilePath valid: %v", err)
	}
	if cleaned != "events.jsonl" {
		t.Fatalf("cleanEventFilePath = %q, want events.jsonl", cleaned)
	}
	if _, err := cleanEventFilePath("bad\x00events.jsonl", false); err == nil {
		t.Fatal("expected error for NUL event path")
	}
	if _, err := cleanEventFilePath("", false); err == nil {
		t.Fatal("expected error for empty required event path")
	}
	if cleaned, err := cleanEventFilePath("", true); err != nil || cleaned != "" {
		t.Fatalf("optional empty path = %q, %v; want empty nil", cleaned, err)
	}
}

func TestNewFileStore_RejectsNULPath(t *testing.T) {
	if _, err := NewFileStore("bad\x00events.jsonl", 0); err == nil {
		t.Fatal("expected error for NUL file store path")
	}
}

// --- FileStore.Close flush error ---

func TestFileStore_CloseFlushError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}

	// Start a goroutine that closes done after the channel is closed
	go func() {
		for range fs.ch {
		}
		close(fs.done)
	}()

	// Write something so the buffer is non-empty and Flush actually hits the file
	fs.writer.WriteString("x")

	// Close underlying file to make writer.Flush fail
	f.Close()

	err = fs.Close()
	if err == nil {
		t.Error("expected flush error")
	}
}

func TestFileStore_CloseSyncError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}
	close(fs.done)

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = fs.Close()
	if err == nil {
		t.Fatal("expected sync/close error")
	}
	if !strings.Contains(err.Error(), "file already closed") && !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("expected closed-file sync/close error, got %v", err)
	}
}

func TestFileStore_FlushRecordsSyncErrorAsDropped(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event),
		done:     make(chan struct{}),
		filePath: path,
		maxSize:  defaultMaxSize,
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := fs.flush(); err == nil {
		t.Fatal("expected flush to return sync error")
	}
	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

// --- checkRotation Stat error ---

func TestCheckRotation_StatError(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
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

	// Write enough to exceed maxSize
	fs.writer.WriteString("xxx")
	fs.writer.Flush()

	// Close underlying file so Stat fails
	f.Close()

	// Should not panic; returns early because Stat errors
	fs.checkRotation()
}

// --- checkRotation rename error (destination is existing directory) ---

func TestCheckRotation_RenameError(t *testing.T) {
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

	fs.writer.WriteString("xxx")
	fs.writer.Flush()

	// Align to next second boundary and pre-create rotated directory
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now) + 10*time.Millisecond)

	ts := time.Now().Format("20060102-150405")
	rotated := filepath.Join(dir, "events-"+ts+".jsonl")
	if err := os.Mkdir(rotated, 0o755); err != nil {
		t.Fatalf("setup rotated dir: %v", err)
	}

	// Rename should fail because destination exists as directory
	fs.checkRotation()

	if got := fs.DroppedEvents(); got == 0 {
		t.Fatal("expected rotation rename failure to increment dropped counter")
	}

	// fs.file should be nil or the reopened file
	if fs.file == nil {
		t.Error("expected file to remain open after rename error")
	}
	if fs.file != nil {
		fs.file.Close()
	}
}

func TestCleanupRotatedRecordsRemoveError(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")
	for i := range defaultMaxRotated + 1 {
		name := filepath.Join(dir, "events-20250101-0000"+intToStr(i)+".jsonl")
		if err := os.WriteFile(name, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	if got := fs.DroppedEvents(); got != 1 {
		t.Fatalf("DroppedEvents = %d, want 1", got)
	}
}

// --- marshalEventJSON IsBot true ---

func TestMarshalEventJSON_IsBotTrue(t *testing.T) {
	ev := engine.Event{
		ID:        "bot-evt",
		Timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		RequestID: "req-bot",
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionPass,
		Score:     0,
		IsBot:     true,
	}
	result := marshalEventJSON(ev)
	if !strings.Contains(result, `"is_bot":true`) {
		t.Errorf("expected is_bot:true, got %s", result)
	}
}
