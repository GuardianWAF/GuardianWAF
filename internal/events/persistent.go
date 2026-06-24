package events

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/logging"
)

// PersistentMemoryStore wraps a MemoryStore and replays events from a JSONL
// file on startup so that recent history survives process restarts.
// New events are appended to the file so that a subsequent restart can replay them.
type PersistentMemoryStore struct {
	*MemoryStore
	path    string
	file    *os.File
	fileMu  sync.Mutex
	dropped atomic.Int64
	closed  bool
	log     *slog.Logger
}

// NewPersistentMemoryStore creates a MemoryStore preloaded from path and
// appends new events to the same file. If path is empty, falls back to a
// plain MemoryStore (no persistence). If path is non-empty and cannot be
// opened, an error is returned so configured persistence can fail fast.
func NewPersistentMemoryStore(capacity int, path string) (*PersistentMemoryStore, error) {
	ms := NewMemoryStore(capacity)
	path, err := cleanEventFilePath(path, true)
	if err != nil {
		return nil, err
	}

	if path == "" {
		return &PersistentMemoryStore{MemoryStore: ms}, nil
	}

	ps := &PersistentMemoryStore{
		MemoryStore: ms,
		path:        path,
		log:         logging.NewLogger("events"),
	}

	// Replay existing events from file
	if err := ps.replay(); err != nil {
		return nil, err
	}

	// Open for append
	// #nosec G304 -- event persistence path is operator-selected, NUL-rejected, and cleaned before use.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	ps.file = f

	return ps, nil
}

// Store writes the event to the ring buffer and appends it to the JSONL file.
func (ps *PersistentMemoryStore) Store(event engine.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		ps.dropped.Add(1)
		ps.log.Warn("failed to marshal event to JSONL", "error", err)
		return nil
	}

	ps.fileMu.Lock()
	defer ps.fileMu.Unlock()
	if ps.closed {
		ps.dropped.Add(1)
		return errors.New("event dropped: persistent memory store is closed")
	}

	if ps.file == nil {
		return ps.MemoryStore.Store(event)
	}
	if _, werr := ps.file.Write(data); werr != nil {
		ps.dropped.Add(1)
		ps.log.Warn("failed to write event to JSONL", "error", werr)
		return fmt.Errorf("persisting event JSON: %w", werr)
	}
	if _, werr := ps.file.Write([]byte("\n")); werr != nil {
		ps.dropped.Add(1)
		ps.log.Warn("failed to write newline to JSONL", "error", werr)
		return fmt.Errorf("persisting event newline: %w", werr)
	}

	return ps.MemoryStore.Store(event)
}

// DroppedEvents returns the number of events that could not be appended to the
// persistence file after being stored in memory.
func (ps *PersistentMemoryStore) DroppedEvents() int64 {
	if ps == nil {
		return 0
	}
	return ps.dropped.Load()
}

// Close flushes and closes the persistence file.
func (ps *PersistentMemoryStore) Close() error {
	var closeErr error
	ps.fileMu.Lock()
	if ps.file != nil {
		ps.closed = true
		closeErr = errors.Join(ps.file.Sync(), ps.file.Close())
		ps.file = nil
	} else {
		ps.closed = true
	}
	ps.fileMu.Unlock()
	return errors.Join(closeErr, ps.MemoryStore.Close())
}

// replay loads events from the JSONL file into the ring buffer.
// Only the last `capacity` events are kept (oldest are dropped).
func (ps *PersistentMemoryStore) replay() error {
	path, err := cleanEventFilePath(ps.path, false)
	if err != nil {
		return err
	}
	ps.path = path
	// #nosec G304 -- event persistence path is operator-selected, NUL-rejected, and cleaned before use.
	f, err := os.Open(ps.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("opening event persistence file for replay: %w", err)
	}
	defer f.Close()

	// Read all events first, then keep only the last N
	var all []engine.Event
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		var ev engine.Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		all = append(all, ev)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning event persistence file: %w", err)
	}

	// Keep only the last `capacity` events
	start := 0
	if len(all) > ps.capacity {
		start = len(all) - ps.capacity
	}
	for _, ev := range all[start:] {
		ps.MemoryStore.Store(ev)
	}

	// Truncate the file to only contain events we kept (rewrite)
	if len(all) > ps.capacity {
		if err := ps.rewriteFile(all[start:]); err != nil {
			return err
		}
	}
	return nil
}

// rewriteFile replaces the JSONL file with only the given events.
func (ps *PersistentMemoryStore) rewriteFile(events []engine.Event) error {
	path, err := cleanEventFilePath(ps.path, false)
	if err != nil {
		return err
	}
	ps.path = path
	tmpPath := ps.path + ".tmp"
	// #nosec G304 -- tmpPath is derived from the cleaned event persistence path.
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening event persistence rewrite temp file: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	enc := json.NewEncoder(f)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return errors.Join(fmt.Errorf("writing event persistence rewrite temp file: %w", err), f.Close())
		}
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("finalizing event persistence rewrite temp file: %w", err)
	}
	if err := os.Rename(tmpPath, ps.path); err != nil {
		return fmt.Errorf("committing event persistence rewrite: %w", err)
	}
	committed = true
	return nil
}
