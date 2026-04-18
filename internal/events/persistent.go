package events

import (
	"bufio"
	"encoding/json"
	"log"
	"os"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// PersistentMemoryStore wraps a MemoryStore and replays events from a JSONL
// file on startup so that recent history survives process restarts.
// New events are appended to the file so that a subsequent restart can replay them.
type PersistentMemoryStore struct {
	*MemoryStore
	path string
	file *os.File
}

// NewPersistentMemoryStore creates a MemoryStore preloaded from path and
// appends new events to the same file. If path is empty, falls back to a
// plain MemoryStore (no persistence).
func NewPersistentMemoryStore(capacity int, path string) (*PersistentMemoryStore, error) {
	ms := NewMemoryStore(capacity)

	if path == "" {
		return &PersistentMemoryStore{MemoryStore: ms}, nil
	}

	ps := &PersistentMemoryStore{
		MemoryStore: ms,
		path:        path,
	}

	// Replay existing events from file
	ps.replay()

	// Open for append
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return ps, nil // graceful: work without persistence
	}
	ps.file = f

	return ps, nil
}

// Store writes the event to the ring buffer and appends it to the JSONL file.
func (ps *PersistentMemoryStore) Store(event engine.Event) error {
	if err := ps.MemoryStore.Store(event); err != nil {
		return err
	}

	if ps.file != nil {
		ps.mu.Lock()
		data, err := json.Marshal(event)
		if err == nil {
			if _, werr := ps.file.Write(data); werr != nil {
				log.Printf("[events] failed to write event to JSONL: %v", werr)
			}
			if _, werr := ps.file.Write([]byte("\n")); werr != nil {
				log.Printf("[events] failed to write newline to JSONL: %v", werr)
			}
		}
		ps.mu.Unlock()
	}

	return nil
}

// Close flushes and closes the persistence file.
func (ps *PersistentMemoryStore) Close() error {
	if ps.file != nil {
		ps.file.Sync()
		ps.file.Close()
	}
	return ps.MemoryStore.Close()
}

// replay loads events from the JSONL file into the ring buffer.
// Only the last `capacity` events are kept (oldest are dropped).
func (ps *PersistentMemoryStore) replay() {
	f, err := os.Open(ps.path)
	if err != nil {
		return
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
		ps.rewriteFile(all[start:])
	}
}

// rewriteFile replaces the JSONL file with only the given events.
func (ps *PersistentMemoryStore) rewriteFile(events []engine.Event) {
	tmpPath := ps.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		f.Write(data)
		f.Write([]byte("\n"))
	}
	f.Close()
	os.Rename(tmpPath, ps.path)
}
