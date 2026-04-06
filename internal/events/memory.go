package events

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// MemoryStore stores events in a fixed-size ring buffer.
type MemoryStore struct {
	mu       sync.RWMutex
	buffer   []engine.Event
	capacity int
	head     int            // next write position
	count    int            // number of stored events
	index    map[string]int // event ID -> buffer position (for Get)
}

// NewMemoryStore creates a new MemoryStore with the given capacity.
// If capacity is less than 1, it defaults to 1024.
func NewMemoryStore(capacity int) *MemoryStore {
	if capacity < 1 {
		capacity = 1024
	}
	return &MemoryStore{
		buffer:   make([]engine.Event, capacity),
		capacity: capacity,
		index:    make(map[string]int, capacity),
	}
}

// Store writes an event into the ring buffer.
// When the buffer is full, the oldest event is overwritten.
func (ms *MemoryStore) Store(event engine.Event) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// If buffer is full, remove the old event at head from the index
	if ms.count == ms.capacity {
		oldID := ms.buffer[ms.head].ID
		delete(ms.index, oldID)
	}

	ms.buffer[ms.head] = event
	ms.index[event.ID] = ms.head

	ms.head = (ms.head + 1) % ms.capacity
	if ms.count < ms.capacity {
		ms.count++
	}

	return nil
}

// Get retrieves an event by its ID.
func (ms *MemoryStore) Get(id string) (*engine.Event, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	pos, ok := ms.index[id]
	if !ok {
		return nil, errors.New("event not found")
	}
	ev := ms.buffer[pos]
	return &ev, nil
}

// Recent returns the last n events in reverse chronological order.
func (ms *MemoryStore) Recent(n int) ([]engine.Event, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if n <= 0 {
		return nil, nil
	}
	if n > ms.count {
		n = ms.count
	}

	result := make([]engine.Event, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recently written position
		pos := (ms.head - 1 - i + ms.capacity) % ms.capacity
		result[i] = ms.buffer[pos]
	}
	return result, nil
}

// Query returns events matching the filter, along with the total count of matches.
func (ms *MemoryStore) Query(filter EventFilter) ([]engine.Event, int, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var matched []engine.Event

	// Iterate over all stored events
	for i := 0; i < ms.count; i++ {
		pos := (ms.head - ms.count + i + ms.capacity) % ms.capacity
		ev := ms.buffer[pos]

		if !ms.matchesFilter(ev, filter) {
			continue
		}
		matched = append(matched, ev)
	}

	// Sort
	sortEvents(matched, filter.SortBy, filter.SortOrder)

	total := len(matched)

	// Apply offset and limit
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return nil, total, nil
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(matched) {
		matched = matched[:filter.Limit]
	}

	return matched, total, nil
}

// Count returns the number of events matching the filter without returning them.
func (ms *MemoryStore) Count(filter EventFilter) (int, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	count := 0
	for i := 0; i < ms.count; i++ {
		pos := (ms.head - ms.count + i + ms.capacity) % ms.capacity
		ev := ms.buffer[pos]
		if ms.matchesFilter(ev, filter) {
			count++
		}
	}
	return count, nil
}

// Close is a no-op for MemoryStore.
func (ms *MemoryStore) Close() error {
	return nil
}

// matchesFilter checks if an event matches the given filter criteria.
func (ms *MemoryStore) matchesFilter(ev engine.Event, f EventFilter) bool {
	if !f.Since.IsZero() && ev.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && ev.Timestamp.After(f.Until) {
		return false
	}
	if f.Action != "" {
		actionStr := actionToFilterString(ev.Action)
		if actionStr != f.Action {
			return false
		}
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	if f.MinScore > 0 && ev.Score < f.MinScore {
		return false
	}
	if f.Path != "" && !strings.HasPrefix(ev.Path, f.Path) {
		return false
	}
	if f.CountryCode != "" && ev.CountryCode != f.CountryCode {
		return false
	}
	return true
}

// actionToFilterString converts an Action to its filter string representation.
func actionToFilterString(a engine.Action) string {
	switch a {
	case engine.ActionBlock:
		return "blocked"
	case engine.ActionLog:
		return "logged"
	case engine.ActionPass:
		return "passed"
	case engine.ActionChallenge:
		return "challenge"
	default:
		return ""
	}
}

// sortEvents sorts the event slice in place according to the specified criteria.
func sortEvents(events []engine.Event, sortBy, sortOrder string) {
	if len(events) < 2 {
		return
	}

	switch sortBy {
	case "score":
		sort.Slice(events, func(i, j int) bool {
			if sortOrder == "asc" {
				return events[i].Score < events[j].Score
			}
			return events[i].Score > events[j].Score
		})
	default: // "timestamp" or empty
		sort.Slice(events, func(i, j int) bool {
			if sortOrder == "asc" {
				return events[i].Timestamp.Before(events[j].Timestamp)
			}
			return events[i].Timestamp.After(events[j].Timestamp)
		})
	}
}
