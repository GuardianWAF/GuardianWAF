package events

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// MemoryStore stores events in a fixed-size ring buffer.
type MemoryStore struct {
	mu sync.RWMutex
	// chunks hold the ring in fixed-size blocks allocated as positions are
	// first written, so a large capacity costs nothing until it is used and
	// growth never copies events. Position p lives at
	// chunks[p>>memoryChunkShift][p&memoryChunkMask].
	chunks   [][]engine.Event
	capacity int
	head     int            // next write position
	count    int            // number of stored events
	index    map[string]int // event ID -> buffer position (for Get)
}

// NewMemoryStore creates a new MemoryStore with the given capacity.
// If capacity is less than 1, it defaults to 1024. Memory is allocated as
// events arrive: the default 100,000-event capacity would otherwise cost
// ~44 MB per store before the first request.
func NewMemoryStore(capacity int) *MemoryStore {
	if capacity < 1 {
		capacity = 1024
	}
	return &MemoryStore{
		chunks:   make([][]engine.Event, (capacity+memoryChunkMask)>>memoryChunkShift),
		capacity: capacity,
		index:    make(map[string]int, min(capacity, memoryChunkSize)),
	}
}

const (
	memoryChunkShift = 10
	memoryChunkSize  = 1 << memoryChunkShift // events per chunk (~440 KiB)
	memoryChunkMask  = memoryChunkSize - 1
)

// slot returns the event at ring position pos, allocating its chunk on first
// write. The last chunk is sized to the remaining capacity. Caller holds mu
// (write lock when the chunk may not exist yet).
func (ms *MemoryStore) slot(pos int) *engine.Event {
	c := pos >> memoryChunkShift
	if ms.chunks[c] == nil {
		ms.chunks[c] = make([]engine.Event, min(memoryChunkSize, ms.capacity-c<<memoryChunkShift))
	}
	return &ms.chunks[c][pos&memoryChunkMask]
}

// at returns the event at an already-written ring position.
func (ms *MemoryStore) at(pos int) engine.Event {
	return ms.chunks[pos>>memoryChunkShift][pos&memoryChunkMask]
}

// Store writes an event into the ring buffer.
// When the buffer is full, the oldest event is overwritten.
func (ms *MemoryStore) Store(event engine.Event) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// If buffer is full, remove the old event at head from the index
	if ms.count == ms.capacity {
		oldID := ms.at(ms.head).ID
		if ms.index[oldID] == ms.head {
			delete(ms.index, oldID)
		}
	}

	*ms.slot(ms.head) = cloneEvent(event)
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
	ev := cloneEvent(ms.at(pos))
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
		result[i] = cloneEvent(ms.at(pos))
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
		ev := ms.at(pos)

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

	for i := range matched {
		matched[i] = cloneEvent(matched[i])
	}
	return matched, total, nil
}

func cloneEvent(event engine.Event) engine.Event {
	event.Findings = slices.Clone(event.Findings)
	return event
}

// Count returns the number of events matching the filter without returning them.
func (ms *MemoryStore) Count(filter EventFilter) (int, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	count := 0
	for i := 0; i < ms.count; i++ {
		pos := (ms.head - ms.count + i + ms.capacity) % ms.capacity
		ev := ms.at(pos)
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

// DroppedEvents reports dropped events. MemoryStore overwrites old entries when
// full, but does not reject new events, so this is always zero.
func (ms *MemoryStore) DroppedEvents() int64 {
	return 0
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
		if !eventActionMatches(ev.Action, f.Action) {
			return false
		}
	}
	if f.ClientIP != "" && ev.ClientIP != f.ClientIP {
		return false
	}
	if f.RuleID != "" && !eventRuleMatches(ev, f.RuleID) {
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
	if f.TenantID != "" && ev.TenantID != f.TenantID {
		return false
	}
	return true
}

func eventActionMatches(action engine.Action, filter string) bool {
	switch filter {
	case action.String(), actionToFilterString(action):
		return true
	default:
		return false
	}
}

func eventRuleMatches(ev engine.Event, ruleID string) bool {
	for _, finding := range ev.Findings {
		if finding.DetectorName == ruleID || strings.TrimPrefix(finding.DetectorName, "rule:") == ruleID {
			return true
		}
	}
	return false
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
