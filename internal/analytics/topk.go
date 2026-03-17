package analytics

import (
	"sort"
	"sync"
)

// TopKEntry is a key-count pair returned by TopK.Top.
type TopKEntry struct {
	Key   string
	Count int64
}

// TopK tracks the top K items by count.
// It uses a simple map plus on-demand sorting (efficient for moderate K).
type TopK struct {
	mu    sync.Mutex
	k     int
	items map[string]int64
}

// NewTopK creates a TopK tracker that retains at most k entries.
// If k <= 0 it defaults to 10.
func NewTopK(k int) *TopK {
	if k <= 0 {
		k = 10
	}
	return &TopK{
		k:     k,
		items: make(map[string]int64),
	}
}

// Add increments the count for key by count.
func (t *TopK) Add(key string, count int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items[key] += count
	t.prune()
}

// prune removes lowest-count entries if the map exceeds 10*k to bound memory.
func (t *TopK) prune() {
	limit := t.k * 10
	if len(t.items) <= limit {
		return
	}
	entries := t.sortedLocked()
	// Keep only top k entries
	t.items = make(map[string]int64, t.k)
	for i := 0; i < t.k && i < len(entries); i++ {
		t.items[entries[i].Key] = entries[i].Count
	}
}

// Top returns the top K entries sorted by count descending.
func (t *TopK) Top() []TopKEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := t.sortedLocked()
	if len(entries) > t.k {
		entries = entries[:t.k]
	}
	return entries
}

// sortedLocked returns all entries sorted by count descending. Caller must hold mu.
func (t *TopK) sortedLocked() []TopKEntry {
	entries := make([]TopKEntry, 0, len(t.items))
	for k, v := range t.items {
		entries = append(entries, TopKEntry{Key: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Key < entries[j].Key
	})
	return entries
}

// Count returns the current count for a given key.
func (t *TopK) Count(key string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.items[key]
}

// Reset clears all tracked items.
func (t *TopK) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items = make(map[string]int64)
}
