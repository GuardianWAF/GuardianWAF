package cache

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryBackend provides an in-memory cache implementation.
type MemoryBackend struct {
	maxSize  int // Maximum size in MB
	data     map[string]*list.Element
	lru      *list.List // LRU eviction
	size     int64      // Current size in bytes
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// cacheItem represents a cached item.
type cacheItem struct {
	key       string
	value     []byte
	expiresAt time.Time
}

// NewMemoryBackend creates a new in-memory cache backend.
func NewMemoryBackend(maxSizeMB int) *MemoryBackend {
	if maxSizeMB <= 0 {
		maxSizeMB = 100 // Default 100MB
	}

	mb := &MemoryBackend{
		maxSize: maxSizeMB,
		data:    make(map[string]*list.Element),
		lru:     list.New(),
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go mb.cleanupExpired()

	return mb
}

// Get retrieves a value from the cache.
func (mb *MemoryBackend) Get(ctx context.Context, key string) ([]byte, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	elem, ok := mb.data[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	item := elem.Value.(*cacheItem)

	// Check expiry
	if time.Now().After(item.expiresAt) {
		mb.deleteLocked(key, elem)
		return nil, fmt.Errorf("key expired: %s", key)
	}

	// Move to front (most recently used)
	mb.lru.MoveToFront(elem)

	return item.value, nil
}

// Set stores a value in the cache.
func (mb *MemoryBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Calculate size
	itemSize := int64(len(key) + len(value))

	// Check if we need to evict
	for mb.size+itemSize > int64(mb.maxSize*1024*1024) {
		if mb.lru.Len() == 0 {
			break
		}
		elem := mb.lru.Back()
		if elem != nil {
			item := elem.Value.(*cacheItem)
			mb.size -= int64(len(item.key) + len(item.value))
			delete(mb.data, item.key)
			mb.lru.Remove(elem)
		}
	}

	// Remove existing item
	if elem, ok := mb.data[key]; ok {
		item := elem.Value.(*cacheItem)
		mb.size -= int64(len(item.key) + len(item.value))
		mb.lru.Remove(elem)
	}

	// Add new item
	item := &cacheItem{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	elem := mb.lru.PushFront(item)
	mb.data[key] = elem
	mb.size += itemSize

	return nil
}

// Delete removes a value from the cache.
func (mb *MemoryBackend) Delete(ctx context.Context, key string) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	elem, ok := mb.data[key]
	if !ok {
		return nil
	}

	mb.deleteLocked(key, elem)
	return nil
}

// deleteLocked removes an element. Caller must hold mb.mu.
func (mb *MemoryBackend) deleteLocked(key string, elem *list.Element) {
	item := elem.Value.(*cacheItem)
	mb.size -= int64(len(item.key) + len(item.value))
	mb.lru.Remove(elem)
	delete(mb.data, key)
}

// Exists checks if a key exists in the cache.
func (mb *MemoryBackend) Exists(ctx context.Context, key string) (bool, error) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	elem, ok := mb.data[key]
	if !ok {
		return false, nil
	}

	item := elem.Value.(*cacheItem)
	if time.Now().After(item.expiresAt) {
		mb.deleteLocked(key, elem)
		return false, nil
	}

	return true, nil
}

// Keys returns keys matching a pattern (simple prefix match for memory backend).
func (mb *MemoryBackend) Keys(ctx context.Context, pattern string) ([]string, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	keys := make([]string, 0)
	now := time.Now()

	for key, elem := range mb.data {
		item := elem.Value.(*cacheItem)
		if now.Before(item.expiresAt) {
			// Simple prefix matching (pattern*)
			if len(pattern) == 0 || len(key) >= len(pattern) && key[:len(pattern)] == pattern {
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

// Clear removes all values from the cache.
func (mb *MemoryBackend) Clear(ctx context.Context) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.data = make(map[string]*list.Element)
	mb.lru = list.New()
	mb.size = 0

	return nil
}

// Close stops the cleanup goroutine and clears the cache.
func (mb *MemoryBackend) Close() error {
	close(mb.stopCh)
	return mb.Clear(context.Background())
}

// cleanupExpired periodically removes expired items.
func (mb *MemoryBackend) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mb.mu.Lock()
			now := time.Now()

			for key, elem := range mb.data {
				item := elem.Value.(*cacheItem)
				if now.After(item.expiresAt) {
					mb.size -= int64(len(item.key) + len(item.value))
					mb.lru.Remove(elem)
					delete(mb.data, key)
				}
			}
			mb.mu.Unlock()
		case <-mb.stopCh:
			return
		}
	}
}

// Stats returns cache statistics.
func (mb *MemoryBackend) Stats() (items int, size int64) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()
	return mb.lru.Len(), mb.size
}
