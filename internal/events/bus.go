package events

import (
	"sync"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// EventBus provides publish/subscribe for WAF events.
type EventBus struct {
	mu          sync.RWMutex
	subscribers []chan<- engine.Event
	closed      bool
}

// NewEventBus creates a new EventBus.
func NewEventBus() *EventBus {
	return &EventBus{}
}

// Subscribe registers a channel to receive events.
func (eb *EventBus) Subscribe(ch chan<- engine.Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return
	}
	eb.subscribers = append(eb.subscribers, ch)
}

// Unsubscribe removes a channel from the subscriber list.
// The channel is NOT closed by Unsubscribe.
func (eb *EventBus) Unsubscribe(ch chan<- engine.Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	for i, sub := range eb.subscribers {
		if sub == ch {
			eb.subscribers = append(eb.subscribers[:i], eb.subscribers[i+1:]...)
			return
		}
	}
}

// Publish sends an event to all subscribers. Non-blocking: if a subscriber's
// channel is full, the event is skipped for that subscriber.
func (eb *EventBus) Publish(event engine.Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			// Skip slow subscribers to avoid blocking
		}
	}
}

// Close closes all subscriber channels and marks the bus as closed.
func (eb *EventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.closed = true
	for _, ch := range eb.subscribers {
		close(ch)
	}
	eb.subscribers = nil
}
