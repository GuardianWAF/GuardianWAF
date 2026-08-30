package events

import (
	"sync"
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// EventBusStats contains bounded operational counters for event fan-out.
type EventBusStats struct {
	Subscribers           int
	MaxSubscribers        int
	PublishedEvents       int64
	DroppedEvents         int64
	RejectedSubscriptions int64
}

// EventBus provides publish/subscribe for WAF events.
type EventBus struct {
	mu                    sync.RWMutex
	subscribers           []chan<- engine.Event
	maxSubscribers        int
	closed                bool
	publishedTotal        atomic.Int64
	droppedTotal          atomic.Int64
	rejectedSubscriptions atomic.Int64
}

const defaultMaxEventBusSubscribers = 1024

// NewEventBus creates a new EventBus.
func NewEventBus() *EventBus {
	return NewEventBusWithMaxSubscribers(defaultMaxEventBusSubscribers)
}

// NewEventBusWithMaxSubscribers creates an EventBus with a fixed subscriber cap.
func NewEventBusWithMaxSubscribers(maxSubscribers int) *EventBus {
	if maxSubscribers < 1 {
		maxSubscribers = defaultMaxEventBusSubscribers
	}
	return &EventBus{maxSubscribers: maxSubscribers}
}

// Subscribe registers a channel to receive events.
func (eb *EventBus) Subscribe(ch chan<- engine.Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		eb.rejectedSubscriptions.Add(1)
		return
	}
	if eb.maxSubscribers < 1 {
		eb.maxSubscribers = defaultMaxEventBusSubscribers
	}
	if len(eb.subscribers) >= eb.maxSubscribers {
		eb.rejectedSubscriptions.Add(1)
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
// channel is full, the event is skipped for that subscriber. The read lock is
// held across the sends so Close() (which takes the write lock before closing
// the channels) can never interleave with a send — a snapshot-then-send
// outside the lock allowed "send on closed channel" panics during shutdown.
func (eb *EventBus) Publish(event engine.Event) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return
	}

	eb.publishedTotal.Add(1)
	for _, ch := range eb.subscribers {
		select {
		case ch <- event:
		default:
			// Skip slow subscribers to avoid blocking
			eb.droppedTotal.Add(1)
		}
	}
}

// Stats returns bounded event bus fan-out counters for metrics and dashboards.
func (eb *EventBus) Stats() EventBusStats {
	eb.mu.RLock()
	subscribers := len(eb.subscribers)
	maxSubscribers := eb.maxSubscribers
	eb.mu.RUnlock()
	if maxSubscribers < 1 {
		maxSubscribers = defaultMaxEventBusSubscribers
	}
	return EventBusStats{
		Subscribers:           subscribers,
		MaxSubscribers:        maxSubscribers,
		PublishedEvents:       eb.publishedTotal.Load(),
		DroppedEvents:         eb.droppedTotal.Load(),
		RejectedSubscriptions: eb.rejectedSubscriptions.Load(),
	}
}

// Close closes all subscriber channels and marks the bus as closed.
// Safe to call multiple times.
func (eb *EventBus) Close() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return
	}
	eb.closed = true
	for _, ch := range eb.subscribers {
		close(ch)
	}
	eb.subscribers = nil
}
