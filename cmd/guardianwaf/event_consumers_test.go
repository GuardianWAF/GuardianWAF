package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestStartEventConsumer_HandlesPublishedEventsAndStopsOnClose(t *testing.T) {
	eventBus := events.NewEventBus()
	var wg sync.WaitGroup
	handled := make(chan engine.Action, 1)

	startEventConsumer(eventBus, &wg, 1, func(event engine.Event) {
		handled <- event.Action
	})

	eventBus.Publish(engine.Event{Action: engine.ActionBlock})
	select {
	case got := <-handled:
		if got != engine.ActionBlock {
			t.Fatalf("expected action %s, got %s", engine.ActionBlock, got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event consumer")
	}

	eventBus.Close()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event consumer shutdown")
	}
}

func TestStartEventConsumer_IgnoresNilInputs(t *testing.T) {
	eventBus := events.NewEventBus()
	var wg sync.WaitGroup

	startEventConsumer(nil, &wg, 1, func(engine.Event) {})
	startEventConsumer(eventBus, nil, 1, func(engine.Event) {})
	startEventConsumer(eventBus, &wg, 1, nil)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nil-input consumer unexpectedly added work")
	}
}

// Regression: startEventConsumer recovered a panicking handler and then
// RETURNED, killing the consumer goroutine for the process lifetime. The
// SIEM exporter and dashboard live view ride these consumers, so one panic
// in a handler silently ended that event stream until restart while the bus
// kept publishing into a dead consumer's buffer. The consumer must recover,
// back off, and resume draining the same channel (mirroring the analyzer/
// watcher restart pattern); it exits only when the bus closes the channel.
func TestEventConsumerSurvivesHandlerPanic(t *testing.T) {
	bus := events.NewEventBus()

	var mu sync.Mutex
	calls := 0
	handle := func(ev engine.Event) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			panic("boom on first event")
		}
	}

	wg := &sync.WaitGroup{}
	startEventConsumer(bus, wg, 16, handle)

	for i := 0; i < 3; i++ {
		bus.Publish(engine.Event{ID: fmt.Sprintf("e%d", i)})
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	bus.Close()
	wg.Wait()

	mu.Lock()
	n := calls
	mu.Unlock()
	if n < 2 {
		t.Fatalf("handler called %d times, want >= 2 — the consumer died on the first "+
			"handler panic and silently stopped processing the event stream "+
			"(SIEM export and dashboard live view dead until restart)", n)
	}
}
