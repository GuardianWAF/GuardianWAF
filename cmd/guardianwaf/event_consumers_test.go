package main

import (
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
