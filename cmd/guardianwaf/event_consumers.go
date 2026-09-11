package main

import (
	"log/slog"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func startEventConsumer(eventBus *events.EventBus, wg *sync.WaitGroup, buffer int, handle func(engine.Event)) {
	if eventBus == nil || wg == nil || handle == nil {
		return
	}
	ch := make(chan engine.Event, buffer)
	eventBus.Subscribe(ch)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// A panicking handler must not kill the consumer for the process
		// lifetime — the SIEM exporter and dashboard live view ride these
		// consumers. Recover, back off, and resume draining the same channel
		// (buffered events are preserved). Exit only when the bus closes the
		// channel on shutdown. Mirrors the analyzer/watcher restart pattern.
		for {
			if closed := drainEvents(ch, handle); closed {
				return
			}
			time.Sleep(time.Second)
		}
	}()
}

// drainEvents ranges over the consumer channel until the bus closes it
// (returns true) or the handler panics (recovers, logs, returns false so the
// caller resumes after a backoff — buffered events are preserved).
func drainEvents(ch <-chan engine.Event, handle func(engine.Event)) (closed bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("event consumer panic recovered", "panic", r)
			closed = false
		}
	}()
	for event := range ch {
		handle(event)
	}
	return true
}
