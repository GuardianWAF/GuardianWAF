package main

import (
	"sync"

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
		defer func() {
			if r := recover(); r != nil {
				_ = r // nolint:errcheck // panic value intentionally discarded; recoverable goroutine
			}
		}()
		for event := range ch {
			handle(event)
		}
	}()
}
