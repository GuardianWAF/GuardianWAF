package main

import (
	"log/slog"
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
				slog.Default().Error("event consumer panic recovered", "panic", r)
			}
		}()
		for event := range ch {
			handle(event)
		}
	}()
}
