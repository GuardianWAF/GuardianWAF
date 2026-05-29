package main

import (
	"fmt"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func setupRuntimeEngine(cfg *config.Config) (events.EventStore, *events.EventBus, *engine.Engine, error) {
	eventStore, err := newEventStore(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create event store: %w", err)
	}
	eventBus := events.NewEventBus()

	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create engine: %w", err)
	}

	addLayers(eng, cfg)
	if cfg.Logging.Level != "" {
		eng.Logs.SetLevel(cfg.Logging.Level)
	}
	setupAccessLogging(eng, cfg)

	return eventStore, eventBus, eng, nil
}

func logRuntimeEngineReady(eng *engine.Engine, cfg *config.Config) {
	eng.Logs.Infof("Engine initialized in %s mode (block=%d, log=%d)", cfg.Mode, cfg.WAF.Detection.Threshold.Block, cfg.WAF.Detection.Threshold.Log)
}
