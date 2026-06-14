package main

import (
	"context"
	"fmt"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func setupRuntimeEngine(cfg *config.Config) (events.EventStore, *events.EventBus, *engine.Engine, *layerRuntimeResources, error) {
	eventStore, err := newEventStore(cfg)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create event store: %w", err)
	}
	eventBus := events.NewEventBus()

	eng, err := engine.NewEngine(cfg, eventStore, eventBus)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create engine: %w", err)
	}

	runtimeResources := &layerRuntimeResources{}
	if err := addLayersWithRuntime(eng, cfg, runtimeResources); err != nil {
		_ = runtimeResources.stopGeoIPRefresh(context.Background())
		_ = eng.Close()
		return nil, nil, nil, nil, fmt.Errorf("wire WAF layers: %w", err)
	}
	if cfg.Logging.Level != "" {
		eng.Logs.SetLevel(cfg.Logging.Level)
	}
	setupAccessLogging(eng, cfg)

	return eventStore, eventBus, eng, runtimeResources, nil
}

func logRuntimeEngineReady(eng *engine.Engine, cfg *config.Config) {
	eng.Logs.Infof("Engine initialized in %s mode (block=%d, log=%d)", cfg.Mode, cfg.WAF.Detection.Threshold.Block, cfg.WAF.Detection.Threshold.Log)
}
