package main

import (
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/siem"
)

// setupSIEMRuntime creates and starts a SIEM exporter when siem.enabled is
// true. The exporter subscribes to the event bus and forwards block/challenge
// events to the configured SIEM endpoint via CEF over TLS syslog.
//
// Returns nil (and does nothing) when SIEM is disabled or the endpoint is
// missing. The returned exporter must be closed during shutdown.
func setupSIEMRuntime(
	cfg *config.Config,
	_ interface{}, // engine — accepted for call-site symmetry with setupAlertingRuntime
	eventBus *events.EventBus,
	eventConsumerWG *sync.WaitGroup,
	dash *dashboard.Dashboard,
) interface{ Close() error } {
	if cfg == nil || eventBus == nil || !cfg.WAF.SIEM.Enabled {
		return nil
	}

	expCfg := siem.ExporterConfigFromSIEM(cfg.WAF.SIEM)
	if expCfg.Endpoint == "" {
		return nil
	}

	exp, err := siem.NewExporter(expCfg)
	if err != nil {
		return nil
	}

	// Subscribe to the event bus. The exporter filters internally — only
	// block/challenge events are forwarded; pass events are silently dropped.
	startEventConsumer(eventBus, eventConsumerWG, 512, func(event engine.Event) {
		exp.Export(event)
	})

	if dash != nil {
		dash.SetSIEMStatsFn(func() any { return exp.Stats() })
	}

	return exp
}
