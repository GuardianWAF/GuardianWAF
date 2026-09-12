package main

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
)

// Regression (new-series round 3): mcpEngineAdapter.EnableCRSRule returned
// nil unconditionally over the void crs.Layer.EnableRule/DisableRule
// mutators — an unknown or typo'd rule ID produced fake success, and
// DisableRule wrote phantom disabledRules state for the unknown ID (state
// the engine's Process loop consults since the 2026-09-07 runtime-disable
// fix). The dashboard's CRS toggle got the same existence check in
// bug-hunt round 15 (crs_handlers.go); the MCP seam carries the identical
// contract: unknown rule IDs must error, not fake success.

func newCRSToggleHarness(t *testing.T) (*mcpEngineAdapter, *crs.Layer) {
	t.Helper()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	crsLayer := crs.NewLayer(&crs.Config{
		Enabled:       true,
		ParanoiaLevel: 1,
	})
	eng.AddLayer(engine.OrderedLayer{Layer: crsLayer, Order: engine.OrderCRS})
	return &mcpEngineAdapter{engine: eng, cfg: cfg}, crsLayer
}

func TestMCPCRSRuleToggleRejectsUnknownRule(t *testing.T) {
	adapter, crsLayer := newCRSToggleHarness(t)

	if err := adapter.EnableCRSRule("9.unknown", true); err == nil {
		t.Fatal("FAIL: EnableCRSRule returned nil for an unknown rule ID — fake success: the operator's enable switch silently does nothing")
	}
	if err := adapter.EnableCRSRule("9.unknown", false); err == nil {
		t.Fatal("FAIL: disable path returned nil for an unknown rule ID — fake success")
	}
	if !crsLayer.IsRuleEnabled("9.unknown") {
		t.Fatal("FAIL: unknown rule ID recorded in disabledRules — the fake-success disable wrote phantom toggle state the engine's Process loop consults")
	}
}
