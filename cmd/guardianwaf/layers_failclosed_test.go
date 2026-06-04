package main

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// newTestEngine builds an engine suitable for exercising addLayers.
func newTestEngine(t *testing.T, cfg *config.Config) *engine.Engine {
	t.Helper()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

// TestAddLayers_FailsClosedOnLayerBuildError verifies that an enabled security
// layer which cannot be built (here: CRS with an unloadable rule path) makes
// addLayers return an error, so serve refuses to start rather than silently
// running without that protection.
func TestAddLayers_FailsClosedOnLayerBuildError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.CRS.RulePath = "/nonexistent/path/to/crs/rules-xyz"

	if err := addLayers(newTestEngine(t, cfg), cfg); err == nil {
		t.Fatal("expected addLayers to fail closed on a layer build error; got nil")
	}
}

// TestAddLayers_DegradedStartOptOut verifies the explicit escape hatch: with
// GWAF_ALLOW_DEGRADED_START set, the same failure downgrades to a warning and
// addLayers returns nil so the operator can boot with reduced protection.
func TestAddLayers_DegradedStartOptOut(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.CRS.RulePath = "/nonexistent/path/to/crs/rules-xyz"

	t.Setenv("GWAF_ALLOW_DEGRADED_START", "1")
	if err := addLayers(newTestEngine(t, cfg), cfg); err != nil {
		t.Fatalf("expected degraded start to succeed with override set; got: %v", err)
	}
}

// TestAddLayers_HealthyConfigSucceeds is a guard that the happy path still wires
// cleanly (no false-positive fail-closed on a default config).
func TestAddLayers_HealthyConfigSucceeds(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := addLayers(newTestEngine(t, cfg), cfg); err != nil {
		t.Fatalf("expected default config to wire without error; got: %v", err)
	}
}
