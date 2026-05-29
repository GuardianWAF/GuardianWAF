package main

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestDashboardRulesLayer_CreatesAndReusesLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	first := dashboardRulesLayer(eng)
	if first == nil {
		t.Fatal("expected rules layer")
	}
	if got := eng.FindLayer("rules"); got != first {
		t.Fatal("expected created rules layer to be added to engine")
	}

	second := dashboardRulesLayer(eng)
	if second != first {
		t.Fatal("expected existing rules layer to be reused")
	}
}

func TestLookupDashboardGeoIP_EmptyAndInvalidInputs(t *testing.T) {
	if code, name := lookupDashboardGeoIP(nil, "127.0.0.1"); code != "" || name != "GeoIP not loaded" {
		t.Fatalf("expected GeoIP not loaded, got code=%q name=%q", code, name)
	}
	if code, name := lookupDashboardGeoIP(nil, "not-an-ip"); code != "" || name != "GeoIP not loaded" {
		t.Fatalf("nil db should take precedence, got code=%q name=%q", code, name)
	}
}
