package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// Regression (hunt round 4/25): mcpEngineAdapter.GetDLPAlerts hardcoded
// {"alerts": []} — the guardianwaf_get_dlp_alerts tool could never see a DLP
// detection even though the layer blocked it. Same seam contract family as
// EnableCRSRule (new-series round 3) and GetCSPReports (round 89): the MCP
// adapter must delegate to the layer's real state, not a constant.

func newDLPAlertsHarness(t *testing.T) (*mcpEngineAdapter, *dlp.Layer) {
	t.Helper()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	dcfg := dlp.DefaultConfig()
	dcfg.Enabled = true
	dcfg.BlockOnMatch = true
	dcfg.Patterns = []string{"credit_card"}
	dlpLayer := dlp.NewLayer(dcfg)
	eng.AddLayer(engine.OrderedLayer{Layer: dlpLayer, Order: engine.OrderDLP})
	if eng.FindLayer("dlp") != engine.Layer(dlpLayer) {
		t.Fatal("harness: FindLayer did not resolve the added dlp layer")
	}
	return &mcpEngineAdapter{engine: eng, cfg: cfg}, dlpLayer
}

func TestMCPGetDLPAlertsReturnsRecordedDetections(t *testing.T) {
	adapter, dlpLayer := newDLPAlertsHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/checkout",
		strings.NewReader(`{"card":"4111111111111111"}`))
	req.Header.Set("Content-Type", "application/json")
	if res := dlpLayer.Process(&engine.RequestContext{Request: req, Path: "/checkout"}); res.Action != engine.ActionBlock {
		t.Fatalf("precondition: Process action = %v, want block", res.Action)
	}

	out, err := adapter.GetDLPAlerts(50, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", out)
	}
	alerts, ok := m["alerts"].([]dlp.Alert)
	if !ok || len(alerts) != 1 {
		t.Fatalf("FAIL: MCP GetDLPAlerts returned %#v, want the recorded detection", m["alerts"])
	}
	if alerts[0].PatternType != "credit_card" || alerts[0].Action != "block" {
		t.Fatalf("FAIL: unexpected alert %+v", alerts[0])
	}
}
