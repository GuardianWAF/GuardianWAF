package main

// Regression contract: the dashboard add-rule path must reject a duplicate
// rule ID instead of silently appending it. rules.Layer.AddRule appends
// unconditionally and Process scores every entry, so an accepted duplicate
// fires twice (double score → false-positive blocks) while Remove/Toggle/
// Update key on ID and only touch the FIRST match — the operator's delete
// leaves the shadow duplicate live and enabled.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

func TestDashboardRulesAddRejectsDuplicateID(t *testing.T) {
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	dash := dashboard.New(eng, store, "test-key")
	wireDashboardRules(dash, cfg, eng, &layerRuntimeResources{})

	srv := httptest.NewServer(dash.Handler())
	t.Cleanup(srv.Close)

	post := func(body string) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/rules", strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("X-API-Key", "test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /api/v1/rules: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	rule := `{"id":"dup-1","name":"probe","pattern":"sig-dup-1","action":"log","score":10}`

	// Control: the first add must succeed.
	if got := post(rule); got != http.StatusOK {
		t.Fatalf("first add: got %d, want 200", got)
	}

	// Contract: a duplicate ID must be rejected, not silently duplicated.
	if got := post(rule); got == http.StatusOK {
		t.Fatalf("FAIL: duplicate rule ID accepted with 200 — rules.Layer.AddRule appends " +
			"unconditionally, so the duplicate fires twice (double score → false-positive blocks) " +
			"and Remove/Toggle only touch the first copy while the shadow duplicate stays live")
	}

	// State: exactly one rule with the ID must exist.
	rl, ok := eng.FindLayer("rules").(*rules.Layer)
	if !ok {
		t.Fatal("rules layer not found after wiring")
	}
	count := 0
	for _, r := range rl.Rules() {
		if r.ID == "dup-1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("FAIL: %d rules with id dup-1 exist after one add + one rejected add, want 1", count)
	}
}
