package main

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

func TestSyncCustomRulesToConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	rLayer := rules.NewLayer(&rules.Config{Enabled: true}, nil)
	rLayer.AddRule(rules.Rule{
		ID:       "r1",
		Name:     "test rule",
		Enabled:  true,
		Priority: 7,
		Conditions: []rules.Condition{
			{Field: "path", Op: "contains", Value: "/admin"},
		},
		Action: "block",
		Score:  80,
	})
	eng.AddLayer(engine.OrderedLayer{Layer: rLayer, Order: engine.OrderRules})

	syncCustomRulesToConfig(eng, cfg)

	if !cfg.WAF.CustomRules.Enabled {
		t.Fatal("expected custom rules to be enabled")
	}
	if got := len(cfg.WAF.CustomRules.Rules); got != 1 {
		t.Fatalf("expected 1 custom rule, got %d", got)
	}
	synced := cfg.WAF.CustomRules.Rules[0]
	if synced.ID != "r1" || synced.Name != "test rule" || synced.Action != "block" || synced.Score != 80 {
		t.Fatalf("unexpected synced rule: %+v", synced)
	}
	if got := len(synced.Conditions); got != 1 {
		t.Fatalf("expected 1 condition, got %d", got)
	}
	if synced.Conditions[0].Field != "path" || synced.Conditions[0].Op != "contains" || synced.Conditions[0].Value != "/admin" {
		t.Fatalf("unexpected synced condition: %+v", synced.Conditions[0])
	}
}

func TestLoadHTTPHandler(t *testing.T) {
	var value atomic.Value
	if got := loadHTTPHandler(&value); got != nil {
		t.Fatalf("expected nil handler before store, got %#v", got)
	}

	handler := http.NotFoundHandler()
	value.Store(handler)
	if got := loadHTTPHandler(&value); got == nil {
		t.Fatal("expected stored handler")
	}
}
