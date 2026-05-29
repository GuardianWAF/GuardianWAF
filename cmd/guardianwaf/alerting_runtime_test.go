package main

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

func TestAlertingWebhookTargets(t *testing.T) {
	targets := alertingWebhookTargets([]config.WebhookConfig{{
		Name:     "ops",
		URL:      "https://alerts.example.com/hook",
		Type:     "generic",
		Events:   []string{"block", "challenge"},
		MinScore: 40,
		Cooldown: 2 * time.Minute,
		Headers:  map[string]string{"X-Test": "yes"},
	}})

	if len(targets) != 1 {
		t.Fatalf("expected one target, got %d", len(targets))
	}
	target := targets[0]
	if target.Name != "ops" ||
		target.URL != "https://alerts.example.com/hook" ||
		target.Type != "generic" ||
		target.MinScore != 40 ||
		target.Cooldown != 2*time.Minute ||
		target.Headers["X-Test"] != "yes" ||
		len(target.Events) != 2 {
		t.Fatalf("unexpected target conversion: %+v", target)
	}
}

func TestSetupAlertingRuntimeDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Alerting.Enabled = false

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var wg sync.WaitGroup
	if mgr := setupAlertingRuntime(cfg, eng, events.NewEventBus(), events.NewMemoryStore(10), nil, &wg, nil, io.Discard); mgr != nil {
		t.Fatalf("expected nil manager when alerting is disabled, got %v", mgr)
	}
}

func TestSetupAlertingRuntimeEnabledStartsConsumer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Alerting.Enabled = true
	cfg.Alerting.Emails = []config.EmailConfig{{
		Name:     "ops",
		SMTPHost: "smtp.example.com",
		From:     "guardian@example.com",
		To:       []string{"ops@example.com"},
	}}
	cfg.MCP.Enabled = false

	store := events.NewMemoryStore(10)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	var wg sync.WaitGroup
	mgr := setupAlertingRuntime(cfg, eng, bus, store, nil, &wg, nil, io.Discard)
	if mgr == nil {
		t.Fatal("expected alerting manager")
	}
	stats := mgr.GetStats()
	if stats.EmailCount != 1 {
		t.Fatalf("expected one email target, got %d", stats.EmailCount)
	}

	bus.Close()
	wg.Wait()
	if err := mgr.CloseWithContext(t.Context()); err != nil {
		t.Fatalf("CloseWithContext error: %v", err)
	}
}
