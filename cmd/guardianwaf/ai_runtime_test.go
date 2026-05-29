package main

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

type recordingEventSubscriber struct {
	channels []chan<- engine.Event
}

func (s *recordingEventSubscriber) Subscribe(ch chan<- engine.Event) {
	s.channels = append(s.channels, ch)
}

func TestAIAnalyzerConfigMapsRuntimeConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.AIAnalysis.BatchSize = 7
	cfg.WAF.AIAnalysis.BatchInterval = 2 * time.Second
	cfg.WAF.AIAnalysis.MaxTokensPerHour = 101
	cfg.WAF.AIAnalysis.MaxTokensPerDay = 202
	cfg.WAF.AIAnalysis.MaxRequestsHour = 3
	cfg.WAF.AIAnalysis.AutoBlock = true
	cfg.WAF.AIAnalysis.AutoBlockTTL = 4 * time.Minute
	cfg.WAF.AIAnalysis.MinScore = 55

	got := aiAnalyzerConfig(cfg)
	if !got.Enabled ||
		got.BatchSize != 7 ||
		got.BatchInterval != 2*time.Second ||
		got.MaxTokensHour != 101 ||
		got.MaxTokensDay != 202 ||
		got.MaxRequestsHour != 3 ||
		!got.AutoBlockEnabled ||
		got.AutoBlockTTL != 4*time.Minute ||
		got.MinScoreForAI != 55 {
		t.Fatalf("unexpected analyzer config: %+v", got)
	}
}

func TestSetupAIRuntimeDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.AIAnalysis.Enabled = false

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	subscriber := &recordingEventSubscriber{}
	if analyzer := setupAIRuntime(cfg, eng, subscriber, nil); analyzer != nil {
		t.Fatalf("expected nil analyzer when AI analysis is disabled, got %v", analyzer)
	}
	if len(subscriber.channels) != 0 {
		t.Fatalf("disabled AI runtime subscribed %d channels", len(subscriber.channels))
	}
}

func TestSetupAIRuntimeEnabledSubscribesAndStarts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.AIAnalysis.Enabled = true
	cfg.WAF.AIAnalysis.StorePath = t.TempDir()
	cfg.WAF.AIAnalysis.BatchInterval = time.Hour
	cfg.Dashboard.APIKey = "strong-dashboard-api-key-for-ai-runtime-test"

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	subscriber := &recordingEventSubscriber{}
	analyzer := setupAIRuntime(cfg, eng, subscriber, nil)
	if analyzer == nil {
		t.Fatal("expected analyzer when AI analysis is enabled")
	}
	defer analyzer.Stop()
	if len(subscriber.channels) != 1 {
		t.Fatalf("expected one AI event subscription, got %d", len(subscriber.channels))
	}
}
