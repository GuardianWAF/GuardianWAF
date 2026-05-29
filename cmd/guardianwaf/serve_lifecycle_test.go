package main

import (
	"sync/atomic"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

type stoppableThreatIntelLayer struct {
	cleanupTestLayer
	stopped atomic.Int32
}

func (l *stoppableThreatIntelLayer) Stop() {
	l.stopped.Add(1)
}

func TestCloseStopChannelIsIdempotent(t *testing.T) {
	ch := make(chan struct{})
	closeStopChannel(ch)
	closeStopChannel(ch)

	select {
	case <-ch:
	default:
		t.Fatal("expected channel to be closed")
	}
}

func TestCloseStopChannelNil(t *testing.T) {
	closeStopChannel(nil)
}

func TestStopThreatIntelCallsLayerStop(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	layer := &stoppableThreatIntelLayer{
		cleanupTestLayer: cleanupTestLayer{name: "threat_intel"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderThreatIntel})

	stopThreatIntel(eng)
	if layer.stopped.Load() != 1 {
		t.Fatalf("expected threat intel Stop to be called once, got %d", layer.stopped.Load())
	}
}

func TestLogServeRuntimeStatus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.WAF.Challenge.Enabled = true
	cfg.WAF.BotDetection.Enabled = true
	cfg.VirtualHosts = []config.VirtualHostConfig{{Domains: []string{"example.com"}}}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(10), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	logServeRuntimeStatus(cfg, eng)
}
