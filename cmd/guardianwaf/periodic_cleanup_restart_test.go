package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// Regression (new-series round 4): startPeriodicCleanup recovered a panicking
// runPeriodicCleanup and then the goroutine EXITED — the periodic janitors
// (rate-limit stale buckets, expired IPACL entries, ATO/botdetect state,
// tenant rate-limiter cleanup) stopped running for the process lifetime while
// the server kept serving. The consumer/analyzer/watcher restart pattern
// applies here too: recover, and keep the ticker loop alive; exit only when
// cleanupStop closes.

type panickyCleanupLayer struct {
	panicked atomic.Bool
	calls    atomic.Int64
}

func (p *panickyCleanupLayer) Name() string { return "ratelimit" }
func (p *panickyCleanupLayer) Order() int   { return engine.OrderRateLimit }
func (p *panickyCleanupLayer) Process(_ *engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{Action: engine.ActionPass}
}
func (p *panickyCleanupLayer) CleanupExpired(time.Duration) {
	if p.panicked.CompareAndSwap(false, true) {
		panic("boom: stale bucket scan exploded")
	}
	p.calls.Add(1)
}

func TestPeriodicCleanupSurvivesPanickingLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(100), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	pl := &panickyCleanupLayer{}
	eng.AddLayer(engine.OrderedLayer{Layer: pl, Order: engine.OrderRateLimit})

	stop, wg := startPeriodicCleanup(eng, nil, 20*time.Millisecond)

	// ~10 ticks at a 20ms interval. The layer panics on its FIRST cleanup and
	// succeeds on every later one, so a live loop advances the counter past 1;
	// a dead loop freezes it at exactly 1.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pl.calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(stop)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup goroutine did not stop after cleanupStop")
	}

	if got := pl.calls.Load(); got < 2 {
		t.Fatalf("FAIL: periodic cleanup loop died on the first panicking layer call (calls=%d, want >= 2) — every janitor (rate-limit stale buckets, expired IPACL entries, ATO/botdetect state, tenant rate-limiter cleanup) is dead for the process lifetime", got)
	}
}
