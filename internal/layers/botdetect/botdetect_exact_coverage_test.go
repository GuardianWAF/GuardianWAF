package botdetect

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayer_OrderAndCleanup(t *testing.T) {
	disabled := DefaultConfig()
	disabled.Behavior.Enabled = false
	disabledLayer := NewLayer(&disabled)
	if got := disabledLayer.Order(); got != engine.OrderBotDetect {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderBotDetect)
	}
	disabledLayer.Cleanup()

	enabled := DefaultConfig()
	enabled.Behavior.Window = time.Second
	enabledLayer := NewLayer(&enabled)
	enabledLayer.behavior.Record("stale", "/", false, time.Millisecond)
	enabledLayer.behavior.trackers["stale"].lastTick = time.Now().Add(-3 * time.Second)
	enabledLayer.Cleanup()
	if got := enabledLayer.behavior.TrackerCount(); got != 0 {
		t.Fatalf("tracker count after layer cleanup = %d, want 0", got)
	}
}

func TestBehaviorManager_FullSkipsNewTrackerAndRecord(t *testing.T) {
	bm := NewBehaviorManager(DefaultBehaviorConfig())
	bm.maxEntries = 1
	first := bm.getOrCreate("first")
	if first == nil {
		t.Fatal("expected first tracker")
	}
	if got := bm.getOrCreate("first"); got != first {
		t.Fatal("expected existing tracker to be reused")
	}
	if got := bm.getOrCreate("second"); got != nil {
		t.Fatal("expected full manager to reject a new tracker")
	}
	bm.Record("second", "/", false, time.Millisecond)
	if got := bm.TrackerCount(); got != 1 {
		t.Fatalf("tracker count = %d, want 1", got)
	}
}

func TestLayer_TenantDisablesBotDetection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)
	ctx := newTestContext("sqlmap/1.0", "10.0.0.1")
	ctx.TenantWAFConfig = &config.WAFConfig{
		BotDetection: config.BotDetectionConfig{Enabled: false},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass || result.Score != 0 || len(result.Findings) != 0 {
		t.Fatalf("tenant-disabled result = %+v, want an empty pass", result)
	}
}
