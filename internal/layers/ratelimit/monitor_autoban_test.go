package ratelimit

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestMonitorObservesViolationsWithoutAutoBan(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Rules: []Rule{{ID: "test", Scope: "ip", Limit: 1, Burst: 1, Window: time.Hour, Action: "block", AutoBanAfter: 1}}})
	bans := 0
	layer.OnAutoBan = func(string, string) { bans++ }
	for range 3 {
		ctx := makeContext("192.0.2.1", "/")
		ctx.ObserveOnly = true
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}
	if bans != 0 {
		t.Fatal("monitor created an automatic ban")
	}
	ctx := makeContext("192.0.2.1", "/")
	defer engine.ReleaseContext(ctx)
	layer.Process(ctx)
	if bans != 1 {
		t.Fatalf("enforce control did not create ban: %d", bans)
	}
}
