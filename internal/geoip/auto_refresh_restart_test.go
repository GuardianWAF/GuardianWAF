package geoip

import (
	"sync/atomic"
	"testing"
	"time"
)

// Regression (round 82): StartAutoRefreshWithContext's refresh loop recovered
// a panic but then EXITED — one panicking tick permanently killed GeoIP
// auto-refresh for the process lifetime while handle.done closed cleanly, so
// operators saw a healthy-looking handle over a dead loop. The loop now
// restarts after a recovered panic (the ai-analyzer/docker-watcher/
// acme-renewal convention), with a stop-aware backoff between restarts.

func TestAutoRefreshRestartsAfterPanic(t *testing.T) {
	prev := runRefreshTick
	t.Cleanup(func() { runRefreshTick = prev })

	var calls atomic.Int64
	var panicked atomic.Bool
	runRefreshTick = func(_ *DB, _ error, _, _ string) {
		calls.Add(1)
		if panicked.CompareAndSwap(false, true) {
			panic("simulated refresh panic")
		}
	}

	db := New()
	handle := db.StartAutoRefreshWithContext("/nonexistent-geoip-restart-test.csv", "", 5*time.Millisecond)
	defer handle.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			return // loop survived the panic and ticked again — restart works
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("refresh loop is dead after the first panicking tick — calls=%d, want >= 2 (recover must restart the loop, not exit it)", calls.Load())
}
