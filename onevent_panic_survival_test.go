package guardianwaf

// Regression (2026-09-28-onevent-panic-kills-pump): OnEvent's panic recovery
// sat at goroutine scope, so ONE panic in the user callback permanently
// killed the event pump — the recover logged, the goroutine exited through
// the range loop, and the channel stayed subscribed on the bus with nobody
// draining it. EventBus.Publish drops on full channels, so every subsequent
// event for that subscriber was silently lost until engine Close. The
// recovery now happens per event (the dispatchOne pattern) and the pump
// survives.

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnEvent_PanicSurvivesPump(t *testing.T) {
	e, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults: %v", err)
	}
	defer e.Close()

	// Defect subscriber: panics on the first event (arbitrary user code).
	var delivered atomic.Int64
	e.OnEvent(func(_ Event) {
		if delivered.Add(1) == 1 {
			panic("deterministic user-callback bug")
		}
	})

	// Control subscriber: a healthy callback keeps receiving events.
	var control atomic.Int64
	e.OnEvent(func(_ Event) { control.Add(1) })

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	for i := 0; i < 5; i++ {
		e.Check(req) // synchronous: publishes one event per call
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (delivered.Load() < 5 || control.Load() < 5) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := delivered.Load(); got != 5 {
		t.Fatalf("panicking callback degraded event delivery: delivered=%d/5", got)
	}
	if ctrl := control.Load(); ctrl != 5 {
		t.Fatalf("control subscriber lost events: %d/5", ctrl)
	}
}

// A callback that panics on EVERY event must not starve other subscribers:
// per-invocation recovery keeps the pump draining its channel.
func TestOnEvent_AlwaysPanickingCallbackDoesNotBlockOthers(t *testing.T) {
	e, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults: %v", err)
	}
	defer e.Close()

	e.OnEvent(func(_ Event) { panic("always panics") })

	var control atomic.Int64
	e.OnEvent(func(_ Event) { control.Add(1) })

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	for i := 0; i < 5; i++ {
		e.Check(req)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && control.Load() < 5 {
		time.Sleep(20 * time.Millisecond)
	}
	if ctrl := control.Load(); ctrl != 5 {
		t.Fatalf("always-panicking callback starved the control subscriber: %d/5", ctrl)
	}
}
