package tenant

import (
	"testing"
	"time"
)

// Regression: AlertManager.dispatchLoop invoked registered handlers with no
// panic isolation. An unrecovered panic in ANY goroutine terminates the whole
// process, so one panicking handler took down the WAF data plane and stopped
// alert dispatch for every tenant. AlertHandler/RegisterHandler are exported
// extension points (embedders supply their own callbacks), and every other
// background loop in the codebase (manager broadcast, ai analyzer, docker
// watcher, tls certstore) recovers panics for the same reason.
//
// Boundary pinned: a panicking handler must be isolated per-invocation — the
// loop survives, later handlers for the same alert still run, and subsequent
// alerts (different type, dodging the per-(tenant,type) cooldown) still
// dispatch.
func TestDispatchLoopIsolatesPanickingHandler(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	panicked := make(chan struct{}, 1)
	good := make(chan *Alert, 8)

	am.RegisterHandler(func(a *Alert) {
		select {
		case panicked <- struct{}{}:
		default:
		}
		panic("alert handler boom")
	})
	am.RegisterHandler(func(a *Alert) {
		good <- a
	})

	am.TriggerAlert("iso-tenant", AlertSecurityEvent, AlertCritical, "iso", "isolation proof", nil)

	// The panicking handler must actually run (signal happens before the panic).
	select {
	case <-panicked:
	case <-time.After(2 * time.Second):
		t.Fatalf("panicking handler was never invoked — dispatch loop broken")
	}

	// The process survives; the good handler still receives the same alert.
	select {
	case a := <-good:
		if a.TenantID != "iso-tenant" {
			t.Fatalf("good handler got unexpected alert tenant %q", a.TenantID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("panicking alert handler killed the process/dispatch loop — good handler never received the alert")
	}

	// The loop remains alive for subsequent alerts (different type: the first
	// alert armed the per-(tenant,type) cooldown, and suppressing the repeat is
	// correct anti-spam behavior).
	am.TriggerAlert("iso-tenant", AlertRateLimit, AlertCritical, "iso-2", "second", nil)
	select {
	case a := <-good:
		if a.Message != "second" {
			t.Fatalf("second alert mismatch: %q", a.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("dispatch loop dead after panicking handler — second alert never delivered")
	}

	// Secondary: both alerts were recorded in the tenant's alert store.
	alerts := am.GetAlerts("iso-tenant", true)
	if len(alerts) != 2 {
		t.Fatalf("alert store has %d alerts, want 2", len(alerts))
	}
}
