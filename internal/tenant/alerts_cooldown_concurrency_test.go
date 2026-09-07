package tenant

import (
	"sync"
	"testing"
	"time"
)

// Regression test: TriggerAlert's cooldown check was a check-then-act race —
// the cooldown test ran under RLock and the write-lock section re-checked
// only `closed`, so N concurrent triggers with the same tenantID:type key all
// passed and all stored + dispatched an alert (duplicate notifications; the
// production call site is RecordUsage -> CheckQuotaAlert on every request).
// The authoritative cooldown check now holds the write lock across
// check-and-set: exactly ONE alert per cooldown key per window.

func TestAlertManager_TriggerAlert_ConcurrentCooldown(t *testing.T) {
	const goroutines = 32
	const rounds = 5

	for round := 0; round < rounds; round++ {
		am := NewAlertManager()
		defer am.Close()

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(goroutines)
		nonNil := 0
		var mu sync.Mutex
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				<-start
				if alert := am.TriggerAlert("tenant-1", AlertQuotaExceeded, AlertCritical, "Quota Exceeded", "burst", nil); alert != nil {
					mu.Lock()
					nonNil++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()

		// Exactly one trigger wins the cooldown window; the rest are suppressed.
		if nonNil != 1 {
			t.Fatalf("round %d: %d/%d concurrent triggers stored an alert; want exactly 1", round+1, nonNil, goroutines)
		}
		if stored := len(am.GetAlerts("tenant-1", true)); stored != 1 {
			t.Fatalf("round %d: %d alerts stored; want exactly 1", round+1, stored)
		}

		// The winner armed the cooldown: a follow-up trigger inside the window
		// must still be suppressed.
		if alert := am.TriggerAlert("tenant-1", AlertQuotaExceeded, AlertCritical, "Quota Exceeded", "after burst", nil); alert != nil {
			t.Fatalf("round %d: trigger inside cooldown after burst returned an alert; want nil", round+1)
		}
	}
}

// TestAlertManager_TriggerAlert_DistinctKeysIndependent guards the secondary
// branch: the cooldown is keyed per tenantID:type — a suppressed alert for
// one key must not suppress a different key.
func TestAlertManager_TriggerAlert_DistinctKeysIndependent(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	if alert := am.TriggerAlert("t1", AlertQuotaExceeded, AlertCritical, "T", "M", nil); alert == nil {
		t.Fatal("first trigger for t1 returned nil; want alert")
	}
	// Same tenant, different type: independent cooldown key.
	if alert := am.TriggerAlert("t1", AlertQuotaWarning, AlertWarning, "T", "M", nil); alert == nil {
		t.Fatal("trigger for t1/quota_warning was suppressed by t1/quota_exceeded cooldown; want alert")
	}
	// Different tenant, same type: independent cooldown key.
	if alert := am.TriggerAlert("t2", AlertQuotaExceeded, AlertCritical, "T", "M", nil); alert == nil {
		t.Fatal("trigger for t2 was suppressed by t1 cooldown; want alert")
	}

	// Cooldowns expire: with a tiny window, the same key triggers again.
	fast := NewAlertManager()
	fast.cooldownDur = 5 * time.Millisecond
	defer fast.Close()
	if alert := fast.TriggerAlert("t3", AlertRateLimit, AlertWarning, "T", "M", nil); alert == nil {
		t.Fatal("first trigger returned nil; want alert")
	}
	time.Sleep(10 * time.Millisecond)
	if alert := fast.TriggerAlert("t3", AlertRateLimit, AlertWarning, "T", "M", nil); alert == nil {
		t.Fatal("trigger after cooldown expiry returned nil; want alert")
	}
}
