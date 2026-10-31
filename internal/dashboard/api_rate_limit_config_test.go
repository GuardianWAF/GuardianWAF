package dashboard

import "testing"

func drainAPIBucket(d *Dashboard, ip string) int {
	allowed := 0
	for range 100000 {
		if !d.apiBucketAllow(ip) {
			break
		}
		allowed++
	}
	return allowed
}

func TestSetAPIRateLimit_DefaultBurst(t *testing.T) {
	d := newTestDashboard(t, "test-key-1234567890")
	got := drainAPIBucket(d, "192.0.2.1")
	if got < apiRateBurst || got > apiRateBurst+2 {
		t.Fatalf("default burst allowed %d requests, want about %d", got, apiRateBurst)
	}
}

func TestSetAPIRateLimit_RaisesBudget(t *testing.T) {
	d := newTestDashboard(t, "test-key-1234567890")
	d.SetAPIRateLimit(6000)
	got := drainAPIBucket(d, "192.0.2.2")
	if want := 6000 / 6; got < want || got > want+2 {
		t.Fatalf("limit 6000 allowed a burst of %d, want about %d", got, want)
	}
}

func TestSetAPIRateLimit_NonPositiveRestoresDefault(t *testing.T) {
	d := newTestDashboard(t, "test-key-1234567890")
	d.SetAPIRateLimit(6000)
	d.SetAPIRateLimit(-5)
	got := drainAPIBucket(d, "192.0.2.3")
	if got > apiRateBurst+2 {
		t.Fatalf("negative limit kept the raised budget: burst %d", got)
	}
}

func TestSetAPIRateLimit_NilReceiver(t *testing.T) {
	var d *Dashboard
	d.SetAPIRateLimit(10) // must not panic
}
