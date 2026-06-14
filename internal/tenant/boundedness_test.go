package tenant

import (
	"fmt"
	"testing"
	"time"
)

func TestManagerTenantAndDomainMapsStayBoundedAtMaxTenants(t *testing.T) {
	manager := NewManagerWithStore(2, t.TempDir())

	if _, err := manager.CreateTenant("Tenant One", "desc", []string{"one.example.com"}, nil); err != nil {
		t.Fatalf("CreateTenant one failed: %v", err)
	}
	if _, err := manager.CreateTenant("Tenant Two", "desc", []string{"two.example.com"}, nil); err != nil {
		t.Fatalf("CreateTenant two failed: %v", err)
	}
	if _, err := manager.CreateTenant("Tenant Three", "desc", []string{"three.example.com"}, nil); err == nil {
		t.Fatal("expected max tenant limit error")
	}

	if got := len(manager.tenants); got != 2 {
		t.Fatalf("tenant map size = %d, want 2", got)
	}
	if got := len(manager.domains); got != 2 {
		t.Fatalf("domain map size = %d, want 2", got)
	}
	if tenant := manager.GetTenantByDomain("three.example.com"); tenant != nil {
		t.Fatalf("rejected tenant domain was registered: %#v", tenant)
	}
}

func TestRateTrackerSlotsStayFixedUnderHighEventVolume(t *testing.T) {
	tracker := NewRateTracker(time.Minute)
	initialSlots := len(tracker.slots)

	for i := 0; i < initialSlots*10; i++ {
		tracker.Record()
	}

	if got := len(tracker.slots); got != initialSlots {
		t.Fatalf("slot count = %d, want fixed size %d", got, initialSlots)
	}
	if got := tracker.Count(); got > int64(initialSlots) {
		t.Fatalf("count = %d, want <= fixed slot count %d", got, initialSlots)
	}
}

func TestTenantRateLimiterCleanupBoundsTrackerMap(t *testing.T) {
	limiter := NewTenantRateLimiter(time.Minute)

	for i := 0; i < 10; i++ {
		limiter.Record(fmt.Sprintf("tenant-%d", i))
	}
	if got := len(limiter.trackers); got != 10 {
		t.Fatalf("tracker map size = %d, want 10 before cleanup", got)
	}

	time.Sleep(10 * time.Millisecond)
	limiter.Cleanup(time.Nanosecond)
	if got := len(limiter.trackers); got != 0 {
		t.Fatalf("tracker map size = %d, want 0 after cleanup", got)
	}
}
