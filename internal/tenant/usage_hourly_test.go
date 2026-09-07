package tenant

import (
	"testing"
)

// Regression: UsageStats.RequestsPerHour (json:"requests_per_hour") was
// declared in the API contract but never populated — Manager.GetTenantUsage
// read only rateLimiter.Count for the per-minute figure, so the dashboard's
// tenant usage view always reported requests_per_hour: 0 while the hourly
// quota (Manager.hourLimiter, enforced by CheckQuota) silently counted.
// GetTenantUsage now reads hourLimiter.Count alongside rateLimiter.Count;
// GetAllUsage delegates to GetTenantUsage.
func TestGetTenantUsagePopulatesRequestsPerHour(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("usage-hourly", "regression", []string{"usage-hourly.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	const total = 7
	for i := 0; i < total; i++ {
		m.RecordUsage(ten, 100)
	}

	stats := m.GetTenantUsage(ten.ID)
	if stats == nil {
		t.Fatalf("GetTenantUsage returned nil for existing tenant %s", ten.ID)
	}
	if stats.RequestsPerMinute != total {
		t.Fatalf("requests_per_minute = %d, want %d (control: RecordUsage accounting broken)", stats.RequestsPerMinute, total)
	}
	if stats.RequestsPerHour != total {
		t.Fatalf("requests_per_hour = %d, want %d (field not populated from hourLimiter)", stats.RequestsPerHour, total)
	}
}

// Boundary: a tenant with zero recorded usage must report zeros in BOTH
// counters — distinguishing "field populated, count is 0" from "field never
// populated".
func TestGetTenantUsageZeroUsageReportsZeroedCounters(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("usage-zero", "regression", []string{"usage-zero.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	stats := m.GetTenantUsage(ten.ID)
	if stats == nil {
		t.Fatalf("GetTenantUsage returned nil for existing tenant %s", ten.ID)
	}
	if stats.RequestsPerMinute != 0 || stats.RequestsPerHour != 0 {
		t.Fatalf("zero-usage tenant reported rpm=%d rph=%d, want 0/0", stats.RequestsPerMinute, stats.RequestsPerHour)
	}
}

// GetAllUsage must reflect the same per-tenant figures through its
// delegation to GetTenantUsage.
func TestGetAllUsageIncludesHourlyCounts(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	ten, err := m.CreateTenant("usage-all", "regression", []string{"usage-all.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	const total = 4
	for i := 0; i < total; i++ {
		m.RecordUsage(ten, 64)
	}

	all := m.GetAllUsage()
	found := false
	for _, stats := range all {
		if stats.TenantID == ten.ID {
			found = true
			if stats.RequestsPerHour != total {
				t.Fatalf("GetAllUsage requests_per_hour = %d, want %d", stats.RequestsPerHour, total)
			}
		}
	}
	if !found {
		t.Fatalf("GetAllUsage missing tenant %s", ten.ID)
	}
}
