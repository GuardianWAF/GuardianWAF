package tenant

import (
	"sync"
	"testing"
)

// Regression test: CheckQuotaAlert runs on the hot request path
// (RecordUsage -> CheckQuotaAlert) and reads tenant.Quota.MaxRequestsPerMinute,
// but did so without holding tenant.mu while UpdateTenant publishes Quota
// writes under tenant.mu (the round-26 lock protocol). Concurrent dashboard
// quota updates and live traffic therefore raced on the Quota field — the same
// class as the round-26 metadata race, missed because the round-26 reader
// hardening covered CheckQuota/GetTenantUsage/sanitizeTenant but not this
// path. The read must snapshot the quota under tenant.mu.RLock.
func TestCheckQuotaAlertReadsQuotaUnderPublicationLock(t *testing.T) {
	am := NewAlertManager()
	defer am.Close()

	tenant := &Tenant{ID: "t-quota-race", Active: true}
	tenant.Quota.MaxRequestsPerMinute = 100

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // the publication writer — UpdateTenant's pattern
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			tenant.mu.Lock()
			tenant.Quota.MaxRequestsPerMinute = int64(100 + i%50)
			tenant.mu.Unlock()
		}
		close(done)
	}()

	go func() { // the hot-path reader — RecordUsage's pattern
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				am.CheckQuotaAlert(tenant, 42)
			}
		}
	}()

	wg.Wait()
}

// NOTE (analysis, no test): Manager.AddTenantRule also reads
// tenant.Quota.MaxRules without tenant.mu, but its path acquires m.mu
// (Manager.GetTenant) after the writer's m.mu-held Quota write, so m.mu
// orders the accesses — race-free by the Go memory model, correctly silent
// under the detector. Only CheckQuotaAlert (no common lock with the writer)
// was a true race.
