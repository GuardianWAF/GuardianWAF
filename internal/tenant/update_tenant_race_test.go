package tenant

import (
	"encoding/json"
	"sync"
	"testing"
)

// Regression (bug-hunt round 26): UpdateTenant published metadata fields
// (Name/Active/Quota/Domains/UpdatedAt) under m.mu only, while the request
// path reads those same fields under tenant.mu (CheckQuota, GetTenantUsage,
// sanitizeTenant). Two different mutexes establish no happens-before edge,
// so a dashboard update raced with live traffic. sanitizeTenant additionally
// returned Quota: &t.Quota, letting the JSON encoder dereference the field
// after its lock was released. The writers must publish under tenant.mu and
// the sanitized view must copy values that escape the critical section.
//
// Run under -race (the project gate): the writer/reader pairs below conflict
// on every iteration pre-fix and the detector aborts the run; post-fix it is
// a plain concurrent smoke test.

func TestUpdateTenantPublishesFieldsUnderTenantLock(t *testing.T) {
	m := NewManager(8)
	t.Cleanup(m.Close)

	tn, err := m.CreateTenant("race-proof", "", []string{"race.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: dashboard/admin path (PUT /api/v1/tenants/{id}).
	go func() {
		defer wg.Done()
		defer close(done)
		active := true
		quota := DefaultQuota()
		for i := 0; i < 300; i++ {
			active = !active
			quota.MaxRequestsPerMinute = int64(1000 + i)
			if err := m.UpdateTenant(tn.ID, &TenantUpdate{
				Name:    "race-proof-renamed",
				Active:  &active,
				Quota:   &quota,
				Domains: []string{"race.example.com", "race2.example.com"},
			}); err != nil {
				t.Errorf("UpdateTenant: %v", err)
				return
			}
		}
	}()

	// Reader: data-plane quota check + usage/sanitize surfaces.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = m.CheckQuota(tn)
			_ = m.GetTenantUsage(tn.ID)
			// sanitizeTenant + encode exercises the escaped Quota pointer
			// after the lock is released (the pre-fix second race facet).
			if b, err := json.Marshal(sanitizeTenant(tn)); err == nil && len(b) == 0 {
				t.Error("empty sanitized tenant JSON")
				return
			}
		}
	}()

	wg.Wait()

	// RegenerateAPIKey must publish UpdatedAt under tenant.mu too: hold a
	// sanitizeTenant+marshal reader against it. The reader deliberately
	// avoids m.mu-taking paths so it can run concurrently with the mutator's
	// m.mu critical section (exactly the pre-fix racing schedule).
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = json.Marshal(sanitizeTenant(tn))
			}
		}
	}()
	if _, err := m.RegenerateAPIKey(tn.ID); err != nil {
		t.Errorf("RegenerateAPIKey: %v", err)
	}
	close(stop)
	readerWG.Wait()
}
