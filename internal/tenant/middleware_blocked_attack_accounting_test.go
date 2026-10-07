package tenant

// Regression guard for the tenant middleware's blocked-attack accounting.
//
// tenantResponseWriter.WriteHeader used to record a blocked attack for every
// response status >= 400. Because RecordBlocked feeds billing as BlockedAttacks,
// and billing.go:33 documents PerBlockedAttackCost as "security value", an
// ordinary origin error — a 404 for a mistyped URL, a 400 from a client, a 500
// from a crashing upstream — was billed to the customer as an attack and
// surfaced to the dashboard as BlockedRequests.
//
// The WAF's own block status is 403 Forbidden (engine.go:660 and :671 for
// ActionBlock and the challenge-service fallback), and the engine maintains a
// separate, precise blockedRequests counter for that event.
//
// This file pins the corrected predicate: only 403 counts.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveTenantStatus runs one request through the real Middleware.Handler with
// an upstream that answers the given status, and returns the manager and the
// tenant it resolved to.
func serveTenantStatus(t *testing.T, domain string, status int) (*Manager, *Tenant) {
	t.Helper()
	mw := NewMiddleware(NewManager(10))
	tn, err := mw.manager.CreateTenant("Acme", "desc", []string{domain}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
	wrapped := mw.Handler(upstream)

	req := httptest.NewRequest(http.MethodGet, "http://"+domain+"/some/path", nil)
	req.Host = domain
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != status {
		t.Fatalf("harness: upstream status did not pass through, got %d want %d", rec.Code, status)
	}
	return mw.manager, tn
}

// Boundary: every origin application error must not be billed as an attack.
func TestTenantMiddleware_OriginErrorsAreNotBlockedAttacks(t *testing.T) {
	for i, tc := range []struct {
		name   string
		status int
	}{
		{"400 origin bad request", http.StatusBadRequest},
		{"401 origin unauthorized", http.StatusUnauthorized},
		{"404 origin not found", http.StatusNotFound},
		{"429 origin too many requests", http.StatusTooManyRequests},
		{"500 origin server error", http.StatusInternalServerError},
		{"502 upstream failure", http.StatusBadGateway},
		{"503 origin unavailable", http.StatusServiceUnavailable},
	} {
		mgr, tn := serveTenantStatus(t, "err"+string(rune('a'+i))+".example.com", tc.status)

		if tn.BlockedCount != 0 {
			t.Errorf("%s: BlockedCount = %d, want 0 — a %d from the origin is an "+
				"application error, not a WAF block", tc.name, tn.BlockedCount, tc.status)
		}
		if bm := mgr.BillingManager(); bm != nil {
			if u := bm.GetCurrentUsage(tn.ID); u != nil && u.BlockedAttacks != 0 {
				t.Errorf("%s: BlockedAttacks = %d, want 0 — benign origin errors must "+
					"not be billed as security value", tc.name, u.BlockedAttacks)
			}
		}
	}
}

// Control: the WAF's real block status must still be counted.
func TestTenantMiddleware_WafBlockStatusIsStillCounted(t *testing.T) {
	mgr, tn := serveTenantStatus(t, "blocked.example.com", http.StatusForbidden)

	if tn.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1 — a 403 WAF block is a blocked attack", tn.BlockedCount)
	}
	if bm := mgr.BillingManager(); bm != nil {
		if u := bm.GetCurrentUsage(tn.ID); u == nil || u.BlockedAttacks != 1 {
			t.Errorf("BlockedAttacks = %v, want 1 — the 403 block must stay billable", u)
		}
	}
}

// Successful traffic must never be counted as a block.
func TestTenantMiddleware_SuccessIsNotBlockedAttack(t *testing.T) {
	mgr, tn := serveTenantStatus(t, "ok.example.com", http.StatusOK)

	if tn.BlockedCount != 0 {
		t.Errorf("BlockedCount = %d, want 0 for a 200 response", tn.BlockedCount)
	}
	if bm := mgr.BillingManager(); bm != nil {
		if u := bm.GetCurrentUsage(tn.ID); u != nil && u.BlockedAttacks != 0 {
			t.Errorf("BlockedAttacks = %d, want 0 for a 200 response", u.BlockedAttacks)
		}
	}
	// The request itself must still be metered, otherwise the quota window
	// would starve (middleware.go records usage after ServeHTTP).
	if bm := mgr.BillingManager(); bm != nil {
		if u := bm.GetCurrentUsage(tn.ID); u != nil && u.Requests != 1 {
			t.Errorf("Requests = %d, want 1 — usage metering must be unaffected", u.Requests)
		}
	}
}

// The WriteHeader wrapper is idempotent: a repeated 403 counts once.
func TestTenantMiddleware_RepeatedWafBlockCountsOnce(t *testing.T) {
	mw := NewMiddleware(NewManager(10))
	tn, err := mw.manager.CreateTenant("Acme", "desc", []string{"dup.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	w := &tenantResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
		tenant:         tn,
		manager:        mw.manager,
	}

	w.WriteHeader(http.StatusForbidden)
	w.WriteHeader(http.StatusForbidden)

	if tn.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1 — a repeated WriteHeader must not double-count", tn.BlockedCount)
	}
}
