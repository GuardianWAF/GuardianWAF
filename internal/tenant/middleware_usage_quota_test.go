package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: the tenant middleware performed quota checks but never called
// RecordUsage — the sole writer feeding the per-minute quota window
// (rateLimiter.Record), usage counters, request billing, and quota alerts.
// CheckQuota is read-only (Count() < limit), so the window stayed empty and
// Check always allowed: an operator's max_requests_per_minute quota silently
// never fired and usage metrics stayed at zero.
func TestMiddlewareRecordsUsageAndEnforcesPerMinuteQuota(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	quota.MaxRequestsPerMinute = 3
	ten, err := m.CreateTenant("usage-regression", "regression", []string{"usage-regression.test"}, &quota)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler := NewMiddleware(m).Handler(next)

	const total = 10
	allowed, limited := 0, 0
	for i := 0; i < total; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://usage-regression.test/resource", nil)
		req.Host = "usage-regression.test"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d on request %d", rec.Code, i+1)
		}
	}
	if allowed != 3 || limited != total-3 {
		t.Fatalf("quota enforcement = %d allowed / %d limited, want 3 allowed / %d x 429", allowed, limited, total-3)
	}

	// Secondary: usage counters advance now that RecordUsage is wired.
	usage := m.GetTenantUsage(ten.ID)
	if usage == nil || usage.TotalRequests == 0 {
		t.Fatalf("usage counters did not advance after %d requests (usage=%+v)", total, usage)
	}
}
