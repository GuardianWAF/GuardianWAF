package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: ResourceQuota.MaxRequestsPerHour was never enforced — CheckQuota
// read only MaxRequestsPerMinute, so an operator's hourly quota (YAML
// max_requests_per_hour, default 500000, dashboard-editable) silently did
// nothing. CheckQuota now consults a 1-hour sliding window limiter, recorded
// per completed request alongside the per-minute one.
//
// Boundary pinned: MaxRequestsPerHour = 0 means unlimited (the > 0 guard must
// stay — TenantRateLimiter.Check treats limit <= 0 as its internal default,
// which would wrongly limit "unlimited" tenants).
func TestMiddlewareEnforcesHourlyQuota(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	quota.MaxRequestsPerMinute = 0 // disabled — isolate the hourly limit
	quota.MaxRequestsPerHour = 5
	if _, err := m.CreateTenant("hourly-regression", "regression", []string{"hourly-regression.test"}, &quota); err != nil {
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
		req := httptest.NewRequest(http.MethodGet, "http://hourly-regression.test/resource", nil)
		req.Host = "hourly-regression.test"
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
	if allowed != 5 || limited != total-5 {
		t.Fatalf("hourly quota enforcement = %d allowed / %d limited, want 5 allowed / %d x 429", allowed, limited, total-5)
	}
}

func TestHourlyQuotaZeroMeansUnlimited(t *testing.T) {
	m := NewManager(10)

	quota := DefaultQuota()
	quota.MaxRequestsPerMinute = 0
	quota.MaxRequestsPerHour = 0 // unlimited
	if _, err := m.CreateTenant("hourly-unlimited", "regression", []string{"hourly-unlimited.test"}, &quota); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := NewMiddleware(m).Handler(next)

	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://hourly-unlimited.test/resource", nil)
		req.Host = "hourly-unlimited.test"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d got %d — zero hourly quota must mean unlimited", i+1, rec.Code)
		}
	}
}
