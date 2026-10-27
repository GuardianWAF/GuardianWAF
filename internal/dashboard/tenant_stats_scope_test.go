package dashboard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: /api/v1/stats is readable by tenant-scoped keys but returned
// the process-wide engine counters plus alerting and integration stats, so a
// tenant learned every other tenant's traffic and block volume.
func TestStatsAreTenantScopedForTenantKeys(t *testing.T) {
	d := newTestDashboard(t, "dash-key")
	d.extraStats = map[string]func() any{"cluster": func() any { return "operator-only" }}
	for i, e := range []struct {
		tenant string
		action engine.Action
	}{
		{"tenant-a", engine.ActionBlock}, {"tenant-a", engine.ActionPass}, {"tenant-a", engine.ActionPass},
		{"tenant-b", engine.ActionBlock}, {"tenant-b", engine.ActionBlock}, {"tenant-b", engine.ActionLog},
	} {
		if err := d.eventStore.Store(engine.Event{ID: fmt.Sprintf("e%d", i), TenantID: e.tenant, Action: e.action}); err != nil {
			t.Fatal(err)
		}
	}

	get := func(tenant string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
		if tenant != "" {
			req = setAuthInfo(req, authTenant, tenant)
		}
		w := httptest.NewRecorder()
		d.handleGetStats(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("stats for %q: status %d", tenant, w.Code)
		}
		return decodeJSON(t, w)
	}

	a := get("tenant-a")
	if a["total_requests"] != float64(3) || a["blocked_requests"] != float64(1) || a["passed_requests"] != float64(2) || a["logged_requests"] != float64(0) {
		t.Fatalf("tenant-a stats = %v, want 3 total / 1 blocked / 2 passed", a)
	}
	b := get("tenant-b")
	if b["total_requests"] != float64(3) || b["blocked_requests"] != float64(2) || b["logged_requests"] != float64(1) {
		t.Fatalf("tenant-b stats = %v, want 3 total / 2 blocked / 1 logged", b)
	}
	for _, key := range []string{"cluster", "alerting", "event_store_errors", "avg_latency_us"} {
		if _, ok := a[key]; ok {
			t.Errorf("tenant stats expose operator field %q", key)
		}
	}
	if global := get(""); global["cluster"] != "operator-only" {
		t.Fatalf("global stats lost extra stats: %v", global)
	}
}
