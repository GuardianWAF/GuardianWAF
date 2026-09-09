package dashboard

// Regression: handleAnalyticsComparison left the previous window
//
// Defect (ledgered round 86, source-verified): handleAnalyticsComparison
// builds the "previous" window from optional previous_from/previous_to
// params only — when absent, the filter's Since/Until stay zero and the
// query returns ALL history, presented as the "previous" period. Every
// comparison delta is computed against an all-time denominator.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func TestAnalyticsComparisonPreviousWindowBounded(t *testing.T) {
	proxy.SetPrivateTargetsAllowed(true)
	eng := newTestEngine(t)

	now := time.Now()
	ms := events.NewMemoryStore(100)
	// Current window (analyticsEvents defaults to the last 24h): two events.
	for i := 0; i < 2; i++ {
		if err := ms.Store(engine.Event{Timestamp: now.Add(-time.Duration(i) * time.Hour), Action: engine.ActionBlock}); err != nil {
			t.Fatalf("store current event: %v", err)
		}
	}
	// One old event, 90 days back — outside any prior window of the current one.
	if err := ms.Store(engine.Event{Timestamp: now.Add(-90 * 24 * time.Hour), Action: engine.ActionBlock}); err != nil {
		t.Fatalf("store old event: %v", err)
	}

	d := New(eng, ms, "test-key")

	req := httptest.NewRequest("GET", "/api/v1/analytics/comparison", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("comparison returned %d: %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Current  map[string]any `json:"current"`
		Previous map[string]any `json:"previous"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid comparison body: %v", err)
	}

	// Bounded previous window (the aligned prior 24h): 0 events — both
	// recent events sit inside the current window and the old event is
	// 90 days back. The unbounded all-history query reports 3.
	prevTotal, _ := body.Previous["total"].(float64)
	if prevTotal != 0 {
		t.Fatalf("FAIL: comparison \"previous\" reports %v events with no previous_from/previous_to set — the previous filter is unbounded (Since/Until zero), so \"previous period\" actually means ALL history and every comparison delta is computed against the wrong denominator", prevTotal)
	}
}
