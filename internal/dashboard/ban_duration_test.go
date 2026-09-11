package dashboard

// Regression tests for round 16/25: handleAddBan must reject malformed or
// non-positive ban durations. The pre-fix implementation silently replaced
// any parse error or non-positive ttl with a 1-hour default, and
// time.ParseDuration does not support "1d" — the most natural operator
// idiom for a day ban — so {"duration": "1d"} quietly banned for ONE hour
// while the operator believed it was 24h: a shorter-than-intended ban,
// fail-open for the protected asset. The sibling flows reject invalid
// durations (cluster_ban.go, clustersync's NewBanCommand). An omitted
// duration keeps the documented 1h default.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

type banDurationStub struct {
	mu    sync.Mutex
	calls []struct {
		ip     string
		reason string
		ttl    time.Duration
	}
}

func (s *banDurationStub) Name() string { return "ipacl" }
func (s *banDurationStub) Order() int   { return engine.OrderIPACL }
func (s *banDurationStub) Process(ctx *engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{}
}
func (s *banDurationStub) AddAutoBan(ip string, reason string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, struct {
		ip     string
		reason string
		ttl    time.Duration
	}{ip, reason, ttl})
}
func (s *banDurationStub) RemoveAutoBan(ip string) bool { return false }

func newBanDurationTestDashboard(t *testing.T) (*Dashboard, *banDurationStub) {
	t.Helper()
	stub := &banDurationStub{}
	cfg := &config.Config{Mode: "monitor", Listen: "127.0.0.1:0"}
	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1024), events.NewEventBus())
	if err != nil {
		t.Fatalf("engine setup: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: stub, Order: engine.OrderIPACL})
	return &Dashboard{engine: eng}, stub
}

func banDurationCalls(stub *banDurationStub) []time.Duration {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	out := make([]time.Duration, 0, len(stub.calls))
	for _, c := range stub.calls {
		out = append(out, c.ttl)
	}
	return out
}

func postBanBody(t *testing.T, d *Dashboard, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bans", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handleAddBan(rec, req)
	return rec
}

func TestBanDurationMalformedRejected(t *testing.T) {
	// "1d" is not a valid Go duration; the handler must reject it instead of
	// silently substituting the 1-hour default.
	d, stub := newBanDurationTestDashboard(t)

	rec := postBanBody(t, d, `{"ip":"10.0.0.9","reason":"proof","duration":"1d"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed duration %q answered HTTP %d with body %q (AddAutoBan calls: %v) — want 400; silently banning for 1h shortens the operator's intended day-long ban", "1d", rec.Code, rec.Body.String(), banDurationCalls(stub))
	}
	if calls := banDurationCalls(stub); len(calls) != 0 {
		t.Fatalf("rejected request must not apply the ban, got AddAutoBan calls: %v", calls)
	}
}

func TestBanDurationNonPositiveRejected(t *testing.T) {
	d, stub := newBanDurationTestDashboard(t)

	rec := postBanBody(t, d, `{"ip":"10.0.0.9","reason":"proof","duration":"-5m"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-positive duration %q answered HTTP %d (AddAutoBan calls: %v) — want 400", "-5m", rec.Code, banDurationCalls(stub))
	}
	if calls := banDurationCalls(stub); len(calls) != 0 {
		t.Fatalf("rejected request must not apply the ban, got AddAutoBan calls: %v", calls)
	}
}

func TestBanDurationValidStillApplied(t *testing.T) {
	d, stub := newBanDurationTestDashboard(t)

	rec := postBanBody(t, d, `{"ip":"10.0.0.9","reason":"proof","duration":"30m"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid 30m duration answered HTTP %d, want 200", rec.Code)
	}
	calls := banDurationCalls(stub)
	if len(calls) != 1 || calls[0] != 30*time.Minute {
		t.Fatalf("AddAutoBan calls = %v, want one call with ttl=30m", calls)
	}
}

func TestBanDurationOmittedKeepsDefault(t *testing.T) {
	d, stub := newBanDurationTestDashboard(t)

	rec := postBanBody(t, d, `{"ip":"10.0.0.9","reason":"proof"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("omitted duration answered HTTP %d, want 200 (documented 1h default)", rec.Code)
	}
	calls := banDurationCalls(stub)
	if len(calls) != 1 || calls[0] != time.Hour {
		t.Fatalf("AddAutoBan calls = %v, want one call with ttl=1h", calls)
	}
}
