package proxy

import (
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Regression (round 68): Router.ServeHTTP's multi-target failover skipped
// already-tried targets by consuming retry budget AFTER selection, but the
// deterministic strategies re-select the same failed target on every call —
// least_conn tie-breaks to the first healthy target once its active
// connections drop back to zero, and ip_hash maps the same client IP to the
// same target — so failover never reached the healthy sibling and the client
// got 502 despite an available backend. The retry loop now selects via
// Balancer.NextExcluding, which enforces "not already tried" inside the
// selector.

// failoverFixture builds a least-conn-orderable [dead, healthy] pair: the dead
// target occupies the position every deterministic selector picks first.
func failoverFixture(t *testing.T) (dead, healthy *Target, healthyHits *atomic.Int64) {
	t.Helper()
	oldAllowed := PrivateTargetsAllowed()
	SetPrivateTargetsAllowed(true)
	t.Cleanup(func() { SetPrivateTargetsAllowed(oldAllowed) })

	healthyHits = &atomic.Int64{}
	healthySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyHits.Add(1)
		body, _ := readBodyForTest(r)
		_, _ = w.Write([]byte("served-by-healthy:" + body))
	}))
	t.Cleanup(healthySrv.Close)

	// Nothing listens on port 1 — dial gets an instant connection refused.
	var err error
	dead, err = NewTarget("http://127.0.0.1:1", 1)
	if err != nil {
		t.Fatalf("NewTarget dead: %v", err)
	}
	healthy, err = NewTarget(healthySrv.URL, 1)
	if err != nil {
		t.Fatalf("NewTarget healthy: %v", err)
	}
	return dead, healthy, healthyHits
}

func readBodyForTest(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return string(buf[:n]), nil
}

func serveThroughRouter(t *testing.T, strategy string, dead, healthy *Target, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	router := NewRouter([]Route{{
		PathPrefix: "/",
		Balancer:   NewBalancer([]*Target{dead, healthy}, strategy),
	}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

func TestRouterFailoverLeastConnTriesHealthySibling(t *testing.T) {
	dead, healthy, hits := failoverFixture(t)

	rec := serveThroughRouter(t, StrategyLeastConn, dead, healthy,
		httptest.NewRequest(http.MethodGet, "/anything", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "served-by-healthy") {
		t.Fatalf("least_conn failover: got %d %q with %d healthy hits, want the healthy sibling to serve the request", rec.Code, rec.Body.String(), hits.Load())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("least_conn failover: healthy backend served %d requests, want 1", got)
	}
}

func TestRouterFailoverIPHashTriesHealthySibling(t *testing.T) {
	dead, healthy, hits := failoverFixture(t)

	// httptest.NewRequest defaults RemoteAddr to 192.0.2.1:1234; mirror the
	// production hash (host without port) and put the dead target in the slot
	// the sticky hash picks, so the first attempt — and every pre-fix retry —
	// lands on it.
	h := fnv.New32a()
	_, _ = h.Write([]byte("192.0.2.1")) // fnv.Write never returns a non-nil error
	deadFirst := h.Sum32()%2 == 0
	targets := []*Target{dead, healthy}
	if !deadFirst {
		targets = []*Target{healthy, dead}
	}

	router := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer(targets, StrategyIPHash)}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "served-by-healthy") {
		t.Fatalf("ip_hash failover: got %d %q with %d healthy hits, want the healthy sibling to serve the request", rec.Code, rec.Body.String(), hits.Load())
	}
}

// Weighted with a heavy dead target is the case a post-selection skip loop can
// never fix: the smooth weighted counter lands inside the dead target's 100-slot
// band for the whole retry budget. Exclusion at the selector is what reaches the
// weight-1 sibling.
func TestRouterFailoverWeightedSkewTriesHealthySibling(t *testing.T) {
	_, healthy, hits := failoverFixture(t)
	oldAllowed := PrivateTargetsAllowed()
	SetPrivateTargetsAllowed(true)
	t.Cleanup(func() { SetPrivateTargetsAllowed(oldAllowed) })
	dead, err := NewTarget("http://127.0.0.1:1", 100)
	if err != nil {
		t.Fatalf("NewTarget dead: %v", err)
	}

	rec := serveThroughRouter(t, StrategyWeighted, dead, healthy,
		httptest.NewRequest(http.MethodGet, "/anything", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "served-by-healthy") {
		t.Fatalf("weighted-skew failover: got %d %q with %d healthy hits, want the healthy sibling to serve the request", rec.Code, rec.Body.String(), hits.Load())
	}
}

// Interaction with the round-25 body-replay contract: a small buffered body
// must be replayed faithfully to the failover target (the ErrorHandler drains
// and closes the consumed body on the failed attempt).
func TestRouterFailoverLeastConnReplaysBufferedBody(t *testing.T) {
	dead, healthy, hits := failoverFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/anything", strings.NewReader("hello-replay"))
	rec := serveThroughRouter(t, StrategyLeastConn, dead, healthy, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "served-by-healthy:hello-replay") {
		t.Fatalf("buffered-body failover: got %d %q, want the body replayed to the healthy sibling", rec.Code, rec.Body.String())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("buffered-body failover: healthy backend served %d requests, want 1", got)
	}
}

// Boundary: when every healthy target has been tried, NextExcluding returns nil
// and the retry loop must terminate with 502 (the exhausted-retries contract).
func TestRouterFailoverAllTargetsExhaustedReturns502(t *testing.T) {
	oldAllowed := PrivateTargetsAllowed()
	SetPrivateTargetsAllowed(true)
	t.Cleanup(func() { SetPrivateTargetsAllowed(oldAllowed) })

	t1, err := NewTarget("http://127.0.0.1:1", 1)
	if err != nil {
		t.Fatalf("NewTarget t1: %v", err)
	}
	t2, err := NewTarget("http://127.0.0.1:2", 1)
	if err != nil {
		t.Fatalf("NewTarget t2: %v", err)
	}

	rec := serveThroughRouter(t, StrategyLeastConn, t1, t2,
		httptest.NewRequest(http.MethodGet, "/anything", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("least_conn exhausted retries: got %d, want 502", rec.Code)
	}
}
