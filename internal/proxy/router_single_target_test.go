package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression: a single-target route returned a silent empty 200 on upstream
// failure. Target's ErrorHandler writes nothing by design (its silence keeps
// multi-target failover retries from double-writing a committed response),
// and Router.ServeHTTP's single-target early return (proxyErr != nil with
// Balancer.Len() <= 1) wrote no fallback either — so the client got 200 OK
// with an empty body from a dead upstream. The single-target path now writes
// 502 Bad Gateway, matching every other failure branch.
func TestRouterSingleTargetUpstreamFailureReturns502(t *testing.T) {
	oldAllowed := PrivateTargetsAllowed()
	SetPrivateTargetsAllowed(true)
	t.Cleanup(func() { SetPrivateTargetsAllowed(oldAllowed) })

	// Nothing listens on port 1 — dial gets an instant connection refused.
	target, err := NewTarget("http://127.0.0.1:1", 1)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	router := NewRouter([]Route{{
		PathPrefix: "/",
		Balancer:   NewBalancer([]*Target{target}, ""),
	}})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("single-target upstream failure: got %d with body %q, want 502 — silent empty 200 regression", rec.Code, rec.Body.String())
	}
}

// Control: the multi-target exhausted-retries path already wrote 502 before
// the fix and must keep doing so.
func TestRouterMultiTargetUpstreamFailureReturns502(t *testing.T) {
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
	router := NewRouter([]Route{{
		PathPrefix: "/",
		Balancer:   NewBalancer([]*Target{t1, t2}, ""),
	}})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("multi-target exhausted retries: got %d, want 502", rec.Code)
	}
}
