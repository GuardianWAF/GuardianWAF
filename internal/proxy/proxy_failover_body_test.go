package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Regression: the router's failover retry ran unconditionally after a proxy
// error. For unknown-length (chunked) and oversized bodies — which are
// streamed unbuffered per maxRetryBodyBytes — the error handler drains and
// closes r.Body, so the retried request carried an EMPTY body upstream and
// silently corrupted the upload at the healthy target. Fixed by gating the
// retry on body faithfulness (see router.go).

func failoverRouter(t *testing.T, abortURL, healthyURL string) *Router {
	t.Helper()
	t1, err := NewTargetWithPolicy(abortURL, 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTarget(abort): %v", err)
	}
	t2, err := NewTargetWithPolicy(healthyURL, 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTarget(healthy): %v", err)
	}
	bal := NewBalancer([]*Target{t1, t2}, "round_robin")
	return NewRouter([]Route{{PathPrefix: "/", Balancer: bal}})
}

func TestChunkedBodyNotCorruptedOnFailover(t *testing.T) {
	abort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // consume the upload first
		panic(http.ErrAbortHandler)        // transport failure: no response
	}))
	defer abort.Close()

	var calls atomic.Int32
	var gotBody atomic.Value
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	router := failoverRouter(t, abort.URL, healthy.URL)

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	req.ContentLength = -1 // chunked / unknown-length upload

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := calls.Load(); got != 0 {
		t.Fatalf("healthy target received a request on failover of an unknown-length upload (body=%q, calls=%d) — the consumed body was replayed; want no retry", gotBody.Load(), got)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (fail fast instead of corrupting)", rec.Code, http.StatusBadGateway)
	}
}

func TestBufferedFailoverReplaysBody(t *testing.T) {
	abort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		panic(http.ErrAbortHandler)
	}))
	defer abort.Close()

	var calls atomic.Int32
	var gotBody atomic.Value
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	router := failoverRouter(t, abort.URL, healthy.URL)

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	req.ContentLength = 5 // buffered failover budget

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := calls.Load(); got != 1 {
		t.Fatalf("buffered failover did not reach the healthy target (calls=%d)", got)
	}
	if got := gotBody.Load(); got != "hello" {
		t.Fatalf("buffered failover body = %q, want %q", got, "hello")
	}
}

func TestEmptyBodyFailoverStillReachesHealthyTarget(t *testing.T) {
	abort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler) // no body to consume; straight transport failure
	}))
	defer abort.Close()

	var calls atomic.Int32
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	router := failoverRouter(t, abort.URL, healthy.URL)

	req := httptest.NewRequest("GET", "/status", nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Empty bodies are faithfully replayable: failover must still work.
	if got := calls.Load(); got != 1 {
		t.Fatalf("empty-body failover did not reach the healthy target (calls=%d)", got)
	}
}
