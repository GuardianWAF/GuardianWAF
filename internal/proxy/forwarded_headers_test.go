package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTarget_ForwardedHeaderHandling pins the proxy's forwarding behaviour as
// observed by the upstream. It is a characterization test: it documents the
// CURRENT (httputil Director-based) behaviour so that the planned migration to
// ReverseProxy.Rewrite (Go 1.26 deprecated Director) can be proven not to change
// what the backend receives. If a future change alters any of these, that is a
// behaviour change that must be reviewed — not silently accepted.
func TestTarget_ForwardedHeaderHandling(t *testing.T) {
	SetPrivateTargetsAllowed(true)

	var (
		mu      sync.Mutex
		got     http.Header
		gotHost string
		reached bool
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		gotHost = r.Host
		reached = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}

	req := httptest.NewRequest("GET", "http://waf.example/path", nil)
	req.RemoteAddr = "203.0.113.55:40000"
	req.Header.Set("X-Forwarded-For", "9.9.9.9") // existing chain (e.g. from a fronting LB)
	// Client-injected headers that must NOT reach the backend.
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	// Correlation source the proxy should propagate.
	req.Header.Set("X-GuardianWAF-RequestID", "rid-123")

	rec := httptest.NewRecorder()
	if serveErr := target.ServeHTTP(rec, req, ""); serveErr != nil {
		t.Fatalf("ServeHTTP: %v", serveErr)
	}

	mu.Lock()
	defer mu.Unlock()
	if !reached {
		t.Fatal("backend was not reached")
	}

	// Inbound Host is preserved to the upstream (not rewritten to the target host).
	if gotHost != "waf.example" {
		t.Errorf("upstream Host = %q, want inbound host %q", gotHost, "waf.example")
	}

	// Client-injected proxy headers are stripped (defense-in-depth).
	for _, h := range []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		if v := got.Get(h); v != "" {
			t.Errorf("%s should be stripped before reaching upstream, got %q", h, v)
		}
	}

	// X-Forwarded-For appends the immediate peer IP to the existing chain.
	if v := got.Get("X-Forwarded-For"); v != "9.9.9.9, 203.0.113.55" {
		t.Errorf("X-Forwarded-For = %q, want %q", v, "9.9.9.9, 203.0.113.55")
	}

	// Correlation ID is propagated from X-GuardianWAF-RequestID when absent.
	if v := got.Get("X-Correlation-ID"); v != "rid-123" {
		t.Errorf("X-Correlation-ID should be propagated from X-GuardianWAF-RequestID, got %q", v)
	}
}
