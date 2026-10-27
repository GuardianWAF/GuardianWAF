package proxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestTarget_ForwardedHeaderHandling pins the forwarding headers the upstream
// receives. A behaviour change here must be reviewed, not silently accepted.
func TestTarget_ForwardedHeaderHandling(t *testing.T) {
	SetPrivateTargetsAllowed(true)

	cases := []struct {
		name      string
		trusted   []string
		tls       bool
		wantXFF   string
		wantProto string
	}{
		// Untrusted peer: its chain and scheme are client-forged and replaced.
		{"untrusted peer", nil, false, "203.0.113.55", "http"},
		{"untrusted peer over TLS", nil, true, "203.0.113.55", "https"},
		// Trusted fronting LB: the chain is extended and its scheme kept.
		{"trusted peer", []string{"203.0.113.0/24"}, false, "9.9.9.9, 203.0.113.55", "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			target, err := NewTargetWithPolicy(backend.URL, 1, TargetPolicy{
				AllowPrivateTargets: true,
				TrustedProxies:      ParseTrustedProxies(tc.trusted),
			})
			if err != nil {
				t.Fatalf("NewTargetWithPolicy: %v", err)
			}
			defer target.Close()

			req := httptest.NewRequest("GET", "http://waf.example/path", nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			req.RemoteAddr = "203.0.113.55:40000"
			req.Header.Set("X-Forwarded-For", "9.9.9.9")
			req.Header.Set("X-Forwarded-Proto", "https")
			// Client-injected headers that must NOT reach the backend.
			req.Header.Set("X-Forwarded-Host", "evil.example")
			req.Header.Set("X-Real-IP", "1.2.3.4")
			req.Header.Set("Forwarded", "for=1.2.3.4;proto=https")
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
			if gotHost != "waf.example" {
				t.Errorf("upstream Host = %q, want inbound host %q", gotHost, "waf.example")
			}
			for _, h := range []string{"X-Forwarded-Host", "X-Real-IP", "Forwarded"} {
				if v := got.Get(h); v != "" {
					t.Errorf("%s should be stripped before reaching upstream, got %q", h, v)
				}
			}
			if v := got.Get("X-Forwarded-For"); v != tc.wantXFF {
				t.Errorf("X-Forwarded-For = %q, want %q", v, tc.wantXFF)
			}
			if v := got.Get("X-Forwarded-Proto"); v != tc.wantProto {
				t.Errorf("X-Forwarded-Proto = %q, want %q", v, tc.wantProto)
			}
			if v := got.Get("X-Correlation-ID"); v != "rid-123" {
				t.Errorf("X-Correlation-ID should be propagated from X-GuardianWAF-RequestID, got %q", v)
			}
		})
	}
}
