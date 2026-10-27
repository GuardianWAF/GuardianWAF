package ato

// Regression (new-series round 9): the ATO layer gated EVERY protection —
// brute force, credential stuffing, password spray, impossible travel — on a
// login-path regex matched against the RAW wire path (ato.go Process:
// isLoginPath(ctx.Path)).
//
// ctx.Path is r.URL.Path: net/url resolves percent-escapes but never
// dot-segments, so "/x/../login" and "//login" reach the backend as "/login" —
// the reverse proxy cleans the path before forwarding it
// (internal/proxy/router.go:101,108) — while the raw-path regex does not match
// them. An alternate spelling of the login route therefore reached the real
// login endpoint with every ATO protection skipped, so the brute-force
// counter never advanced.
//
// This is the canonical-path contract the three sibling path-based layers
// already honour (rules.go, ratelimit.go, apisecurity.go), and the one
// rules.go states explicitly: "ctx.Path is r.URL.Path: net/url decodes
// percent-escapes but never resolves dot-segments, so '/admin/./panel' and
// '/x/../admin/panel' reach the backend as '/admin/panel'".
//
// The harness is production-shaped end to end:
//   client -> engine.Middleware (ATO layer, order 250) -> proxy.Router -> backend

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// loginCanonHarness wires the ATO layer in front of the real reverse proxy and
// a recording backend. It returns the WAF's base URL and the backend's
// observed request paths.
func loginCanonHarness(t *testing.T, loginPaths []string) (string, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var seen []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized) // the login attempt failed
	}))
	t.Cleanup(backend.Close)

	// The proxy's SSRF filter rejects loopback upstream targets; the package
	// exposes a test seam for exactly this. Restore the previous value.
	prevPrivate := proxy.PrivateTargetsAllowed()
	proxy.SetPrivateTargetsAllowed(true)
	t.Cleanup(func() { proxy.SetPrivateTargetsAllowed(prevPrivate) })

	target, err := proxy.NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatalf("proxy target: %v", err)
	}
	router := proxy.NewRouter([]proxy.Route{{
		PathPrefix: "/",
		Balancer:   proxy.NewBalancer([]*proxy.Target{target}, "round_robin"),
	}})

	layer, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: loginPaths,
		BruteForce: BruteForceConfig{
			Enabled:             true,
			Window:              time.Hour,
			MaxAttemptsPerIP:    2,
			MaxAttemptsPerEmail: 1000,
			BlockDuration:       time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	eng, err := engine.NewEngine(config.DefaultConfig(), events.NewMemoryStore(64), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderATO})
	t.Cleanup(func() { _ = eng.Close() })

	srv := httptest.NewServer(eng.Middleware(router))
	t.Cleanup(srv.Close)

	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

func loginCanonPost(t *testing.T, base, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader("email=user%40example.com&password=guess1"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// An alternate spelling of the login route must still be recognised as a login
// request, so the brute-force protection applies to it.
func TestATOLoginPathMatchesCanonicalPath(t *testing.T) {
	base, backendPaths := loginCanonHarness(t, []string{"/login"})

	codes := make([]int, 0, 3)
	for range 3 {
		codes = append(codes, loginCanonPost(t, base, "/x/../login"))
	}
	if codes[2] != http.StatusForbidden {
		t.Fatalf("three failed logins addressed as %q were answered %v — the last one should "+
			"have been blocked (403) by the brute-force protection; the ATO layer must match its "+
			"login-path regex against the canonical path as well as the raw one", "/x/../login", codes)
	}

	// The requests that were not blocked did reach the login endpoint: the
	// proxy forwarded them as "/login".
	paths := backendPaths()
	if len(paths) == 0 {
		t.Fatal("the backend never received the login request")
	}
	for _, p := range paths {
		if p != "/login" {
			t.Fatalf("the backend received %q, expected the cleaned login path %q", p, "/login")
		}
	}
}

// The canonical spelling keeps working — the control that keeps the test
// above from passing merely because brute-force detection is broken.
func TestATOLoginPathCanonicalSpellingStillProtected(t *testing.T) {
	base, _ := loginCanonHarness(t, []string{"/login"})

	codes := make([]int, 0, 3)
	for range 3 {
		codes = append(codes, loginCanonPost(t, base, "/login"))
	}
	if codes[2] != http.StatusForbidden {
		t.Fatalf("three failed logins to the canonical path were answered %v, want 403 at the "+
			"third — brute-force detection itself is broken", codes)
	}
}

// A route that is NOT a login path must not be pulled into the ATO
// protections, whatever spelling it is addressed with.
func TestATONonLoginPathIsNotProtected(t *testing.T) {
	base, _ := loginCanonHarness(t, []string{"/login"})

	for range 3 {
		if code := loginCanonPost(t, base, "/x/../public"); code == http.StatusForbidden {
			t.Fatal("a non-login route was treated as a login request and blocked; the canonical " +
				"path must only widen the login-path match to the routes the operator configured")
		}
	}
}
