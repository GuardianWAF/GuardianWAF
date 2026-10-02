package proxy

// Regression: a health probe must include the target's base path.
//
// HealthChecker.check built the probe URL from t.URL.Host + hc.path, never
// including t.URL.Path. The reverse proxy does the opposite: Rewrite calls
// pr.SetURL(u), which PREPENDS the target's base path to the forwarded request.
// The two disagreed for any upstream configured with a path, e.g.
// "http://backend:8080/api":
//
//	proxied  -> /api/foo        (correct, backend mounts its app under /api)
//	probed   -> /healthz        (wrong prefix — backend answers 404)
//
// A 404 made check() return false, checkAll call SetHealthy(false), and every
// later load-balancing pass see IsHealthy() == false and skip the target. A
// healthy, correctly configured upstream was therefore dropped permanently and
// its traffic got 503, with nothing but an ordinary "unhealthy" in the log.
//
// Reachable: validateUpstreamTargetURL (internal/config/validate.go) validates
// only the scheme and the host, so an upstream URL carrying a path loads fine.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// basePathBackend serves only under /api and 404s everything else — the shape
// of an application mounted behind a path prefix.
func basePathBackend(t *testing.T, proxied *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if proxied != nil {
				*proxied = append(*proxied, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// probeOnce runs one real health probe against target.
func probeOnce(t *testing.T, target *Target, path string) bool {
	t.Helper()
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{Path: path, Interval: time.Hour})
	return hc.check(context.Background(), target)
}

func TestHealthCheckPreservesTargetBasePath(t *testing.T) {
	backend := basePathBackend(t, nil)
	defer backend.Close()

	target, err := NewTargetWithPolicy(backend.URL+"/api", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("upstream URL with a base path must be accepted: %v", err)
	}

	if !probeOnce(t, target, "/healthz") {
		t.Fatalf("FAIL: target %q serves its app under /api and is healthy, but the probe "+
			"did not include the base path — it is taken out of rotation (503) for traffic "+
			"it is serving correctly", target.URL)
	}
}

// A trailing slash on the configured base path must not double the separator.
func TestHealthCheckHandlesTrailingSlashBasePath(t *testing.T) {
	backend := basePathBackend(t, nil)
	defer backend.Close()

	target, err := NewTargetWithPolicy(backend.URL+"/api/", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("target: %v", err)
	}

	if !probeOnce(t, target, "/healthz") {
		t.Fatalf("FAIL: base path %q with a trailing slash produced a bad probe URL",
			target.URL.Path)
	}
}

// CONTROL: a target with no base path is probed as before.
func TestHealthCheckRootTargetStillHealthy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	target, err := NewTargetWithPolicy(backend.URL, 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if !probeOnce(t, target, "/healthz") {
		t.Fatal("FAIL: a root target with a 200 backend must report healthy")
	}
}

// CONTROL: an unhealthy backend is still reported unhealthy — the join must not
// turn every probe into a success.
func TestHealthCheckStillDetectsUnhealthyBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	target, err := NewTargetWithPolicy(backend.URL+"/api", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if probeOnce(t, target, "/healthz") {
		t.Fatal("FAIL: a 500 backend must still be reported unhealthy")
	}
}

// CONTROL: the base path really is joined for proxied traffic, so the
// configuration these tests rely on is legitimate.
func TestBasePathIsJoinedForProxiedTraffic(t *testing.T) {
	var proxied []string
	backend := basePathBackend(t, &proxied)
	defer backend.Close()

	target, err := NewTargetWithPolicy(backend.URL+"/api", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("target: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://gw.example.com/foo", nil)
	if err := target.ServeHTTP(rec, req, ""); err != nil {
		t.Fatalf("proxy: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("FAIL: proxied request got %d, want 200 (backend serves only under /api)",
			rec.Code)
	}
	if len(proxied) == 0 || !strings.HasPrefix(proxied[0], "/api/") {
		t.Fatalf("FAIL: backend saw %v, want a /api/ prefixed path", proxied)
	}
}
