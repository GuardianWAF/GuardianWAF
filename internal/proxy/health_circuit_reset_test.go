package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression (hunt round 11/25): Target.SetHealthy(true) contained
// circuit.Reset(), and the health checker calls SetHealthy(healthy) on every
// cycle — so every passing health probe force-closed the circuit breaker and
// wiped its failure state on a fixed timer. An upstream whose health path
// returns 200 while its real endpoints are failing (a common real-world
// pattern) had its open circuit reset every interval, re-flooding the failing
// upstream and neutralizing the breaker's half-open recovery. The two gates
// documented on IsHealthy ("healthy AND circuit not open") must compose: the
// health flag and the circuit are independent, and only the circuit's own
// half-open probe on real traffic may close it.

func TestHealthCheckDoesNotForceCloseCircuit(t *testing.T) {
	oldPrivate := PrivateTargetsAllowed()
	SetPrivateTargetsAllowed(true)
	defer SetPrivateTargetsAllowed(oldPrivate)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	target, err := NewTargetWithPolicy(srv.URL, 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("NewTargetWithPolicy: %v", err)
	}
	balancer := NewBalancer([]*Target{target}, StrategyRoundRobin)

	// Open the circuit from real traffic FIRST: 5 consecutive 500s →
	// ModifyResponse records consecutive failures → CircuitOpen.
	for range 5 {
		rec := httptest.NewRecorder()
		if err := target.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil), ""); err != nil {
			t.Fatalf("ServeHTTP returned unexpected proxy error: %v", err)
		}
	}
	if got := target.CircuitState(); got != CircuitOpen {
		t.Fatalf("precondition: circuit should be open after 5 consecutive 500s, got %v", got)
	}

	// Now start the health checker: each cycle sees /healthz → 200 and calls
	// SetHealthy(true). The circuit must stay open — the probe passing on a
	// different path is not evidence that real traffic recovered.
	hc := NewHealthChecker(balancer, HealthConfig{
		Enabled:  true,
		Interval: 20 * time.Millisecond,
		Timeout:  time.Second,
		Path:     "/healthz",
	})
	hc.Start()
	defer hc.Stop()
	time.Sleep(120 * time.Millisecond)

	if got := target.CircuitState(); got != CircuitOpen {
		t.Fatalf("FAIL: the health checker force-closed the circuit breaker (state %v) while real requests still fail — SetHealthy(true) must not reset the circuit", got)
	}
	if target.IsHealthy() {
		t.Fatalf("FAIL: IsHealthy() is true while the circuit is open — the two gates must compose")
	}
}
