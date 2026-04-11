package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func init() {
	allowPrivateTargets.Store(true)
}

func TestWeightedRoundRobin_ZeroTotalWeight(t *testing.T) {
	t1, _ := NewTarget("http://a:3000", 1)
	t2, _ := NewTarget("http://b:3000", 1)
	t1.Weight = 0
	t2.Weight = 0
	lb := NewBalancer([]*Target{t1, t2}, StrategyWeighted)
	req := httptest.NewRequest("GET", "/", nil)
	got := lb.Next(req)
	if got != t1 {
		t.Errorf("expected first target when total weight is zero")
	}
}

func TestWeightedRoundRobin_Fallthrough(t *testing.T) {
	t1, _ := NewTarget("http://a:3000", 1)
	t2, _ := NewTarget("http://b:3000", 1)
	t1.Weight = -1
	t2.Weight = -1
	lb := NewBalancer([]*Target{t1, t2}, StrategyWeighted)
	req := httptest.NewRequest("GET", "/", nil)
	got := lb.Next(req)
	if got == nil {
		t.Fatal("expected non-nil target")
	}
}

func TestCircuitAllow_InvalidState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 3})
	cb.state.Store(int32(99))
	if cb.Allow() {
		t.Error("expected false for invalid state")
	}
}

func TestHealthCheck_NewRequestError(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{})
	target.URL = &url.URL{Scheme: "", Host: "localhost", Path: "/"}
	if hc.check(context.Background(), target) {
		t.Error("expected false when request cannot be created")
	}
}

func TestRouter_AllUpstreamStatus_VHosts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()
	target, _ := NewTarget(backend.URL, 1)
	balancer := NewBalancer([]*Target{target}, StrategyRoundRobin)
	router := NewRouterWithVHosts([]VirtualHost{
		{Domains: []string{"api.example.com"}, Routes: []Route{{PathPrefix: "/", Balancer: balancer}}},
		{Domains: []string{"*.example.com"}, Routes: []Route{{PathPrefix: "/", Balancer: balancer}}},
	}, nil)
	statuses := router.AllUpstreamStatus()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
}

func TestStripPort_IPv6NoPort(t *testing.T) {
	if got := stripPort("[::1]"); got != "[::1]" {
		t.Errorf("expected [::1], got %s", got)
	}
}

func TestTargetServeHTTP_EmptyStripPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer backend.Close()
	target, _ := NewTarget(backend.URL, 1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api", nil)
	target.ServeHTTP(w, req, "/api")
	if w.Body.String() != "path=/" {
		t.Errorf("expected path=/, got %s", w.Body.String())
	}
}

func TestTargetErrorHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()
	target, _ := NewTarget(backend.URL, 1)
	backend.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	target.ServeHTTP(w, req, "")
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
	if target.circuit.Failures() == 0 {
		t.Error("expected circuit failure to be recorded")
	}
}

func TestRouterSortWildcards(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()
	target, _ := NewTarget(backend.URL, 1)
	balancer := NewBalancer([]*Target{target}, StrategyRoundRobin)
	router := NewRouterWithVHosts([]VirtualHost{
		{Domains: []string{"*.example.com"}, Routes: []Route{{PathPrefix: "/", Balancer: balancer}}},
		{Domains: []string{"*.sub.example.com"}, Routes: []Route{{PathPrefix: "/", Balancer: balancer}}},
	}, nil)
	_ = router.AllUpstreamStatus()
}
