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

func TestRouterCloseClosesUniqueTargetsAcrossRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	shared, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatalf("NewTarget shared: %v", err)
	}
	vhostOnly, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatalf("NewTarget vhostOnly: %v", err)
	}

	sharedBalancer := NewBalancer([]*Target{shared}, StrategyRoundRobin)
	vhostBalancer := NewBalancer([]*Target{shared, vhostOnly}, StrategyRoundRobin)
	nilTargetBalancer := NewBalancer([]*Target{nil}, StrategyRoundRobin)
	router := NewRouterWithVHosts(
		[]VirtualHost{
			{Domains: []string{"api.example.com"}, Routes: []Route{{PathPrefix: "/", Balancer: vhostBalancer}}},
			{Domains: []string{"*.example.com"}, Routes: []Route{{PathPrefix: "/wild", Balancer: sharedBalancer}}},
			{Domains: []string{"nil.example.com"}, Routes: []Route{{PathPrefix: "/nil", Balancer: nilTargetBalancer}}},
		},
		[]Route{
			{PathPrefix: "/", Balancer: sharedBalancer},
			{PathPrefix: "/nil", Balancer: nil},
		},
	)

	router.Close()

	if !shared.Closed() {
		t.Fatal("expected shared target to be closed")
	}
	if !vhostOnly.Closed() {
		t.Fatal("expected vhost-only target to be closed")
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
	err := target.ServeHTTP(w, req, "")
	if err == nil {
		t.Error("expected error when backend is down")
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
