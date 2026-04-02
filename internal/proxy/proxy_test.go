package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// --- Target ---

func TestNewTarget(t *testing.T) {
	target, err := NewTarget("http://localhost:3000", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.URL.Host != "localhost:3000" {
		t.Errorf("expected localhost:3000, got %s", target.URL.Host)
	}
	if target.Weight != 2 {
		t.Errorf("expected weight 2, got %d", target.Weight)
	}
	if !target.IsHealthy() {
		t.Error("new target should be healthy")
	}
}

func TestNewTargetDefaultWeight(t *testing.T) {
	target, err := NewTarget("http://localhost:3000", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Weight != 1 {
		t.Errorf("expected default weight 1, got %d", target.Weight)
	}
}

func TestNewTargetInvalidURL(t *testing.T) {
	_, err := NewTarget("://invalid", 1)
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestTargetHealthToggle(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	if !target.IsHealthy() {
		t.Error("should start healthy")
	}
	target.SetHealthy(false)
	if target.IsHealthy() {
		t.Error("should be unhealthy after SetHealthy(false)")
	}
	target.SetHealthy(true)
	if !target.IsHealthy() {
		t.Error("should be healthy after SetHealthy(true)")
	}
}

func TestTargetServeHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer backend.Close()

	target, _ := NewTarget(backend.URL, 1)

	// Normal proxy
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/hello", nil)
	target.ServeHTTP(w, req, "")
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestTargetServeHTTPStripPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer backend.Close()

	target, _ := NewTarget(backend.URL, 1)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users", nil)
	target.ServeHTTP(w, req, "/api")
	if w.Body.String() != "path=/users" {
		t.Errorf("expected path=/users, got %s", w.Body.String())
	}
}

func TestTargetActiveConns(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	if target.ActiveConns() != 0 {
		t.Errorf("expected 0 active conns, got %d", target.ActiveConns())
	}
}

// --- Balancer ---

func makeTargets(n int) []*Target {
	targets := make([]*Target, n)
	for i := range n {
		targets[i], _ = NewTarget(fmt.Sprintf("http://backend%d:3000", i), 1)
	}
	return targets
}

func TestBalancerRoundRobin(t *testing.T) {
	targets := makeTargets(3)
	lb := NewBalancer(targets, StrategyRoundRobin)

	req := httptest.NewRequest("GET", "/", nil)
	counts := make(map[string]int)
	for range 30 {
		target := lb.Next(req)
		counts[target.URL.Host]++
	}

	// Each should get ~10 requests
	for host, count := range counts {
		if count != 10 {
			t.Errorf("round robin: %s got %d requests, expected 10", host, count)
		}
	}
}

func TestBalancerWeighted(t *testing.T) {
	targets := make([]*Target, 3)
	targets[0], _ = NewTarget("http://heavy:3000", 3)
	targets[1], _ = NewTarget("http://medium:3000", 2)
	targets[2], _ = NewTarget("http://light:3000", 1)

	lb := NewBalancer(targets, StrategyWeighted)
	req := httptest.NewRequest("GET", "/", nil)

	counts := make(map[string]int)
	for range 600 {
		target := lb.Next(req)
		counts[target.URL.Host]++
	}

	// heavy should get ~300 (3/6), medium ~200 (2/6), light ~100 (1/6)
	if counts["heavy:3000"] != 300 {
		t.Errorf("weighted: heavy got %d, expected 300", counts["heavy:3000"])
	}
	if counts["medium:3000"] != 200 {
		t.Errorf("weighted: medium got %d, expected 200", counts["medium:3000"])
	}
	if counts["light:3000"] != 100 {
		t.Errorf("weighted: light got %d, expected 100", counts["light:3000"])
	}
}

func TestBalancerLeastConn(t *testing.T) {
	targets := makeTargets(3)
	// Simulate different connection counts
	targets[0].activeConns.Store(10)
	targets[1].activeConns.Store(2)
	targets[2].activeConns.Store(5)

	lb := NewBalancer(targets, StrategyLeastConn)
	req := httptest.NewRequest("GET", "/", nil)

	target := lb.Next(req)
	if target.URL.Host != "backend1:3000" {
		t.Errorf("least_conn should pick backend1 (2 conns), got %s", target.URL.Host)
	}
}

func TestBalancerIPHash(t *testing.T) {
	targets := makeTargets(3)
	lb := NewBalancer(targets, StrategyIPHash)

	// Same IP should always get same target
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	first := lb.Next(req)
	for range 10 {
		got := lb.Next(req)
		if got.URL.Host != first.URL.Host {
			t.Errorf("ip_hash should be sticky, got %s then %s", first.URL.Host, got.URL.Host)
		}
	}
}

func TestBalancerSkipsUnhealthy(t *testing.T) {
	targets := makeTargets(3)
	targets[0].SetHealthy(false)
	targets[1].SetHealthy(false)

	lb := NewBalancer(targets, StrategyRoundRobin)
	req := httptest.NewRequest("GET", "/", nil)

	for range 10 {
		target := lb.Next(req)
		if target.URL.Host != "backend2:3000" {
			t.Errorf("should only pick healthy backend2, got %s", target.URL.Host)
		}
	}
}

func TestBalancerAllUnhealthy(t *testing.T) {
	targets := makeTargets(2)
	targets[0].SetHealthy(false)
	targets[1].SetHealthy(false)

	lb := NewBalancer(targets, StrategyRoundRobin)
	req := httptest.NewRequest("GET", "/", nil)

	target := lb.Next(req)
	if target != nil {
		t.Error("should return nil when all unhealthy")
	}
}

func TestBalancerHealthyCount(t *testing.T) {
	targets := makeTargets(3)
	targets[1].SetHealthy(false)

	lb := NewBalancer(targets, StrategyRoundRobin)
	if lb.HealthyCount() != 2 {
		t.Errorf("expected 2 healthy, got %d", lb.HealthyCount())
	}
}

func TestBalancerStrategy(t *testing.T) {
	lb := NewBalancer(makeTargets(1), StrategyLeastConn)
	if lb.Strategy() != StrategyLeastConn {
		t.Errorf("expected least_conn, got %s", lb.Strategy())
	}
}

func TestBalancerDefaultStrategy(t *testing.T) {
	lb := NewBalancer(makeTargets(1), "")
	if lb.Strategy() != StrategyRoundRobin {
		t.Errorf("expected round_robin default, got %s", lb.Strategy())
	}
}

func TestBalancerXForwardedFor(t *testing.T) {
	targets := makeTargets(3)
	lb := NewBalancer(targets, StrategyIPHash)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")

	first := lb.Next(req)
	for range 5 {
		got := lb.Next(req)
		if got.URL.Host != first.URL.Host {
			t.Error("ip_hash with XFF should be sticky")
		}
	}
}

// --- Router ---

func TestRouterPathMatching(t *testing.T) {
	var hit1, hit2 atomic.Int64
	b1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit1.Add(1)
		fmt.Fprint(w, "api")
	}))
	defer b1.Close()
	b2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit2.Add(1)
		fmt.Fprint(w, "web")
	}))
	defer b2.Close()

	t1, _ := NewTarget(b1.URL, 1)
	t2, _ := NewTarget(b2.URL, 1)

	router := NewRouter([]Route{
		{PathPrefix: "/api", Balancer: NewBalancer([]*Target{t1}, StrategyRoundRobin)},
		{PathPrefix: "/", Balancer: NewBalancer([]*Target{t2}, StrategyRoundRobin)},
	})

	// /api should go to b1
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, httptest.NewRequest("GET", "/api/users", nil))
	if w1.Body.String() != "api" {
		t.Errorf("expected api, got %s", w1.Body.String())
	}

	// / should go to b2
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, httptest.NewRequest("GET", "/index.html", nil))
	if w2.Body.String() != "web" {
		t.Errorf("expected web, got %s", w2.Body.String())
	}
}

func TestRouterNoMatch(t *testing.T) {
	router := NewRouter([]Route{
		{PathPrefix: "/api", Balancer: NewBalancer(makeTargets(1), StrategyRoundRobin)},
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/other", nil))
	if w.Code != 404 {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestRouterAllUnhealthy503(t *testing.T) {
	targets := makeTargets(1)
	targets[0].SetHealthy(false)

	router := NewRouter([]Route{
		{PathPrefix: "/", Balancer: NewBalancer(targets, StrategyRoundRobin)},
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

// --- Host-based routing ---

func TestRouterVirtualHosts(t *testing.T) {
	apiBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "api")
	}))
	defer apiBackend.Close()
	webBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "web")
	}))
	defer webBackend.Close()
	fallbackBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fallback")
	}))
	defer fallbackBackend.Close()

	tAPI, _ := NewTarget(apiBackend.URL, 1)
	tWeb, _ := NewTarget(webBackend.URL, 1)
	tFb, _ := NewTarget(fallbackBackend.URL, 1)

	router := NewRouterWithVHosts(
		[]VirtualHost{
			{
				Domains: []string{"api.example.com"},
				Routes:  []Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{tAPI}, StrategyRoundRobin)}},
			},
			{
				Domains: []string{"www.example.com", "example.com"},
				Routes:  []Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{tWeb}, StrategyRoundRobin)}},
			},
		},
		[]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{tFb}, StrategyRoundRobin)}},
	)

	tests := []struct {
		host     string
		expected string
	}{
		{"api.example.com", "api"},
		{"api.example.com:8088", "api"},
		{"www.example.com", "web"},
		{"example.com", "web"},
		{"unknown.example.com", "fallback"},
		{"other.com", "fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Body.String() != tt.expected {
				t.Errorf("host %s: expected %q, got %q", tt.host, tt.expected, w.Body.String())
			}
		})
	}
}

func TestRouterWildcardDomain(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "wildcard")
	}))
	defer backend.Close()
	fb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "default")
	}))
	defer fb.Close()

	tB, _ := NewTarget(backend.URL, 1)
	tFb, _ := NewTarget(fb.URL, 1)

	router := NewRouterWithVHosts(
		[]VirtualHost{
			{
				Domains: []string{"*.example.com"},
				Routes:  []Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{tB}, StrategyRoundRobin)}},
			},
		},
		[]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{tFb}, StrategyRoundRobin)}},
	)

	tests := []struct {
		host     string
		expected string
	}{
		{"api.example.com", "wildcard"},
		{"www.example.com", "wildcard"},
		{"sub.api.example.com", "wildcard"},
		{"other.com", "default"},
		{"example.com", "default"}, // *.example.com does NOT match bare example.com
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Body.String() != tt.expected {
				t.Errorf("host %s: expected %q, got %q", tt.host, tt.expected, w.Body.String())
			}
		})
	}
}

func TestRouterVHostPathRouting(t *testing.T) {
	apiHandler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "api:%s", r.URL.Path)
	}))
	defer apiHandler.Close()
	staticHandler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "static:%s", r.URL.Path)
	}))
	defer staticHandler.Close()

	tAPI, _ := NewTarget(apiHandler.URL, 1)
	tStatic, _ := NewTarget(staticHandler.URL, 1)

	router := NewRouterWithVHosts(
		[]VirtualHost{
			{
				Domains: []string{"mysite.com"},
				Routes: []Route{
					{PathPrefix: "/api", Balancer: NewBalancer([]*Target{tAPI}, StrategyRoundRobin), StripPrefix: true},
					{PathPrefix: "/", Balancer: NewBalancer([]*Target{tStatic}, StrategyRoundRobin)},
				},
			},
		},
		nil,
	)

	// /api/users -> api backend with prefix stripped
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/api/users", nil)
	req1.Host = "mysite.com"
	router.ServeHTTP(w1, req1)
	if w1.Body.String() != "api:/users" {
		t.Errorf("expected api:/users, got %s", w1.Body.String())
	}

	// /index.html -> static backend
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/index.html", nil)
	req2.Host = "mysite.com"
	router.ServeHTTP(w2, req2)
	if w2.Body.String() != "static:/index.html" {
		t.Errorf("expected static:/index.html, got %s", w2.Body.String())
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com", "example.com"},
		{"example.com:8088", "example.com"},
		{"[::1]:8088", "[::1]"},
		{"127.0.0.1:443", "127.0.0.1"},
	}
	for _, tt := range tests {
		got := stripPort(tt.input)
		if got != tt.expected {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- Circuit Breaker ---

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 3, ResetTimeout: 100 * time.Millisecond})
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed, got %s", cb.State())
	}
	if !cb.Allow() {
		t.Error("closed circuit should allow")
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 3, ResetTimeout: 100 * time.Millisecond})

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Error("should still be closed after 2 failures")
	}

	cb.RecordFailure() // 3rd = threshold
	if cb.State() != CircuitOpen {
		t.Errorf("expected open after 3 failures, got %s", cb.State())
	}
	if cb.Allow() {
		t.Error("open circuit should reject")
	}
}

func TestCircuitBreakerHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 2, ResetTimeout: 50 * time.Millisecond})

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("expected open")
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Should transition to half-open and allow probe
	if !cb.Allow() {
		t.Error("should allow after reset timeout (half-open)")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected half-open, got %s", cb.State())
	}
}

func TestCircuitBreakerHalfOpenSuccess(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 2, ResetTimeout: 50 * time.Millisecond})

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transition to half-open

	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed after success in half-open, got %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Errorf("failures should be reset, got %d", cb.Failures())
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 2, ResetTimeout: 50 * time.Millisecond})

	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // half-open

	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected open after failure in half-open, got %s", cb.State())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 2})
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("expected open")
	}

	cb.Reset()
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed after reset, got %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Error("failures should be 0 after reset")
	}
}

func TestCircuitBreakerSuccessResetCount(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 5})
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // should reset count
	if cb.Failures() != 0 {
		t.Errorf("expected 0 failures after success, got %d", cb.Failures())
	}
}

func TestCircuitStateString(t *testing.T) {
	if CircuitClosed.String() != "closed" {
		t.Error("expected 'closed'")
	}
	if CircuitOpen.String() != "open" {
		t.Error("expected 'open'")
	}
	if CircuitHalfOpen.String() != "half-open" {
		t.Error("expected 'half-open'")
	}
}

func TestTargetCircuitBreaker503(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer backend.Close()

	target, _ := NewTarget(backend.URL, 1)

	// Send requests until circuit opens (5 failures = default threshold)
	for range 5 {
		w := httptest.NewRecorder()
		target.ServeHTTP(w, httptest.NewRequest("GET", "/", nil), "")
	}

	// Next request should get 503 from circuit breaker
	w := httptest.NewRecorder()
	target.ServeHTTP(w, httptest.NewRequest("GET", "/", nil), "")
	if w.Code != 503 {
		t.Errorf("expected 503 from circuit breaker, got %d", w.Code)
	}
}

func TestTargetHealthyIncludesCircuit(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	if !target.IsHealthy() {
		t.Error("should be healthy initially")
	}

	// Open circuit
	for range 5 {
		target.circuit.RecordFailure()
	}
	if target.IsHealthy() {
		t.Error("should be unhealthy when circuit is open")
	}

	// SetHealthy resets circuit
	target.SetHealthy(true)
	if !target.IsHealthy() {
		t.Error("should be healthy after SetHealthy(true)")
	}
}

// --- Health Check ---

func TestHealthChecker(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer healthy.Close()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer unhealthy.Close()

	t1, _ := NewTarget(healthy.URL, 1)
	t2, _ := NewTarget(unhealthy.URL, 1)

	lb := NewBalancer([]*Target{t1, t2}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Interval: 50 * time.Millisecond,
		Timeout:  1 * time.Second,
		Path:     "/healthz",
	})
	hc.Start()
	defer hc.Stop()

	// Give it time to run
	time.Sleep(150 * time.Millisecond)

	if !t1.IsHealthy() {
		t.Error("t1 should be healthy")
	}
	if t2.IsHealthy() {
		t.Error("t2 should be unhealthy (returns 500)")
	}
}

func TestHealthCheckerUnreachable(t *testing.T) {
	target, _ := NewTarget("http://127.0.0.1:1", 1) // nothing listening on port 1

	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Interval: 50 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
		Path:     "/",
	})
	hc.Start()
	defer hc.Stop()

	time.Sleep(200 * time.Millisecond)

	if target.IsHealthy() {
		t.Error("unreachable target should be unhealthy")
	}
}

// --- Benchmarks ---

func BenchmarkBalancerRoundRobin(b *testing.B) {
	lb := NewBalancer(makeTargets(5), StrategyRoundRobin)
	req := httptest.NewRequest("GET", "/", nil)
	b.ResetTimer()
	for range b.N {
		lb.Next(req)
	}
}

func BenchmarkBalancerIPHash(b *testing.B) {
	lb := NewBalancer(makeTargets(5), StrategyIPHash)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	b.ResetTimer()
	for range b.N {
		lb.Next(req)
	}
}

func BenchmarkBalancerLeastConn(b *testing.B) {
	lb := NewBalancer(makeTargets(5), StrategyLeastConn)
	req := httptest.NewRequest("GET", "/", nil)
	b.ResetTimer()
	for range b.N {
		lb.Next(req)
	}
}
