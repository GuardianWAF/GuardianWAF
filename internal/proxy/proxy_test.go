package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	allowPrivateTargets.Store(true)
}

type hijackableRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, h.err
}

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
	tests := []string{
		"://invalid",
		"/relative",
		"http:///missing-host",
		"ftp://example.com",
	}
	for _, rawURL := range tests {
		if _, err := NewTarget(rawURL, 1); err == nil {
			t.Errorf("expected error for invalid URL %q", rawURL)
		}
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
	if len(lb.healthyTargets()) != 2 {
		t.Errorf("expected 2 healthy, got %d", len(lb.healthyTargets()))
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

// TestRouterRetryOnFailure verifies that when the first target fails
// (proxy error — upstream unreachable), the router retries with a different
// target and succeeds.
func TestRouterRetryOnFailure(t *testing.T) {
	// Healthy backend that returns 200
	goodBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer goodBackend.Close()

	goodTarget, _ := NewTarget(goodBackend.URL, 1)

	// Bad target pointing to a non-listening port — will cause proxy error
	badTarget, _ := NewTarget("http://127.0.0.1:1", 1) // port 1 should never be listening

	targets := []*Target{badTarget, goodTarget}
	router := NewRouter([]Route{
		{PathPrefix: "/", Balancer: NewBalancer(targets, StrategyRoundRobin)},
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))

	// The router should have retried and succeeded via the good target
	if w.Code != 200 {
		t.Errorf("expected 200 after retry, got %d (body: %s)", w.Code, w.Body.String())
	}
	if w.Body.String() != "ok" {
		t.Errorf("expected 'ok', got %q", w.Body.String())
	}
}

// TestRouterRetryExhausted502 verifies that when all targets fail,
// the router returns 502 Bad Gateway.
func TestRouterRetryExhausted502(t *testing.T) {
	// Two bad targets pointing to non-listening ports
	bad1, _ := NewTarget("http://127.0.0.1:1", 1)
	bad2, _ := NewTarget("http://127.0.0.1:2", 1)

	targets := []*Target{bad1, bad2}
	router := NewRouter([]Route{
		{PathPrefix: "/", Balancer: NewBalancer(targets, StrategyRoundRobin)},
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))

	if w.Code != 502 {
		t.Errorf("expected 502 after all retries exhausted, got %d", w.Code)
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
	cb.Allow() // half-open (resets failure count to 0)

	// Failures counter was reset on Open->HalfOpen transition, so we need
	// threshold failures to re-open the circuit.
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected open after failures in half-open, got %s", cb.State())
	}
}

func TestRouterFailoverReplaysRequestBody(t *testing.T) {
	// A live backend that echoes the request body it received.
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// A dead backend (closed listener) that the first attempt will fail on.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	deadTarget, err := NewTarget(deadURL, 1)
	if err != nil {
		t.Fatalf("dead target: %v", err)
	}
	liveTarget, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatalf("live target: %v", err)
	}

	// Round-robin balancer: dead target is first, live target second.
	bal := NewBalancer([]*Target{deadTarget, liveTarget}, "round_robin")
	rt := NewRouter([]Route{{PathPrefix: "/", Balancer: bal}})

	const payload = "user=admin&cmd=whoami"
	req := httptest.NewRequest("POST", "/submit", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after failover, got %d", w.Code)
	}
	if gotBody != payload {
		t.Fatalf("failover backend received body %q, want %q (body not replayed)", gotBody, payload)
	}
}

func TestCircuitBreakerHalfOpenFailureReopensAndRecovers(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 5, ResetTimeout: 20 * time.Millisecond})

	// Open the circuit.
	for range 5 {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open, got %s", cb.State())
	}

	// After the reset timeout, one probe is admitted (half-open).
	time.Sleep(30 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("expected probe to be admitted after reset timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open, got %s", cb.State())
	}

	// A single failed probe must reopen the circuit (not wedge in half-open).
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected reopen after failed probe, got %s", cb.State())
	}

	// The reset cycle must resume: after the timeout, another probe is admitted
	// and a success closes the circuit.
	time.Sleep(30 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("expected a new probe to be admitted after reopen (circuit wedged)")
	}
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Fatalf("expected closed after successful probe, got %s", cb.State())
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

// Merged from proxy_extra3_test.go
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

// Merged from proxy_extra_test.go
func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

func TestTarget_CircuitState(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	target, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatal(err)
	}

	state := target.CircuitState()
	if state != CircuitClosed {
		t.Errorf("expected closed, got %s", state.String())
	}
}

func TestTarget_ActiveConns(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	target, err := NewTarget(backend.URL, 1)
	if err != nil {
		t.Fatal(err)
	}

	if conns := target.ActiveConns(); conns != 0 {
		t.Errorf("expected 0 active conns, got %d", conns)
	}
}

func TestRouter_AllUpstreamStatus(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	target, _ := NewTarget(backend.URL, 1)
	balancer := NewBalancer([]*Target{target}, "round_robin")

	routes := []Route{
		{PathPrefix: "/", Balancer: balancer},
	}
	router := NewRouter(routes)

	statuses := router.AllUpstreamStatus()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 upstream status, got %d", len(statuses))
	}
	if len(statuses[0].Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(statuses[0].Targets))
	}

	ts := statuses[0].Targets[0]
	if !ts.Healthy {
		t.Error("expected healthy target")
	}
	if ts.CircuitState != "closed" {
		t.Errorf("expected 'closed', got %q", ts.CircuitState)
	}
}

func TestRouter_AllUpstreamStatus_DeduplicatesBalancers(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer backend.Close()

	target, _ := NewTarget(backend.URL, 1)
	balancer := NewBalancer([]*Target{target}, "round_robin")

	routes := []Route{
		{PathPrefix: "/api", Balancer: balancer},
		{PathPrefix: "/web", Balancer: balancer},
	}
	router := NewRouter(routes)

	statuses := router.AllUpstreamStatus()
	if len(statuses) != 1 {
		t.Errorf("expected 1 (deduplicated), got %d", len(statuses))
	}
}

func TestRouter_AllUpstreamStatus_NilBalancer(t *testing.T) {
	routes := []Route{
		{PathPrefix: "/", Balancer: nil},
	}
	router := NewRouter(routes)
	statuses := router.AllUpstreamStatus()
	if len(statuses) != 0 {
		t.Errorf("expected 0 for nil balancer, got %d", len(statuses))
	}
}

func TestExtractClientIPForHash_WithPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ip := extractClientIPForHash(req)
	if ip != "192.168.1.100" {
		t.Errorf("expected '192.168.1.100', got %q", ip)
	}
}

func TestExtractClientIPForHash_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	ip := extractClientIPForHash(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %q", ip)
	}
}

func TestExtractClientIPForHash_XForwardedFor(t *testing.T) {
	// XFF is no longer trusted — uses RemoteAddr only
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	ip := extractClientIPForHash(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected RemoteAddr '10.0.0.1', got %q", ip)
	}
}

// Merged from proxy_gap_targeted_test.go
func TestProxyErrorHijack_Unsupported(t *testing.T) {
	pe := &proxyError{ResponseWriter: httptest.NewRecorder()}
	conn, rw, err := pe.Hijack()
	if err == nil {
		t.Fatal("expected hijack error")
	}
	if conn != nil || rw != nil {
		t.Fatal("expected nil hijack results")
	}
}

func TestProxyErrorHijack_Delegates(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
	wantErr := errors.New("sentinel hijack error")
	pe := &proxyError{ResponseWriter: &hijackableRecorder{ResponseRecorder: httptest.NewRecorder(), conn: serverConn, rw: rw, err: wantErr}}

	gotConn, gotRW, err := pe.Hijack()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Hijack() error = %v, want %v", err, wantErr)
	}
	if gotConn != serverConn || gotRW != rw {
		t.Fatal("Hijack() did not delegate to underlying ResponseWriter")
	}
}

func TestTargetServeHTTP_TargetClosed(t *testing.T) {
	target, err := NewTarget("http://localhost:3000", 1)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	target.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err := target.ServeHTTP(w, req, ""); err != nil {
		t.Fatalf("ServeHTTP() error = %v, want nil", err)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ServeHTTP() code = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(w.Body.String(), "Target closed") {
		t.Fatalf("ServeHTTP() body = %q, want target closed message", w.Body.String())
	}
}

func TestIsPrivateOrReservedIP_DNSFailureReturnsNil(t *testing.T) {
	if err := IsPrivateOrReservedIP("nonexistent.invalid"); err != nil {
		t.Fatalf("IsPrivateOrReservedIP() error = %v, want nil on lookup failure", err)
	}
}

func TestIsPrivateOrReservedIPWithPolicy_AllowPrivateShortCircuits(t *testing.T) {
	if err := IsPrivateOrReservedIPWithPolicy("127.0.0.1:8080", TargetPolicy{AllowPrivateTargets: true}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy() error = %v, want nil", err)
	}
}

func TestIsPrivateOrReservedIPWithPolicy_HostnameBranches(t *testing.T) {
	cidrs, err := ParseAllowedUpstreamCIDRs([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseAllowedUpstreamCIDRs() error = %v", err)
	}
	if err := IsPrivateOrReservedIPWithPolicy("localhost", TargetPolicy{AllowedCIDRs: cidrs}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy(localhost) error = %v, want nil", err)
	}
	if err := IsPrivateOrReservedIPWithPolicy("nonexistent.invalid", TargetPolicy{}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy(lookup fail) error = %v, want nil", err)
	}
}

func TestClassifyIPWithAllowedCIDRs_InterfaceLocalMulticast(t *testing.T) {
	ip := net.ParseIP("ff01::1")
	if ip == nil {
		t.Fatal("expected multicast IP to parse")
	}
	if err := classifyIPWithAllowedCIDRs(ip, "ff01::1", nil); err == nil {
		t.Fatal("expected interface-local multicast to be blocked")
	}
}

func TestParseAllowedUpstreamCIDRs_AdditionalBranches(t *testing.T) {
	parsed, err := ParseAllowedUpstreamCIDRs([]string{"  ", "2001:db8::1", "224.0.0.1"})
	if err == nil {
		t.Fatal("expected multicast IP error")
	}
	if parsed != nil {
		t.Fatal("expected parsed result to be nil on error")
	}

	parsed, err = ParseAllowedUpstreamCIDRs([]string{"  ", "2001:db8::1"})
	if err != nil {
		t.Fatalf("ParseAllowedUpstreamCIDRs() error = %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("len(parsed) = %d, want 1", len(parsed))
	}
	ones, bits := parsed[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("IPv6 host mask = %d/%d, want 128/128", ones, bits)
	}

	if _, err := ParseAllowedUpstreamCIDRs([]string{"1.2.3.4/0"}); err == nil {
		t.Fatal("expected all-address CIDR to be rejected")
	}
}

func TestSSRFDialContextWithPolicy_NoPortAndDNSFailure(t *testing.T) {
	dial := SSRFDialContextWithPolicy(TargetPolicy{})
	if _, err := dial(context.Background(), "tcp", "nonexistent.invalid"); err == nil {
		t.Fatal("expected DNS lookup failure")
	}
}

func TestRouterServeHTTP_RetryExhaustedAfterNoHealthyTargets(t *testing.T) {
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	failURL := failServer.URL
	failServer.Close()

	failTarget, err := NewTarget(failURL, 1)
	if err != nil {
		t.Fatalf("NewTarget(fail) error = %v", err)
	}
	failTarget.circuit.threshold = 1

	spareTarget, err := NewTarget("http://spare.invalid:8080", 1)
	if err != nil {
		t.Fatalf("NewTarget(spare) error = %v", err)
	}
	spareTarget.SetHealthy(false)

	router := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{failTarget, spareTarget}, StrategyRoundRobin)}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("body"))
	req.ContentLength = int64(len("body"))
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("ServeHTTP() code = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestRouterClose_NilReceiver(t *testing.T) {
	var rt *Router
	rt.Close()
}

func TestHealthCheckPolicy_DefaultBranches(t *testing.T) {
	assertZeroPolicy := func(name string, got TargetPolicy) {
		t.Helper()
		if got.AllowPrivateTargets {
			t.Fatalf("%s AllowPrivateTargets = true, want false", name)
		}
		if got.AllowedCIDRs != nil {
			t.Fatalf("%s AllowedCIDRs = %v, want nil", name, got.AllowedCIDRs)
		}
	}

	assertZeroPolicy("nil", healthCheckPolicy(nil))
	assertZeroPolicy("empty", healthCheckPolicy(NewBalancer(nil, StrategyRoundRobin)))
	assertZeroPolicy("nil target", healthCheckPolicy(NewBalancer([]*Target{nil}, StrategyRoundRobin)))
}

func TestMinHealthCheckDuration_Branches(t *testing.T) {
	if got := minHealthCheckDuration(0, time.Second); got != time.Second {
		t.Fatalf("minHealthCheckDuration(0, 1s) = %v, want 1s", got)
	}
	if got := minHealthCheckDuration(2*time.Second, time.Second); got != time.Second {
		t.Fatalf("minHealthCheckDuration(2s, 1s) = %v, want 1s", got)
	}
	if got := minHealthCheckDuration(500*time.Millisecond, time.Second); got != 500*time.Millisecond {
		t.Fatalf("minHealthCheckDuration(500ms, 1s) = %v, want 500ms", got)
	}
}
