package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// helper to create a Backend from an httptest.Server URL
func newTestBackend(rawURL string, weight int, healthy bool) *Backend {
	u, _ := url.Parse(rawURL)
	b := &Backend{
		URL:     u,
		Weight:  weight,
		Healthy: healthy,
	}
	return b
}

// --- Basic Proxying ---

func TestBasicProxying(t *testing.T) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "test")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	b := newTestBackend(backend.URL, 1, true)
	proxy := NewProxy(Config{
		Backends:     []*Backend{b},
		LoadBalancer: "round_robin",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if body != "hello from backend" {
		t.Errorf("expected 'hello from backend', got %q", body)
	}
	if rr.Header().Get("X-Backend") != "test" {
		t.Errorf("expected X-Backend header to be 'test', got %q", rr.Header().Get("X-Backend"))
	}
}

func TestProxyForwardsPostBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer backend.Close()

	b := newTestBackend(backend.URL, 1, true)
	proxy := NewProxy(Config{
		Backends:     []*Backend{b},
		LoadBalancer: "round_robin",
	})

	req := httptest.NewRequest("POST", "/api", strings.NewReader("request body"))
	req.RemoteAddr = "10.0.0.1:9999"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Body.String() != "request body" {
		t.Errorf("expected 'request body', got %q", rr.Body.String())
	}
}

// --- Round Robin ---

func TestRoundRobinLoadBalancer(t *testing.T) {
	counts := make([]int, 3)
	servers := make([]*httptest.Server, 3)
	backends := make([]*Backend, 3)

	for i := 0; i < 3; i++ {
		idx := i
		servers[idx] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[idx]++
			w.WriteHeader(http.StatusOK)
		}))
		defer servers[idx].Close()
		backends[idx] = newTestBackend(servers[idx].URL, 1, true)
	}

	proxy := NewProxy(Config{
		Backends:     backends,
		LoadBalancer: "round_robin",
	})

	// Send 9 requests
	for i := 0; i < 9; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		proxy.ServeHTTP(rr, req)
	}

	// Each should get exactly 3
	for i, c := range counts {
		if c != 3 {
			t.Errorf("backend %d got %d requests, expected 3", i, c)
		}
	}
}

// --- Weighted ---

func TestWeightedLoadBalancer(t *testing.T) {
	counts := make([]int, 2)
	servers := make([]*httptest.Server, 2)
	backends := make([]*Backend, 2)

	for i := 0; i < 2; i++ {
		idx := i
		servers[idx] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[idx]++
			w.WriteHeader(http.StatusOK)
		}))
		defer servers[idx].Close()
	}

	// Weight 3:1
	backends[0] = newTestBackend(servers[0].URL, 3, true)
	backends[1] = newTestBackend(servers[1].URL, 1, true)

	proxy := NewProxy(Config{
		Backends:     backends,
		LoadBalancer: "weighted",
	})

	// Send many requests to see weight distribution
	total := 1000
	for i := 0; i < total; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		proxy.ServeHTTP(rr, req)
	}

	// Backend 0 should get roughly 75% (750), Backend 1 ~25% (250)
	// Allow generous tolerance
	ratio := float64(counts[0]) / float64(total)
	if ratio < 0.60 || ratio > 0.90 {
		t.Errorf("weighted distribution off: backend0=%d, backend1=%d, ratio=%.2f (expected ~0.75)",
			counts[0], counts[1], ratio)
	}
}

// --- Least Connections ---

func TestLeastConnLoadBalancer(t *testing.T) {
	backends := make([]*Backend, 3)
	for i := 0; i < 3; i++ {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer s.Close()
		backends[i] = newTestBackend(s.URL, 1, true)
	}

	// Simulate different active connection counts
	backends[0].ActiveConns.Store(10)
	backends[1].ActiveConns.Store(5)
	backends[2].ActiveConns.Store(1)

	lb := NewLeastConn(backends)
	req := httptest.NewRequest("GET", "/", nil)

	selected := lb.Select(req)
	if selected != backends[2] {
		t.Errorf("expected backend with least connections (index 2), got %v", selected.URL)
	}
}

// --- IP Hash ---

func TestIPHashConsistency(t *testing.T) {
	backends := make([]*Backend, 3)
	for i := 0; i < 3; i++ {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer s.Close()
		backends[i] = newTestBackend(s.URL, 1, true)
	}

	lb := NewIPHash(backends)

	// Same IP should always get the same backend
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.100:12345"
	selected1 := lb.Select(req1)

	req2 := httptest.NewRequest("GET", "/other", nil)
	req2.RemoteAddr = "192.168.1.100:54321"
	selected2 := lb.Select(req2)

	if selected1 != selected2 {
		t.Errorf("IP hash not consistent: same IP mapped to different backends")
	}

	// Different IPs may map to different backends (probabilistic)
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "10.0.0.1:12345"
	// Just ensure it doesn't panic
	lb.Select(req3)
}

// --- Health Check ---

func TestHealthCheckMarksUnhealthy(t *testing.T) {
	// Create a backend that always fails
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	b := newTestBackend(failServer.URL, 1, true)

	hc := NewHealthChecker([]*Backend{b}, 50*time.Millisecond, 2*time.Second, "/health")

	// Run checks manually (3 failures needed)
	hc.CheckNow()
	if !b.IsHealthy() {
		t.Error("backend should still be healthy after 1 failure")
	}
	hc.CheckNow()
	if !b.IsHealthy() {
		t.Error("backend should still be healthy after 2 failures")
	}
	hc.CheckNow()
	if b.IsHealthy() {
		t.Error("backend should be unhealthy after 3 consecutive failures")
	}
}

func TestHealthCheckMarksHealthy(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	b := newTestBackend(server.URL, 1, true)

	hc := NewHealthChecker([]*Backend{b}, 50*time.Millisecond, 2*time.Second, "/health")

	// Mark unhealthy: 3 failures
	hc.CheckNow()
	hc.CheckNow()
	hc.CheckNow()
	if b.IsHealthy() {
		t.Error("backend should be unhealthy")
	}

	// Now make it pass
	healthy.Store(true)
	hc.CheckNow()
	if !b.IsHealthy() {
		t.Error("backend should be healthy after 1 success")
	}
}

func TestHealthCheckWithUnreachableBackend(t *testing.T) {
	// Backend URL that doesn't exist
	b := newTestBackend("http://127.0.0.1:1", 1, true)

	hc := NewHealthChecker([]*Backend{b}, 50*time.Millisecond, 1*time.Second, "/health")

	// 3 failures to mark unhealthy
	hc.CheckNow()
	hc.CheckNow()
	hc.CheckNow()

	if b.IsHealthy() {
		t.Error("unreachable backend should be marked unhealthy")
	}
}

// --- Circuit Breaker ---

func TestCircuitBreakerOpensAfterFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

	host := "backend1.example.com"

	// Initially closed, should allow
	if !cb.Allow(host) {
		t.Error("circuit should be closed initially")
	}

	// Record 3 failures to open the circuit
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordFailure(host)

	if cb.State(host) != CircuitOpen {
		t.Errorf("expected circuit to be open, got %v", cb.State(host))
	}
	if cb.Allow(host) {
		t.Error("circuit should not allow requests when open")
	}
}

func TestCircuitBreakerHalfOpenRecovery(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 50*time.Millisecond)

	host := "backend2.example.com"

	// Open the circuit
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordFailure(host)

	if cb.State(host) != CircuitOpen {
		t.Fatalf("expected circuit to be open, got %v", cb.State(host))
	}

	// Wait for timeout to transition to half-open
	time.Sleep(100 * time.Millisecond)

	// Should transition to half-open on Allow
	if !cb.Allow(host) {
		t.Error("circuit should allow after timeout (half-open)")
	}

	if cb.State(host) != CircuitHalfOpen {
		t.Errorf("expected circuit to be half-open, got %v", cb.State(host))
	}

	// Record successes to close the circuit
	cb.RecordSuccess(host)
	cb.RecordSuccess(host)

	if cb.State(host) != CircuitClosed {
		t.Errorf("expected circuit to be closed after recovery, got %v", cb.State(host))
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 50*time.Millisecond)

	host := "backend3.example.com"

	// Open the circuit
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordFailure(host)

	// Wait for half-open
	time.Sleep(100 * time.Millisecond)
	cb.Allow(host) // transitions to half-open

	// Any failure in half-open goes back to open
	cb.RecordFailure(host)

	if cb.State(host) != CircuitOpen {
		t.Errorf("expected circuit to be open after half-open failure, got %v", cb.State(host))
	}
}

func TestCircuitBreakerSuccessResets(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

	host := "backend4.example.com"

	// Record 2 failures, then a success
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	cb.RecordSuccess(host)

	// Circuit should still be closed
	if cb.State(host) != CircuitClosed {
		t.Errorf("expected circuit to remain closed after success reset, got %v", cb.State(host))
	}

	// Now 3 more failures needed to open
	cb.RecordFailure(host)
	cb.RecordFailure(host)
	if cb.State(host) != CircuitClosed {
		t.Error("circuit should still be closed after 2 failures")
	}
	cb.RecordFailure(host)
	if cb.State(host) != CircuitOpen {
		t.Error("circuit should be open after 3 failures")
	}
}

// --- WebSocket ---

func TestWebSocketUpgradeDetection(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "valid websocket upgrade",
			headers:  map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"},
			expected: true,
		},
		{
			name:     "case insensitive",
			headers:  map[string]string{"Upgrade": "WebSocket", "Connection": "upgrade"},
			expected: true,
		},
		{
			name:     "connection with keep-alive",
			headers:  map[string]string{"Upgrade": "websocket", "Connection": "Upgrade, keep-alive"},
			expected: true,
		},
		{
			name:     "no upgrade header",
			headers:  map[string]string{"Connection": "Upgrade"},
			expected: false,
		},
		{
			name:     "no connection header",
			headers:  map[string]string{"Upgrade": "websocket"},
			expected: false,
		},
		{
			name:     "wrong upgrade value",
			headers:  map[string]string{"Upgrade": "h2c", "Connection": "Upgrade"},
			expected: false,
		},
		{
			name:     "empty headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/ws", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := IsWebSocketUpgrade(req); got != tt.expected {
				t.Errorf("IsWebSocketUpgrade() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// --- Header Forwarding ---

func TestHeaderForwarding(t *testing.T) {
	var receivedHeaders http.Header

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	b := newTestBackend(backend.URL, 1, true)
	proxy := NewProxy(Config{
		Backends:     []*Backend{b},
		LoadBalancer: "round_robin",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Request-ID", "test-req-123")
	req.Header.Set("X-Custom-Header", "custom-value")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// Check X-Forwarded-For
	xff := receivedHeaders.Get("X-Forwarded-For")
	if xff != "192.168.1.1" {
		t.Errorf("expected X-Forwarded-For '192.168.1.1', got %q", xff)
	}

	// Check X-Real-IP
	xri := receivedHeaders.Get("X-Real-IP")
	if xri != "192.168.1.1" {
		t.Errorf("expected X-Real-IP '192.168.1.1', got %q", xri)
	}

	// Check X-Request-ID is preserved
	reqID := receivedHeaders.Get("X-Request-ID")
	if reqID != "test-req-123" {
		t.Errorf("expected X-Request-ID 'test-req-123', got %q", reqID)
	}

	// Check custom header is forwarded
	custom := receivedHeaders.Get("X-Custom-Header")
	if custom != "custom-value" {
		t.Errorf("expected X-Custom-Header 'custom-value', got %q", custom)
	}
}

// --- Error Handling ---

func TestBackendFailureReturns502(t *testing.T) {
	// Backend that's unreachable
	b := newTestBackend("http://127.0.0.1:1", 1, true)

	proxy := NewProxy(Config{
		Backends:       []*Backend{b},
		LoadBalancer:   "round_robin",
		ConnectTimeout: 500 * time.Millisecond,
		ReadTimeout:    500 * time.Millisecond,
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", rr.Code)
	}
}

func TestAllBackendsUnhealthyReturns503(t *testing.T) {
	b1 := newTestBackend("http://127.0.0.1:1", 1, false) // unhealthy
	b2 := newTestBackend("http://127.0.0.1:2", 1, false) // unhealthy

	proxy := NewProxy(Config{
		Backends:     []*Backend{b1, b2},
		LoadBalancer: "round_robin",
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

func TestCircuitBreakerReturns503(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	b := newTestBackend(backend.URL, 1, true)
	cb := NewCircuitBreaker(1, 1, 10*time.Second)

	proxy := NewProxy(Config{
		Backends:     []*Backend{b},
		LoadBalancer: "round_robin",
	})
	proxy.SetCircuitBreaker(cb)

	// Open the circuit for this backend
	cb.RecordFailure(b.URL.Host)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 with open circuit, got %d", rr.Code)
	}
}

// --- Load Balancer Skips Unhealthy ---

func TestRoundRobinSkipsUnhealthy(t *testing.T) {
	backends := []*Backend{
		newTestBackend("http://server1:80", 1, false), // unhealthy
		newTestBackend("http://server2:80", 1, true),  // healthy
		newTestBackend("http://server3:80", 1, false), // unhealthy
	}

	lb := NewRoundRobin(backends)
	req := httptest.NewRequest("GET", "/", nil)

	// Should always select server2
	for i := 0; i < 5; i++ {
		selected := lb.Select(req)
		if selected != backends[1] {
			t.Errorf("iteration %d: expected healthy backend (server2), got %v", i, selected)
		}
	}
}

func TestNoHealthyBackendsReturnsNil(t *testing.T) {
	backends := []*Backend{
		newTestBackend("http://server1:80", 1, false),
		newTestBackend("http://server2:80", 1, false),
	}

	lb := NewRoundRobin(backends)
	req := httptest.NewRequest("GET", "/", nil)

	selected := lb.Select(req)
	if selected != nil {
		t.Errorf("expected nil when no backends healthy, got %v", selected)
	}
}

func TestEmptyBackendsReturnsNil(t *testing.T) {
	lbs := []LoadBalancer{
		NewRoundRobin(nil),
		NewWeighted(nil),
		NewLeastConn(nil),
		NewIPHash(nil),
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	for _, lb := range lbs {
		if selected := lb.Select(req); selected != nil {
			t.Errorf("expected nil for empty backends, got %v", selected)
		}
	}
}

// --- Client IP Extraction ---

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{"from RemoteAddr", "192.168.1.1:1234", "", "", "192.168.1.1"},
		{"from X-Forwarded-For", "10.0.0.1:1234", "203.0.113.50", "", "203.0.113.50"},
		{"from X-Forwarded-For multiple", "10.0.0.1:1234", "203.0.113.50, 70.41.3.18", "", "203.0.113.50"},
		{"from X-Real-IP", "10.0.0.1:1234", "", "203.0.113.50", "203.0.113.50"},
		{"XFF takes precedence over XRI", "10.0.0.1:1234", "1.1.1.1", "2.2.2.2", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			got := ClientIP(req)
			if got != tt.expected {
				t.Errorf("ClientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// --- Helper Functions ---

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, expected string
	}{
		{"", "/path", "/path"},
		{"/", "/path", "/path"},
		{"/api", "/v1", "/api/v1"},
		{"/api/", "/v1", "/api/v1"},
		{"/api", "v1", "/api/v1"},
		{"/api/", "v1", "/api/v1"},
	}

	for _, tt := range tests {
		got := singleJoiningSlash(tt.a, tt.b)
		if got != tt.expected {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.expected)
		}
	}
}
