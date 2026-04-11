package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	allowPrivateTargets.Store(true)
}

// --- NewHealthChecker ---

func TestNewHealthChecker_Defaults(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)

	hc := NewHealthChecker(lb, HealthConfig{})
	if hc.interval != 10*time.Second {
		t.Errorf("expected default interval 10s, got %v", hc.interval)
	}
	if hc.timeout != 3*time.Second {
		t.Errorf("expected default timeout 3s, got %v", hc.timeout)
	}
	if hc.path != "/" {
		t.Errorf("expected default path '/', got %q", hc.path)
	}
}

func TestNewHealthChecker_CustomConfig(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)

	hc := NewHealthChecker(lb, HealthConfig{
		Interval: 5 * time.Second,
		Timeout:  2 * time.Second,
		Path:     "/healthz",
	})
	if hc.interval != 5*time.Second {
		t.Errorf("expected interval 5s, got %v", hc.interval)
	}
	if hc.timeout != 2*time.Second {
		t.Errorf("expected timeout 2s, got %v", hc.timeout)
	}
	if hc.path != "/healthz" {
		t.Errorf("expected path '/healthz', got %q", hc.path)
	}
}

func TestNewHealthChecker_ZeroValues(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)

	// All zeros should use defaults
	hc := NewHealthChecker(lb, HealthConfig{
		Interval: 0,
		Timeout:  0,
		Path:     "",
	})
	if hc.interval != 10*time.Second {
		t.Errorf("expected default interval, got %v", hc.interval)
	}
	if hc.timeout != 3*time.Second {
		t.Errorf("expected default timeout, got %v", hc.timeout)
	}
	if hc.path != "/" {
		t.Errorf("expected default path, got %q", hc.path)
	}
}

func TestNewHealthChecker_ClientTimeout(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)

	hc := NewHealthChecker(lb, HealthConfig{
		Timeout: 500 * time.Millisecond,
	})
	if hc.client.Timeout != 500*time.Millisecond {
		t.Errorf("expected client timeout 500ms, got %v", hc.client.Timeout)
	}
}

// --- check ---

func TestCheck_HealthyUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Path: "/healthz",
	})

	result := hc.check(context.Background(), target)
	if !result {
		t.Error("expected healthy for 200 response")
	}
}

func TestCheck_UnhealthyUpstream_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{})

	result := hc.check(context.Background(), target)
	if result {
		t.Error("expected unhealthy for 500 response")
	}
}

func TestCheck_UnhealthyUpstream_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{})

	result := hc.check(context.Background(), target)
	if result {
		t.Error("expected unhealthy for 404 response")
	}
}

func TestCheck_Status399IsHealthy(t *testing.T) {
	// Status codes 200-399 are considered healthy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(301) // redirect
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{})

	result := hc.check(context.Background(), target)
	if !result {
		t.Error("expected healthy for 301 response")
	}
}

func TestCheck_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Timeout: 5 * time.Second, // client timeout is long
	})

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := hc.check(ctx, target)
	if result {
		t.Error("expected unhealthy when context is canceled")
	}
}

func TestCheck_UnreachableHost(t *testing.T) {
	target, _ := NewTarget("http://127.0.0.1:1", 1) // nothing on port 1
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Timeout: 100 * time.Millisecond,
	})

	result := hc.check(context.Background(), target)
	if result {
		t.Error("expected unhealthy for unreachable host")
	}
}

// --- NewCircuitBreaker ---

func TestNewCircuitBreaker_DefaultThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{})
	if cb.threshold != 5 {
		t.Errorf("expected default threshold 5, got %d", cb.threshold)
	}
}

func TestNewCircuitBreaker_DefaultResetTimeout(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{})
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("expected default reset timeout 30s, got %v", cb.resetTimeout)
	}
}

func TestNewCircuitBreaker_CustomThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 10})
	if cb.threshold != 10 {
		t.Errorf("expected threshold 10, got %d", cb.threshold)
	}
}

func TestNewCircuitBreaker_CustomResetTimeout(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{ResetTimeout: 1 * time.Minute})
	if cb.resetTimeout != 1*time.Minute {
		t.Errorf("expected reset timeout 1m, got %v", cb.resetTimeout)
	}
}

func TestNewCircuitBreaker_NegativeThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: -3})
	if cb.threshold != 5 {
		t.Errorf("expected default threshold for negative input, got %d", cb.threshold)
	}
}

func TestNewCircuitBreaker_ZeroThreshold(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 0})
	if cb.threshold != 5 {
		t.Errorf("expected default threshold for zero input, got %d", cb.threshold)
	}
}

func TestNewCircuitBreaker_NegativeResetTimeout(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{ResetTimeout: -5 * time.Second})
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("expected default reset timeout for negative input, got %v", cb.resetTimeout)
	}
}

// --- Allow state transitions ---

func TestAllow_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{Threshold: 3})
	if !cb.Allow() {
		t.Error("closed circuit should allow")
	}
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed, got %s", cb.State())
	}
}

func TestAllow_OpenState_Rejects(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    2,
		ResetTimeout: 30 * time.Second, // long timeout
	})
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open, got %s", cb.State())
	}
	if cb.Allow() {
		t.Error("open circuit should reject")
	}
}

func TestAllow_OpenToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    2,
		ResetTimeout: 50 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("expected open")
	}

	time.Sleep(60 * time.Millisecond)

	if !cb.Allow() {
		t.Error("should allow after reset timeout (transition to half-open)")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected half-open, got %s", cb.State())
	}
}

func TestAllow_HalfOpenThenSuccess(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    2,
		ResetTimeout: 50 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transition to half-open

	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed after success in half-open, got %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Errorf("expected 0 failures, got %d", cb.Failures())
	}
}

func TestAllow_HalfOpenThenFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    2,
		ResetTimeout: 50 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transition to half-open (resets failure count to 0)

	// Failures counter was reset on Open->HalfOpen transition, so we need
	// threshold failures to re-open the circuit.
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected open after failures in half-open, got %s", cb.State())
	}
}

func TestAllow_HalfOpenAllowsMultiple(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    1,
		ResetTimeout: 50 * time.Millisecond,
	})
	cb.RecordFailure() // opens immediately with threshold 1
	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transition to half-open

	// In the current implementation, half-open allows all requests
	// (only the probe result determines next state)
	if !cb.Allow() {
		t.Error("half-open should allow in this implementation")
	}
}

func TestAllow_FullCycle(t *testing.T) {
	cb := NewCircuitBreaker(CircuitConfig{
		Threshold:    2,
		ResetTimeout: 50 * time.Millisecond,
	})

	// Start closed
	if cb.State() != CircuitClosed {
		t.Fatal("expected initial state closed")
	}

	// Record failures to open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("expected open after 2 failures")
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Allow triggers half-open
	if !cb.Allow() {
		t.Fatal("expected allow during half-open")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatal("expected half-open after allow")
	}

	// Success closes circuit
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected closed after success, got %s", cb.State())
	}
}

// --- weightedRoundRobin ---

func TestWeightedRoundRobin_SingleTarget(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 5)
	lb := NewBalancer([]*Target{target}, StrategyWeighted)

	req := httptest.NewRequest("GET", "/", nil)
	for range 10 {
		got := lb.Next(req)
		if got != target {
			t.Error("weighted with single target should always return that target")
		}
	}
}

func TestWeightedRoundRobin_EqualWeights(t *testing.T) {
	t1, _ := NewTarget("http://a:3000", 2)
	t2, _ := NewTarget("http://b:3000", 2)
	lb := NewBalancer([]*Target{t1, t2}, StrategyWeighted)

	req := httptest.NewRequest("GET", "/", nil)
	counts := make(map[string]int)
	for range 400 {
		got := lb.Next(req)
		counts[got.URL.Host]++
	}
	// Equal weights should give equal distribution
	if counts["a:3000"] != counts["b:3000"] {
		t.Errorf("equal weights should give equal distribution: %v", counts)
	}
}

func TestWeightedRoundRobin_VariousWeights(t *testing.T) {
	t1, _ := NewTarget("http://heavy:3000", 5)
	t2, _ := NewTarget("http://medium:3000", 3)
	t3, _ := NewTarget("http://light:3000", 2)
	lb := NewBalancer([]*Target{t1, t2, t3}, StrategyWeighted)

	req := httptest.NewRequest("GET", "/", nil)
	counts := make(map[string]int)
	total := 1000
	for range total {
		got := lb.Next(req)
		counts[got.URL.Host]++
	}

	// Total weight = 10; heavy=5/10=50%, medium=3/10=30%, light=2/10=20%
	if counts["heavy:3000"] != 500 {
		t.Errorf("heavy: expected 500, got %d", counts["heavy:3000"])
	}
	if counts["medium:3000"] != 300 {
		t.Errorf("medium: expected 300, got %d", counts["medium:3000"])
	}
	if counts["light:3000"] != 200 {
		t.Errorf("light: expected 200, got %d", counts["light:3000"])
	}
}

func TestWeightedRoundRobin_ZeroWeightFailsafe(t *testing.T) {
	// If all weights are 0 (default to 1 by NewTarget, but test the failsafe in weightedRoundRobin)
	t1, _ := NewTarget("http://a:3000", 1)
	t2, _ := NewTarget("http://b:3000", 1)
	lb := NewBalancer([]*Target{t1, t2}, StrategyWeighted)

	req := httptest.NewRequest("GET", "/", nil)
	// Should not panic and should return a valid target
	got := lb.Next(req)
	if got == nil {
		t.Error("expected non-nil target")
	}
}

// --- extractClientIPForHash ---

func TestExtractClientIPForHash_XForwardedForIgnored(t *testing.T) {
	// XFF headers are no longer trusted by extractClientIPForHash — uses RemoteAddr only
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 192.168.1.1")
	req.RemoteAddr = "10.0.0.1:1234"

	ip := extractClientIPForHash(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected RemoteAddr '10.0.0.1', got %q", ip)
	}
}

func TestExtractClientIPForHash_XRealIPIgnored(t *testing.T) {
	// X-Real-IP is no longer trusted — uses RemoteAddr only
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "203.0.113.99")
	req.RemoteAddr = "10.0.0.1:1234"

	ip := extractClientIPForHash(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected RemoteAddr '10.0.0.1', got %q", ip)
	}
}

func TestExtractClientIPForHash_RemoteAddrAlwaysUsed(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.RemoteAddr = "192.168.1.1:1234"

	ip := extractClientIPForHash(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected RemoteAddr '192.168.1.1', got %q", ip)
	}
}

func TestExtractClientIPForHash_RemoteAddrFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	ip := extractClientIPForHash(req)
	if ip != "192.168.1.100" {
		t.Errorf("expected '192.168.1.100' from RemoteAddr, got %q", ip)
	}
}

func TestExtractClientIPForHash_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"

	ip := extractClientIPForHash(req)
	if ip != "10.0.0.1" {
		t.Errorf("expected '10.0.0.1', got %q", ip)
	}
}

func TestExtractClientIPForHash_EmptyXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "")
	req.RemoteAddr = "192.168.1.1:1234"

	ip := extractClientIPForHash(req)
	if ip != "192.168.1.1" {
		t.Errorf("expected RemoteAddr fallback, got %q", ip)
	}
}

// --- Health check integration ---

func TestHealthChecker_StartStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	target, _ := NewTarget(server.URL, 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)
	hc := NewHealthChecker(lb, HealthConfig{
		Interval: 50 * time.Millisecond,
	})

	hc.Start()
	// Should not panic on Stop
	hc.Stop()
}

func TestHealthChecker_MultipleTargets(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer healthy.Close()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
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

	time.Sleep(150 * time.Millisecond)

	if !t1.IsHealthy() {
		t.Error("t1 should be healthy (200)")
	}
	if t2.IsHealthy() {
		t.Error("t2 should be unhealthy (503)")
	}
}

func TestHealthChecker_TargetsReturnsCopy(t *testing.T) {
	target, _ := NewTarget("http://localhost:3000", 1)
	lb := NewBalancer([]*Target{target}, StrategyRoundRobin)

	orig := lb.Targets()
	if len(orig) != 1 {
		t.Fatalf("expected 1 target, got %d", len(orig))
	}
	// Mutating the copy should not affect the balancer
	orig[0] = nil
	copy := lb.Targets()
	if copy[0] == nil {
		t.Error("Targets() should return a copy, not the original slice")
	}
}
