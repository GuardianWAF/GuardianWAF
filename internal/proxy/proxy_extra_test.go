package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	ip := extractClientIPForHash(req)
	if ip != "203.0.113.50" {
		t.Errorf("expected '203.0.113.50', got %q", ip)
	}
}
