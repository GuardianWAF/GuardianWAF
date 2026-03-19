// Package proxy implements reverse proxy, load balancing, and health checking
// for GuardianWAF upstreams. All implementations use only the Go standard library.
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Target represents a single backend server with its reverse proxy and stats.
type Target struct {
	URL         *url.URL
	Weight      int
	proxy       *httputil.ReverseProxy
	circuit     *CircuitBreaker
	activeConns atomic.Int64
	healthy     atomic.Bool
	lastCheck   atomic.Value // stores time.Time
}

// NewTarget creates a target from a URL string and weight.
func NewTarget(rawURL string, weight int) (*Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if weight <= 0 {
		weight = 1
	}

	t := &Target{
		URL:    u,
		Weight: weight,
		circuit: NewCircuitBreaker(CircuitConfig{
			Threshold:    5,
			ResetTimeout: 30 * time.Second,
		}),
	}
	t.healthy.Store(true) // healthy by default until proven otherwise
	t.lastCheck.Store(time.Time{})

	// Build reverse proxy with sensible timeouts
	t.proxy = httputil.NewSingleHostReverseProxy(u)
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	t.proxy.Transport = transport
	// Enable immediate flushing for streaming (SSE, WebSocket upgrade, chunked)
	t.proxy.FlushInterval = -1

	// Wire error handler for circuit breaker
	t.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		t.circuit.RecordFailure()
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
	}

	// Wire response modifier to record success
	t.proxy.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode < 500 {
			t.circuit.RecordSuccess()
		} else {
			t.circuit.RecordFailure()
		}
		return nil
	}

	return t, nil
}

// ServeHTTP proxies the request to this target, tracking active connections.
// If the circuit breaker is open, returns 503 immediately.
func (t *Target) ServeHTTP(w http.ResponseWriter, r *http.Request, stripPrefix string) {
	if !t.circuit.Allow() {
		http.Error(w, "503 Service Unavailable - Circuit breaker open", http.StatusServiceUnavailable)
		return
	}

	t.activeConns.Add(1)
	defer t.activeConns.Add(-1)

	if stripPrefix != "" {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r2.URL.Path, stripPrefix)
		if !strings.HasPrefix(r2.URL.Path, "/") {
			r2.URL.Path = "/" + r2.URL.Path
		}
		r2.URL.RawPath = ""
		t.proxy.ServeHTTP(w, r2)
		return
	}

	t.proxy.ServeHTTP(w, r)
}

// IsHealthy returns true if the target is healthy AND circuit is not open.
func (t *Target) IsHealthy() bool {
	return t.healthy.Load() && t.circuit.State() != CircuitOpen
}

// SetHealthy sets the health status.
func (t *Target) SetHealthy(h bool) {
	t.healthy.Store(h)
	if h {
		t.circuit.Reset()
	}
}

// ActiveConns returns the number of active connections.
func (t *Target) ActiveConns() int64 {
	return t.activeConns.Load()
}

// CircuitState returns the target's circuit breaker state.
func (t *Target) CircuitState() CircuitState {
	return t.circuit.State()
}
