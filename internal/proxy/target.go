// Package proxy implements reverse proxy, load balancing, and health checking
// for GuardianWAF upstreams. All implementations use only the Go standard library.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)



// proxyError wraps a ResponseWriter to detect proxy errors.
// When ErrorHandler fires, it records the error. The router checks this to retry.
type proxyError struct {
	http.ResponseWriter
	err error
}

func (pe *proxyError) WriteHeader(code int) { pe.ResponseWriter.WriteHeader(code) }
func (pe *proxyError) Write(p []byte) (int, error)              { return pe.ResponseWriter.Write(p) }

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

// IsPrivateOrReservedIP checks if a host resolves to a private, loopback,
// link-local, or other reserved IP range. Used for SSRF prevention.
func IsPrivateOrReservedIP(host string) error {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port
	}

	// Check if it's already an IP literal
	ip := net.ParseIP(h)
	if ip != nil {
		return classifyIP(ip, host)
	}

	// Resolve hostname to IPs
	ips, err := net.LookupIP(h)
	if err != nil {
		return nil // DNS resolution failed — will be caught by proxy transport
	}

	for _, addr := range ips {
		if err := classifyIP(addr, host); err != nil {
			return err
		}
	}
	return nil
}

func classifyIP(ip net.IP, host string) error {
	// Unspecified (0.0.0.0, ::) — would bind to all interfaces
	if ip.IsUnspecified() {
		return fmt.Errorf("target %q resolves to unspecified address %s — blocked by SSRF filter", host, ip)
	}
	if ip.IsLoopback() {
		return fmt.Errorf("target %q resolves to loopback address %s — blocked by SSRF filter", host, ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("target %q resolves to private address %s — blocked by SSRF filter", host, ip)
	}
	// Link-local unicast (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("target %q resolves to link-local address %s — blocked by SSRF filter", host, ip)
	}
	// Link-local multicast
	if ip.IsLinkLocalMulticast() {
		return fmt.Errorf("target %q resolves to link-local multicast address %s — blocked by SSRF filter", host, ip)
	}
	// Interface-local multicast
	if ip.IsInterfaceLocalMulticast() {
		return fmt.Errorf("target %q resolves to interface-local multicast address %s — blocked by SSRF filter", host, ip)
	}
	return nil
}
// allowPrivateTargets is set to true in tests to allow httptest.NewServer URLs.
var allowPrivateTargets atomic.Bool

// AllowPrivateTargets enables private/reserved IP targets for testing.
func AllowPrivateTargets() {
	allowPrivateTargets.Store(true)
}

// SSRFDialContext returns a DialContext function that validates the resolved IP
// against private/reserved ranges at connection time. This prevents DNS rebinding
// attacks where DNS resolves to a public IP at validation time but to a private IP
// at actual connection time (TOCTOU gap).
func SSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if allowPrivateTargets.Load() {
			return dialer.DialContext(ctx, network, addr)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}

		// Resolve and validate IPs once; use the first valid IP to avoid TOCTOU.
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("SSRF dial: DNS lookup failed for %q: %w", host, err)
		}

		var validIP net.IP
		for _, ip := range ips {
			if err := classifyIP(ip, host); err == nil {
				validIP = ip
				break
			}
		}
		if validIP == nil {
			return nil, fmt.Errorf("SSRF dial: no valid IPs for %q", host)
		}

		// Dial the validated IP directly, avoiding DNS re-resolution at dial time.
		target := net.JoinHostPort(validIP.String(), port)
		return dialer.DialContext(ctx, network, target)
	}
}

// PrivateTargetsAllowed reports whether private targets are allowed (for testing).
func PrivateTargetsAllowed() bool {
	return allowPrivateTargets.Load()
}

func NewTarget(rawURL string, weight int) (*Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if weight <= 0 {
		weight = 1
	}

	// SSRF prevention: block targets resolving to private/reserved IPs
	if !allowPrivateTargets.Load() {
		if err := IsPrivateOrReservedIP(u.Host); err != nil {
			return nil, err
		}
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

	// Custom Director: set target scheme/host/path and remove incoming hop-by-hop
	// headers that may have been injected by the client (defense-in-depth).
	defaultDirector := t.proxy.Director
	t.proxy.Director = func(req *http.Request) {
		defaultDirector(req)
		// Remove headers that should not be forwarded upstream.
		// Go's ReverseProxy strips standard hop-by-hop headers, but clients can
		// inject non-standard ones like X-Forwarded-Host to confuse backends.
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Real-IP")

			// Propagate correlation ID across hops. If the incoming request
			// already carries X-Correlation-ID (e.g., from another WAF node),
			// preserve it. Otherwise use X-GuardianWAF-RequestID if present.
			if req.Header.Get("X-Correlation-ID") == "" {
				if rid := req.Header.Get("X-GuardianWAF-RequestID"); rid != "" {
					req.Header.Set("X-Correlation-ID", rid)
				}
			}
	}

	transport := &http.Transport{
		DialContext:           SSRFDialContext(),
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxConnsPerHost:       100,
	}
	t.proxy.Transport = transport
	// Enable immediate flushing for streaming (SSE, WebSocket upgrade, chunked)
	t.proxy.FlushInterval = -1

	// Wire error handler for circuit breaker
	t.proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Drain the request body so the connection can be reused for keep-alive.
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			r.Body.Close()
		}
		t.circuit.RecordFailure()
		// Store error on the writer so ServeHTTP can return it.
		if pw, ok := w.(*proxyError); ok {
			pw.err = err
		}
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
// Returns an error if the upstream was unreachable (so the router can retry).
// If the circuit breaker is open, writes 503 and returns nil (not retryable).
func (t *Target) ServeHTTP(w http.ResponseWriter, r *http.Request, stripPrefix string) error {
	if !t.circuit.Allow() {
		http.Error(w, "503 Service Unavailable - Circuit breaker open", http.StatusServiceUnavailable)
		return nil
	}

	t.activeConns.Add(1)
	defer t.activeConns.Add(-1)

	// Track whether the ErrorHandler was invoked (upstream unreachable).
	proxyErr := &proxyError{ResponseWriter: w}
	if stripPrefix != "" {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r2.URL.Path, stripPrefix)
		if !strings.HasPrefix(r2.URL.Path, "/") {
			r2.URL.Path = "/" + r2.URL.Path
		}
		r2.URL.RawPath = ""
		t.proxy.ServeHTTP(proxyErr, r2)
	} else {
		t.proxy.ServeHTTP(proxyErr, r)
	}

	if proxyErr.err != nil {
		return proxyErr.err
	}
	return nil
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

// Close releases resources held by the target, including idle transport connections.
// Call this when removing a target during routing reconfiguration.
func (t *Target) Close() {
	if tr, ok := t.proxy.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}
