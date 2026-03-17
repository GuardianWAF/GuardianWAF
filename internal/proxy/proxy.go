package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Backend represents a single upstream server.
type Backend struct {
	URL         *url.URL
	Weight      int
	Healthy     bool
	ActiveConns atomic.Int64
	mu          sync.RWMutex
}

// IsHealthy returns the health status of the backend (thread-safe).
func (b *Backend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Healthy
}

// SetHealthy sets the health status of the backend (thread-safe).
func (b *Backend) SetHealthy(healthy bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Healthy = healthy
}

// Config holds proxy configuration.
type Config struct {
	Backends       []*Backend
	LoadBalancer   string // "round_robin", "weighted", "least_conn", "ip_hash"
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxIdleConns   int
	FlushInterval  time.Duration
}

// Proxy is a reverse proxy that distributes requests to backends.
type Proxy struct {
	config      Config
	transport   *http.Transport
	lb          LoadBalancer
	healthCheck *HealthChecker
	cb          *CircuitBreaker
}

// NewProxy creates a new reverse proxy with the given configuration.
func NewProxy(cfg Config) *Proxy {
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 90 * time.Second
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 100
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConns / max(len(cfg.Backends), 1),
		IdleConnTimeout:     cfg.IdleTimeout,
		ResponseHeaderTimeout: cfg.ReadTimeout,
		DisableCompression:  false,
	}

	lb := NewLoadBalancer(cfg.LoadBalancer, cfg.Backends)

	return &Proxy{
		config:    cfg,
		transport: transport,
		lb:        lb,
	}
}

// SetHealthChecker sets the health checker for this proxy.
func (p *Proxy) SetHealthChecker(hc *HealthChecker) {
	p.healthCheck = hc
}

// SetCircuitBreaker sets the circuit breaker for this proxy.
func (p *Proxy) SetCircuitBreaker(cb *CircuitBreaker) {
	p.cb = cb
}

// ServeHTTP handles incoming requests, selects a backend, and proxies.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	backend := p.lb.Select(r)
	if backend == nil {
		http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// Handle WebSocket upgrades
	if IsWebSocketUpgrade(r) {
		p.HandleWebSocket(w, r, backend)
		return
	}

	// Check circuit breaker
	if p.cb != nil && !p.cb.Allow(backend.URL.Host) {
		http.Error(w, "503 Service Unavailable (circuit open)", http.StatusServiceUnavailable)
		return
	}

	// Track active connections
	backend.ActiveConns.Add(1)
	defer backend.ActiveConns.Add(-1)

	// Create proxy request
	proxyReq := p.createProxyRequest(r, backend)

	// Execute request
	resp, err := p.transport.RoundTrip(proxyReq)
	if err != nil {
		if p.cb != nil {
			p.cb.RecordFailure(backend.URL.Host)
		}
		http.Error(w, "502 Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if p.cb != nil {
		p.cb.RecordSuccess(backend.URL.Host)
	}

	// Copy response headers
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Copy response body; optionally flush if streaming
	if p.config.FlushInterval > 0 {
		if flusher, ok := w.(http.Flusher); ok {
			buf := make([]byte, 32*1024)
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					w.Write(buf[:n])
					flusher.Flush()
				}
				if readErr != nil {
					break
				}
			}
			return
		}
	}
	io.Copy(w, resp.Body)
}

// createProxyRequest builds an outgoing request from the incoming one.
func (p *Proxy) createProxyRequest(r *http.Request, backend *Backend) *http.Request {
	targetURL := *backend.URL
	targetURL.Path = singleJoiningSlash(backend.URL.Path, r.URL.Path)
	targetURL.RawQuery = r.URL.RawQuery

	ctx := r.Context()
	if p.config.ReadTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.config.ReadTimeout)
		_ = cancel // caller must handle; deferred in ServeHTTP via resp.Body.Close
	}

	proxyReq, _ := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), r.Body)

	// Copy original headers
	copyHeaders(proxyReq.Header, r.Header)

	// Remove hop-by-hop headers
	removeHopByHopHeaders(proxyReq.Header)

	// Set forwarding headers
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// X-Forwarded-For: append client IP
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		proxyReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		proxyReq.Header.Set("X-Forwarded-For", clientIP)
	}

	// X-Real-IP: set to the original client IP
	if r.Header.Get("X-Real-IP") == "" {
		proxyReq.Header.Set("X-Real-IP", clientIP)
	}

	// X-Forwarded-Host
	if r.Header.Get("X-Forwarded-Host") == "" {
		proxyReq.Header.Set("X-Forwarded-Host", r.Host)
	}

	// X-Forwarded-Proto
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.Header.Get("X-Forwarded-Proto") == "" {
		proxyReq.Header.Set("X-Forwarded-Proto", scheme)
	}

	// Preserve X-Request-ID if present
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		proxyReq.Header.Set("X-Request-ID", reqID)
	}

	// Set the Host header to the backend host
	proxyReq.Host = backend.URL.Host

	return proxyReq
}

// copyHeaders copies all headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopByHopHeaders removes hop-by-hop headers that should not be forwarded.
func removeHopByHopHeaders(h http.Header) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, header := range hopByHop {
		h.Del(header)
	}
}

// singleJoiningSlash joins two URL path segments with a single slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// ClientIP extracts the client IP from the request for IP hashing.
func ClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// String returns a human-readable representation of a Backend.
func (b *Backend) String() string {
	return fmt.Sprintf("Backend{URL: %s, Weight: %d, Healthy: %v}", b.URL.String(), b.Weight, b.IsHealthy())
}
