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

func (pe *proxyError) WriteHeader(code int)        { pe.ResponseWriter.WriteHeader(code) }
func (pe *proxyError) Write(p []byte) (int, error) { return pe.ResponseWriter.Write(p) }

// Target represents a single backend server with its reverse proxy and stats.
type Target struct {
	URL         *url.URL
	Weight      int
	proxy       *httputil.ReverseProxy
	circuit     *CircuitBreaker
	activeConns atomic.Int64
	healthy     atomic.Bool
	closed      atomic.Bool
	lastCheck   atomic.Value // stores time.Time
	policy      TargetPolicy
}

// TargetPolicy controls backend SSRF protection for one target/router
// generation. Prefer this over package-global test hooks in production paths.
type TargetPolicy struct {
	AllowPrivateTargets bool
	AllowedCIDRs        []*net.IPNet
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
		return classifyIPWithAllowedCIDRs(ip, host, allowedUpstreamNets())
	}

	// Resolve hostname to IPs
	ips, err := net.LookupIP(h)
	if err != nil {
		return nil // DNS resolution failed — will be caught by proxy transport
	}

	for _, addr := range ips {
		if err := classifyIPWithAllowedCIDRs(addr, host, allowedUpstreamNets()); err != nil {
			return err
		}
	}
	return nil
}

// IsPrivateOrReservedIPWithPolicy checks a host against the supplied per-target
// policy instead of package-global test/runtime state.
func IsPrivateOrReservedIPWithPolicy(host string, policy TargetPolicy) error {
	if policy.AllowPrivateTargets {
		return nil
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	ip := net.ParseIP(h)
	if ip != nil {
		return classifyIPWithAllowedCIDRs(ip, host, policy.AllowedCIDRs)
	}
	ips, err := net.LookupIP(h)
	if err != nil {
		return nil
	}
	for _, addr := range ips {
		if err := classifyIPWithAllowedCIDRs(addr, host, policy.AllowedCIDRs); err != nil {
			return err
		}
	}
	return nil
}

func validateTargetURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("target URL scheme must be http or https; got %q", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("target URL host must not be empty")
	}
	return u, nil
}

func classifyIP(ip net.IP, host string) error {
	return classifyIPWithAllowedCIDRs(ip, host, nil)
}

func classifyIPWithAllowedCIDRs(ip net.IP, host string, allowed []*net.IPNet) error {
	if ipAllowedByCIDRs(ip, allowed) {
		return nil
	}
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

func ipAllowedByCIDRs(ip net.IP, allowed []*net.IPNet) bool {
	for _, cidr := range allowed {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// allowPrivateTargets is set to true in tests to allow httptest.NewServer URLs.
var allowPrivateTargets atomic.Bool
var allowedUpstreamCIDRs atomic.Value // stores []*net.IPNet

// SetPrivateTargetsAllowed controls whether upstream targets may resolve to
// private, loopback, link-local, or otherwise reserved IP ranges.
func SetPrivateTargetsAllowed(allowed bool) {
	allowPrivateTargets.Store(allowed)
}

// SetAllowedUpstreamCIDRs controls the narrow private/reserved upstream CIDR
// allowlist used when global private target allowance is disabled.
func SetAllowedUpstreamCIDRs(cidrs []string) error {
	parsed, err := ParseAllowedUpstreamCIDRs(cidrs)
	if err != nil {
		return err
	}
	allowedUpstreamCIDRs.Store(parsed)
	return nil
}

// ParseAllowedUpstreamCIDRs validates and parses upstream CIDR/IP allowlists.
func ParseAllowedUpstreamCIDRs(cidrs []string) ([]*net.IPNet, error) {
	parsed := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			ip, cidr, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid allowed upstream CIDR %q: %w", raw, err)
			}
			ones, _ := cidr.Mask.Size()
			if ip.IsUnspecified() {
				return nil, fmt.Errorf("invalid allowed upstream CIDR %q: unspecified ranges are not allowed", raw)
			}
			if ip.IsMulticast() {
				return nil, fmt.Errorf("invalid allowed upstream CIDR %q: multicast ranges are not allowed", raw)
			}
			if ones == 0 {
				return nil, fmt.Errorf("invalid allowed upstream CIDR %q: all-address ranges are not allowed", raw)
			}
			parsed = append(parsed, cidr)
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("invalid allowed upstream IP %q", raw)
		}
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("invalid allowed upstream IP %q: unspecified addresses are not allowed", raw)
		}
		if ip.IsMulticast() {
			return nil, fmt.Errorf("invalid allowed upstream IP %q: multicast addresses are not allowed", raw)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		parsed = append(parsed, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return parsed, nil
}

func allowedUpstreamNets() []*net.IPNet {
	if v := allowedUpstreamCIDRs.Load(); v != nil {
		if cidrs, ok := v.([]*net.IPNet); ok {
			return cidrs
		}
	}
	return nil
}

// SSRFDialContext returns a DialContext function that validates the resolved IP
// against private/reserved ranges at connection time. This prevents DNS rebinding
// attacks where DNS resolves to a public IP at validation time but to a private IP
// at actual connection time (TOCTOU gap).
func SSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return SSRFDialContextWithPolicy(TargetPolicy{
		AllowPrivateTargets: allowPrivateTargets.Load(),
		AllowedCIDRs:        allowedUpstreamNets(),
	})
}

// SSRFDialContextWithPolicy returns a DialContext function bound to a specific
// backend SSRF policy. It resolves and validates IPs once, then dials the
// validated IP directly to avoid DNS rebinding TOCTOU gaps.
func SSRFDialContextWithPolicy(policy TargetPolicy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if policy.AllowPrivateTargets {
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
			if err := classifyIPWithAllowedCIDRs(ip, host, policy.AllowedCIDRs); err == nil {
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
	return NewTargetWithPolicy(rawURL, weight, TargetPolicy{
		AllowPrivateTargets: allowPrivateTargets.Load(),
		AllowedCIDRs:        allowedUpstreamNets(),
	})
}

// NewTargetWithPolicy creates a backend target bound to an instance-scoped SSRF
// policy. This avoids cross-router interference from package-global policy state.
func NewTargetWithPolicy(rawURL string, weight int, policy TargetPolicy) (*Target, error) {
	u, err := validateTargetURL(rawURL)
	if err != nil {
		return nil, err
	}
	if weight <= 0 {
		weight = 1
	}

	// SSRF prevention: block targets resolving to private/reserved IPs
	if !policy.AllowPrivateTargets {
		if err := IsPrivateOrReservedIPWithPolicy(u.Host, policy); err != nil {
			return nil, err
		}
	}

	t := &Target{
		URL:    u,
		Weight: weight,
		policy: policy,
		circuit: NewCircuitBreaker(CircuitConfig{
			Threshold:    5,
			ResetTimeout: 30 * time.Second,
		}),
	}
	t.healthy.Store(true) // healthy by default until proven otherwise
	t.lastCheck.Store(time.Time{})

	// Build reverse proxy with sensible timeouts
	// Reverse proxy via the Rewrite hook. httputil.ReverseProxy.Director is
	// deprecated as of Go 1.26; Rewrite reproduces NewSingleHostReverseProxy plus
	// the previous custom Director exactly (inbound Host preserved, X-Forwarded-For
	// peer-append, client-injected forwarding headers stripped, correlation-ID
	// propagated). Equivalence is pinned by TestTarget_ForwardedHeaderHandling.
	t.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)             // route to target scheme/host/base-path
			pr.Out.Host = pr.In.Host // preserve the inbound Host header upstream

			// Append the immediate peer IP to X-Forwarded-For. Director mode did
			// this automatically in ServeHTTP; Rewrite mode does not — and it also
			// strips the inbound chain from pr.Out — so read the prior chain from
			// pr.In and replicate the append (SetXForwarded would drop the chain).
			if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				if prior := pr.In.Header.Values("X-Forwarded-For"); len(prior) > 0 {
					clientIP = strings.Join(prior, ", ") + ", " + clientIP
				}
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}

			// Strip client-injected forwarding headers (defense-in-depth): clients
			// can set non-standard ones like X-Forwarded-Host to confuse backends.
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("X-Real-IP")

			// Propagate correlation ID across hops; preserve an existing one.
			if pr.Out.Header.Get("X-Correlation-ID") == "" {
				if rid := pr.Out.Header.Get("X-GuardianWAF-RequestID"); rid != "" {
					pr.Out.Header.Set("X-Correlation-ID", rid)
				}
			}
		},
	}

	transport := &http.Transport{
		DialContext:           SSRFDialContextWithPolicy(policy),
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
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
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20)) // nolint:errcheck // #nosec G104 -- response body drain; error ignored
			r.Body.Close() // #nosec G104 -- best-effort close; error not actionable
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
	t.closed.Store(true)
	if tr, ok := t.proxy.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// Closed reports whether Close has been called for this target.
func (t *Target) Closed() bool {
	return t.closed.Load()
}
