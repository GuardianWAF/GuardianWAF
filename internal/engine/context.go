package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/tracing"
)

// randReader allows tests to inject failures for generateRequestID.
var randReader = rand.Read

// trustedProxyCIDRs holds parsed CIDRs for trusted proxy detection.
// Only requests from these CIDRs will have their X-Forwarded-For / X-Real-IP headers trusted.
// When empty (default), proxy headers are never trusted — RemoteAddr is always used.
var (
	trustedProxyCIDRs []*net.IPNet
	trustedProxyMu    sync.RWMutex
)

// SetTrustedProxies configures the list of trusted proxy CIDRs.
// Only connections originating from these CIDRs will have their
// X-Forwarded-For and X-Real-IP headers honored.
// Accepts CIDR notation ("10.0.0.0/8") or single IPs ("10.0.0.1").
func SetTrustedProxies(cidrs []string) {
	var parsed []*net.IPNet
	for _, s := range cidrs {
		if !strings.Contains(s, "/") {
			// Single IP — convert to /32 or /128
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			parsed = append(parsed, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		// Reject overly broad CIDRs that would trust all connections
		if cidr.IP.IsUnspecified() {
			ones, _ := cidr.Mask.Size()
			if ones == 0 {
				fmt.Printf("[engine] WARNING: rejecting overly broad trusted proxy CIDR %q — would trust all connections\n", s)
				continue
			}
		}
		parsed = append(parsed, cidr)
	}
	trustedProxyMu.Lock()
	trustedProxyCIDRs = parsed
	trustedProxyMu.Unlock()
}

// isTrustedProxy checks if the given IP is within a configured trusted proxy CIDR.
func isTrustedProxy(ip net.IP) bool {
	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// RequestContext carries all per-request state through the WAF pipeline.
// Allocated from a sync.Pool to minimize GC pressure.
type RequestContext struct {
	// Original request reference
	Request *http.Request

	// Parsed client information
	ClientIP net.IP

	// Request components (populated from Request)
	Method      string
	URI         string
	Path        string // URL path
	QueryParams map[string][]string
	Headers     map[string][]string
	Cookies     map[string]string
	Body        []byte
	BodyString  string // Lazy: populated on first access via GetBodyString(). Allocated to avoid per-request string([]byte) if no body.
	ContentType string

	// Normalized versions (populated by sanitizer layer)
	NormalizedPath    string
	NormalizedQuery   map[string][]string
	NormalizedBody    string
	NormalizedHeaders map[string][]string

	// Scoring
	Accumulator *ScoreAccumulator
	Action      Action

	// Metadata
	RequestID string
	StartTime time.Time
	Metadata  map[string]any

	// TLS info for bot detection
	TLSVersion     uint16
	TLSCipherSuite uint16
	ServerName     string

	// JA4 TLS fingerprinting data (populated by custom TLS handler if available)
	// These fields enable full JA4 fingerprint computation
	JA4Ciphers  []uint16 // TLS cipher suites from ClientHello
	JA4Exts     []uint16 // TLS extensions from ClientHello
	JA4ALPN     string   // First ALPN value
	JA4SigAlgs  []uint16 // Signature algorithms in original order
	JA4Protocol string   // "t" (TLS), "q" (QUIC), or "d" (DTLS)
	JA4SNI      bool     // Whether SNI extension exists
	JA4Ver      uint16   // Highest TLS version from supported_versions extension

	// Tenant info (set by engine middleware for multi-tenant)
	TenantID       string         // Tenant identifier (empty = global/default)
	TenantWAFConfig *config.WAFConfig // Per-tenant WAF config override (nil = use global)

	// Tracing (set by engine if tracing is enabled and request is sampled)
	TraceSpan *tracing.Span

	// Internal
	bodyRead bool
}

// contextPool is the package-level sync.Pool for RequestContext reuse.
var contextPool = sync.Pool{
	New: func() any {
		return &RequestContext{}
	},
}

// AcquireContext retrieves a RequestContext from the pool, populates it from
// the given HTTP request, and returns it ready for pipeline processing.
// paranoiaLevel controls the score multiplier (1-4).
// maxBodySize limits how many bytes of the request body are read.
func AcquireContext(r *http.Request, paranoiaLevel int, maxBodySize int64) *RequestContext {
	ctx := contextPool.Get().(*RequestContext)

	ctx.Request = r
	ctx.StartTime = time.Now()
	ctx.RequestID = generateRequestID()
	ctx.Action = ActionPass

	// Parse request components
	ctx.Method = r.Method
	ctx.URI = r.RequestURI
	if ctx.URI == "" {
		ctx.URI = r.URL.String()
	}
	ctx.Path = r.URL.Path

	// Query parameters
	ctx.QueryParams = make(map[string][]string, len(r.URL.Query()))
	for k, v := range r.URL.Query() {
		cp := make([]string, len(v))
		copy(cp, v)
		ctx.QueryParams[k] = cp
	}

	// Headers — limit to prevent memory exhaustion from excessive header injection
	ctx.Headers = make(map[string][]string, min(len(r.Header), 100))
	for k, v := range r.Header {
		if len(ctx.Headers) >= 100 {
			break // Excessive headers — stop processing to prevent resource exhaustion
		}
		cp := make([]string, len(v))
		copy(cp, v)
		ctx.Headers[k] = cp
	}

	// Cookies
	cookies := r.Cookies()
	ctx.Cookies = make(map[string]string, len(cookies))
	for _, c := range cookies {
		ctx.Cookies[c.Name] = c.Value
	}

	// Content-Type
	ctx.ContentType = r.Header.Get("Content-Type")

	// Client IP
	ctx.ClientIP = extractClientIP(r)

	// Body reading — read for inspection, then restore for downstream proxying.
	// Decompresses gzip/deflate bodies so detectors can inspect actual content.
	if r.Body != nil && !ctx.bodyRead {
		limited := io.LimitReader(r.Body, maxBodySize)
		rawData, err := io.ReadAll(limited)
		if err == nil {
			// Restore original body for proxying (always raw/compressed)
			r.Body = io.NopCloser(bytes.NewReader(rawData))

			// Decompress for WAF inspection based on Content-Encoding.
			// Rejects decompression bombs (ratio > 100:1).
			inspectData := rawData
			switch strings.ToLower(r.Header.Get("Content-Encoding")) {
			case "gzip":
				if gr, err := gzip.NewReader(bytes.NewReader(rawData)); err == nil {
					if decompressed, err := io.ReadAll(io.LimitReader(gr, maxBodySize)); err == nil {
						if len(rawData) > 0 && len(decompressed)/len(rawData) <= 100 {
							inspectData = decompressed
						}
					}
					gr.Close()
				}
			case "deflate":
				fr := flate.NewReader(bytes.NewReader(rawData))
				if decompressed, err := io.ReadAll(io.LimitReader(fr, maxBodySize)); err == nil {
					if len(rawData) > 0 && len(decompressed)/len(rawData) <= 100 {
						inspectData = decompressed
					}
				}
				fr.Close()
			}

			ctx.Body = inspectData
			if len(inspectData) > 0 {
				ctx.BodyString = string(inspectData)
			}
		}
		ctx.bodyRead = true
	}

	// TLS info
	if r.TLS != nil {
		ctx.TLSVersion = r.TLS.Version
		ctx.TLSCipherSuite = r.TLS.CipherSuite
		ctx.ServerName = r.TLS.ServerName
	}

	// Scoring accumulator
	ctx.Accumulator = NewScoreAccumulator(paranoiaLevel)

	// Metadata
	ctx.Metadata = make(map[string]any)

	return ctx
}

// ReleaseContext resets all fields on the RequestContext and returns it to the pool.
func ReleaseContext(ctx *RequestContext) {
	// Clear all fields to avoid retaining references
	ctx.Request = nil
	ctx.ClientIP = nil

	ctx.Method = ""
	ctx.URI = ""
	ctx.Path = ""
	ctx.QueryParams = nil
	ctx.Headers = nil
	ctx.Cookies = nil
	ctx.Body = nil
	ctx.BodyString = ""
	ctx.ContentType = ""

	ctx.NormalizedPath = ""
	ctx.NormalizedQuery = nil
	ctx.NormalizedBody = ""
	ctx.NormalizedHeaders = nil

	ctx.Accumulator = nil
	ctx.Action = ActionPass

	ctx.RequestID = ""
	ctx.StartTime = time.Time{}
	ctx.Metadata = nil

	ctx.TLSVersion = 0
	ctx.TLSCipherSuite = 0
	ctx.ServerName = ""

	ctx.TenantID = ""
	ctx.TenantWAFConfig = nil

	// Clear JA4 TLS fingerprinting fields to prevent cross-request leakage
	ctx.JA4Ciphers = nil
	ctx.JA4Exts = nil
	ctx.JA4SigAlgs = nil
	ctx.JA4ALPN = ""
	ctx.JA4Protocol = ""
	ctx.JA4SNI = false
	ctx.JA4Ver = 0

	ctx.TraceSpan = nil

	ctx.bodyRead = false

	contextPool.Put(ctx)
}

// ExtractClientIP determines the real client IP from the request.
// When trusted proxies are configured, proxy headers (X-Forwarded-For, X-Real-IP)
// are only trusted if the direct connection comes from a trusted proxy.
// For X-Forwarded-For, the rightmost non-trusted IP is used (not the leftmost,
// which is attacker-controlled). When no trusted proxies are configured,
// proxy headers are ignored and RemoteAddr is always used.
func ExtractClientIP(r *http.Request) net.IP {
	return extractClientIP(r)
}

// extractClientIP determines the real client IP from the request.
// When trusted proxies are configured, proxy headers (X-Forwarded-For, X-Real-IP)
// are only trusted if the direct connection comes from a trusted proxy.
// For X-Forwarded-For, the rightmost non-trusted IP is used (not the leftmost,
// which is attacker-controlled). When no trusted proxies are configured,
// proxy headers are ignored and RemoteAddr is always used.
func extractClientIP(r *http.Request) net.IP {
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	if remoteIP == nil {
		return nil
	}

	// Only trust proxy headers if the direct peer is a trusted proxy
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}

	// Check X-Forwarded-For — walk from right to left, find the rightmost
	// IP that is NOT a trusted proxy (that's the real client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ipStr := strings.TrimSpace(parts[i])
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if !isTrustedProxy(ip) {
				return ip
			}
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}

	return remoteIP
}

// parseRemoteAddr extracts the IP from a RemoteAddr string (host:port or bare IP).
func parseRemoteAddr(addr string) net.IP {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}

// generateRequestID creates a unique request identifier formatted as a UUID-like string.
// Uses crypto/rand for cryptographically secure random bytes.
func generateRequestID() string {
	var b [16]byte
	_, err := randReader(b[:])
	if err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	var buf [36]byte
	hex.Encode(buf[:8], b[:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}
