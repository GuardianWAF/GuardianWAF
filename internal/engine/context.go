package engine

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

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
	BodyString  string
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

	// Headers
	ctx.Headers = make(map[string][]string, len(r.Header))
	for k, v := range r.Header {
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

	// Body reading — read for inspection, then restore for downstream proxying
	if r.Body != nil && !ctx.bodyRead {
		limited := io.LimitReader(r.Body, maxBodySize)
		data, err := io.ReadAll(limited)
		if err == nil {
			ctx.Body = data
			ctx.BodyString = string(data)
			// Restore body so reverse proxies can forward it
			r.Body = io.NopCloser(bytes.NewReader(data))
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

	ctx.bodyRead = false

	contextPool.Put(ctx)
}

// extractClientIP determines the real client IP from the request.
// It checks X-Forwarded-For, then X-Real-IP, then falls back to RemoteAddr.
func extractClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For first (take the first IP in the list)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ipStr := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(ipStr); ip != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ipStr := strings.TrimSpace(xri)
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr (strip port)
	addr := r.RemoteAddr
	if addr == "" {
		return nil
	}

	// Try to split host:port
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe there's no port (bare IP)
		if ip := net.ParseIP(addr); ip != nil {
			return ip
		}
		return nil
	}

	return net.ParseIP(host)
}

// generateRequestID creates a unique request identifier formatted as a UUID-like string.
// Uses crypto/rand for cryptographically secure random bytes.
func generateRequestID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback: return a zero-filled ID (extremely unlikely path)
		return "00000000-0000-0000-0000-000000000000"
	}
	h := hex.EncodeToString(b)
	// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
