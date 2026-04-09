package acme

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTP01Handler serves ACME HTTP-01 challenge responses.
// Mount it on the HTTP server to handle /.well-known/acme-challenge/ requests.
type HTTP01Handler struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> keyAuthorization

	// Rate limiting — simple per-IP request counter with sliding window
	rlMu    sync.Mutex
	rlReqs  map[string][]time.Time // IP → request timestamps
	rlLimit int                    // max requests per window
	rlWin   time.Duration          // sliding window duration
}

const (
	acmeRateLimit  = 10  // max requests per window per IP
	acmeRateWindow = 60 * time.Second
)

// NewHTTP01Handler creates a new HTTP-01 challenge handler.
func NewHTTP01Handler() *HTTP01Handler {
	return &HTTP01Handler{
		tokens:  make(map[string]string),
		rlReqs:  make(map[string][]time.Time),
		rlLimit: acmeRateLimit,
		rlWin:   acmeRateWindow,
	}
}

// SetToken provisions a challenge token with its key authorization.
func (h *HTTP01Handler) SetToken(token, keyAuth string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokens[token] = keyAuth
}

// ClearToken removes a provisioned token.
func (h *HTTP01Handler) ClearToken(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.tokens, token)
}

// ServeHTTP handles HTTP-01 challenge validation requests.
// Responds with the key authorization for the requested token.
func (h *HTTP01Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path: /.well-known/acme-challenge/<token>
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" || strings.ContainsAny(token, "/\\") || strings.Contains(token, "..") {
		http.NotFound(w, r)
		return
	}

	// Rate limit — per-IP sliding window
	if !h.allow(r) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	h.mu.RLock()
	keyAuth, ok := h.tokens[token]
	h.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write([]byte(keyAuth))
}

// allow checks if a request from this IP is within the rate limit.
func (h *HTTP01Handler) allow(r *http.Request) bool {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	h.rlMu.Lock()
	defer h.rlMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-h.rlWin)

	// Filter out expired timestamps
	times := h.rlReqs[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	h.rlReqs[ip] = valid

	if len(valid) >= h.rlLimit {
		return false
	}

	h.rlReqs[ip] = append(h.rlReqs[ip], now)

	// Periodic cleanup — if map is getting large, clear old entries
	if len(h.rlReqs) > 1000 {
		for k, ts := range h.rlReqs {
			recent := false
			for _, t := range ts {
				if t.After(cutoff) {
					recent = true
					break
				}
			}
			if !recent {
				delete(h.rlReqs, k)
			}
		}
	}

	return true
}
