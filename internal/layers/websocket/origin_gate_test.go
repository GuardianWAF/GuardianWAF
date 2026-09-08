package websocket

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression: the origin gate was wrapped in `len(AllowedOrigins) > 0`, so the
// zero-value empty list silently disabled CSWSH protection — any browser
// origin could open an inspected WebSocket connection. The gate now always
// runs: an empty list denies origin-carrying (browser) requests, while
// non-browser clients (no Origin header) are unaffected.
func TestEmptyOriginsDenyBrowserRequests(t *testing.T) {
	l := NewLayer(&Config{
		IdleTimeout:         time.Second,
		AllowedOrigins:      nil, // the zero value
		AllowedBackendHosts: []string{"backend.internal"},
	})

	// A browser client from a non-allowlisted origin must be rejected with
	// 403 from the ORIGIN gate. Pre-fix it fell through the skipped origin
	// check to the non-hijackable fallthrough (404) — accepted, not blocked.
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "backend.internal"
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	l.handleWebSocket(rec, req, http.NotFoundHandler())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("FAIL: cross-origin browser request accepted with zero-value AllowedOrigins (status %d) — CSWSH protection silently off", rec.Code)
	}

	// A non-browser client (no Origin header) is unaffected by the gate.
	req2 := httptest.NewRequest("GET", "/ws", nil)
	req2.Host = "backend.internal"
	req2.Header.Set("Upgrade", "websocket")
	req2.Header.Set("Connection", "Upgrade")
	req2.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req2.Header.Set("Sec-WebSocket-Version", "13")
	rec2 := httptest.NewRecorder()
	l.handleWebSocket(rec2, req2, http.NotFoundHandler())
	if rec2.Code == http.StatusForbidden {
		t.Fatalf("FAIL: non-browser client (no Origin header) blocked by the origin gate")
	}

	// An allowlisted origin with a configured list is still accepted.
	l2 := NewLayer(&Config{
		IdleTimeout:         time.Second,
		AllowedOrigins:      []string{"https://app.example"},
		AllowedBackendHosts: []string{"backend.internal"},
	})
	req3 := httptest.NewRequest("GET", "/ws", nil)
	req3.Host = "backend.internal"
	req3.Header.Set("Upgrade", "websocket")
	req3.Header.Set("Connection", "Upgrade")
	req3.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req3.Header.Set("Sec-WebSocket-Version", "13")
	req3.Header.Set("Origin", "https://app.example")
	rec3 := httptest.NewRecorder()
	l2.handleWebSocket(rec3, req3, http.NotFoundHandler())
	if rec3.Code == http.StatusForbidden {
		t.Fatalf("FAIL: allowlisted origin rejected when list is configured")
	}
}
