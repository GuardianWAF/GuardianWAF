package mcp

import (
	"net/http/httptest"
	"testing"
)

type countingGuard struct {
	failures map[string]int
	limit    int
}

func (g *countingGuard) AuthAllowed(ip string) bool { return g.failures[ip] < g.limit }
func (g *countingGuard) AuthFailed(ip string)       { g.failures[ip]++ }

// Regression: /mcp/sse and /mcp/message checked the dashboard key with no
// limiter, allowing unlimited online key guessing past the /login lockout.
func TestSSEAuthGuardThrottlesKeyGuessing(t *testing.T) {
	h := NewSSEHandler(NewServer(nil, nil), "correct-key")
	g := &countingGuard{failures: map[string]int{}, limit: 3}
	h.SetAuthGuard(g)

	req := func(ip, key string) bool {
		r := httptest.NewRequest("POST", "/mcp/message", nil)
		r.RemoteAddr = ip + ":5555"
		r.Header.Set("X-API-Key", key)
		return h.authenticate(r)
	}

	for range 3 {
		if req("203.0.113.9", "wrong") {
			t.Fatal("wrong key authenticated")
		}
	}
	if g.failures["203.0.113.9"] != 3 {
		t.Fatalf("failures recorded = %d, want 3 (keyed by host, not host:port)", g.failures["203.0.113.9"])
	}
	if req("203.0.113.9", "correct-key") {
		t.Fatal("locked-out client authenticated with the correct key")
	}
	if !req("203.0.113.10", "correct-key") {
		t.Fatal("unrelated client was rejected")
	}
}
