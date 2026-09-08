package ratelimit

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: Process ran matchesRule and bucketKey on the RAW wire path
// (ctx.Path). Every detection layer resolves the request path via the
// NormalizedPath||Path dual-view precisely because raw paths can dodge
// literal matching — but the rate limiter missed that pattern. A request to
// "/%61dmin/api/users" is the same decoded path as "/admin/api/users", yet:
//   - matchesRule's glob ("/admin/**") never matches the encoded form, so
//     the rule does not apply at all, and
//   - even when matched, bucketKey's path.Clean keeps "%61dmin" literal, so
//     each encoding variant gets a fresh bucket.
//
// Result: ip+path-scoped rate limits were bypassable by trivial percent-
// encoding rotation.

func encodedPathCtx(ip net.IP, rawPath, normalizedPath string) *engine.RequestContext {
	return &engine.RequestContext{
		ClientIP:       ip,
		Path:           rawPath,
		NormalizedPath: normalizedPath,
		TenantWAFConfig: &config.WAFConfig{
			RateLimit: config.RateLimitConfig{Enabled: true},
		},
	}
}

func TestRateLimitEncodedPathBypass(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID:     "RL-ADMIN",
			Scope:  "ip+path",
			Paths:  []string{"/admin/**"},
			Limit:  2,
			Window: time.Minute,
			Action: "block",
		}},
	})
	ip := net.ParseIP("10.0.0.5")

	// Two hits on the literal path exhaust the limit.
	for i := 0; i < 2; i++ {
		l.Process(encodedPathCtx(ip, "/admin/api/users", "/admin/api/users"))
	}
	if res := l.Process(encodedPathCtx(ip, "/admin/api/users", "/admin/api/users")); res.Action != engine.ActionBlock {
		t.Fatalf("FAIL: literal-path request not blocked after limit (action=%v)", res.Action)
	}

	// The percent-encoded path decodes to the same path — it must share the
	// bucket and be blocked too.
	res := l.Process(encodedPathCtx(ip, "/%61dmin/api/users", "/admin/api/users"))
	if res.Action == engine.ActionPass {
		t.Fatalf("FAIL: percent-encoded path bypassed the ip+path rate limit (action=%v, findings=%v)", res.Action, res.Findings)
	}
}
