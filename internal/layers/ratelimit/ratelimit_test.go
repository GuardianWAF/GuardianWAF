package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

func makeContext(ip, path string) *engine.RequestContext {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":12345"
	return engine.AcquireContext(req, 2, 1024)
}

func TestRateLimit_WithinLimit(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "global",
				Scope:  "ip",
				Limit:  10,
				Window: 1 * time.Second,
				Burst:  10,
				Action: "block",
			},
		},
	})

	// 10 requests within limit
	for i := 0; i < 10; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)

		if result.Action != engine.ActionPass {
			t.Fatalf("request %d: expected pass, got %v", i+1, result.Action)
		}
	}
}

func TestRateLimit_ExceedLimitBlock(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "strict",
				Scope:  "ip",
				Limit:  5,
				Window: 1 * time.Second,
				Burst:  5,
				Action: "block",
			},
		},
	})

	// Exhaust limit
	for i := 0; i < 5; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}

	// 6th request should be blocked
	ctx := makeContext("1.2.3.4", "/test")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)

	if result.Action != engine.ActionBlock {
		t.Fatalf("expected block, got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Description != "Rate limit exceeded: strict" {
		t.Fatalf("unexpected description: %s", result.Findings[0].Description)
	}
}

func TestRateLimit_BurstHandling(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "burst-test",
				Scope:  "ip",
				Limit:  5,
				Window: 1 * time.Second,
				Burst:  10, // allow burst of 10
				Action: "block",
			},
		},
	})

	// Should allow 10 burst requests
	allowed := 0
	for i := 0; i < 15; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)

		if result.Action == engine.ActionPass {
			allowed++
		}
	}

	if allowed != 10 {
		t.Fatalf("expected 10 allowed (burst), got %d", allowed)
	}
}

func TestRateLimit_IPScoped(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "per-ip",
				Scope:  "ip",
				Limit:  3,
				Window: 1 * time.Second,
				Burst:  3,
				Action: "block",
			},
		},
	})

	// IP1: 3 requests (should all pass)
	for i := 0; i < 3; i++ {
		ctx := makeContext("10.0.0.1", "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("IP1 request %d: expected pass", i+1)
		}
	}

	// IP1: 4th request (should be blocked)
	ctx := makeContext("10.0.0.1", "/test")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("IP1 request 4: expected block")
	}

	// IP2: should still be allowed (separate bucket)
	ctx = makeContext("10.0.0.2", "/test")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("IP2 request 1: expected pass (separate bucket)")
	}
}

func TestRateLimit_IPPathScoped(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "per-ip-path",
				Scope:  "ip+path",
				Limit:  2,
				Window: 1 * time.Second,
				Burst:  2,
				Action: "block",
			},
		},
	})

	ip := "10.0.0.1"

	// Path /a: 2 requests
	for i := 0; i < 2; i++ {
		ctx := makeContext(ip, "/a")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("/a request %d: expected pass", i+1)
		}
	}

	// Path /a: 3rd should be blocked
	ctx := makeContext(ip, "/a")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("/a request 3: expected block")
	}

	// Path /b: should still be allowed (separate bucket)
	ctx = makeContext(ip, "/b")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("/b request 1: expected pass (separate bucket)")
	}
}

func TestRateLimit_PathPatternMatching(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "api-only",
				Scope:  "ip",
				Paths:  []string{"/api/**"},
				Limit:  2,
				Window: 1 * time.Second,
				Burst:  2,
				Action: "block",
			},
		},
	})

	// Non-API path should not be rate limited
	for i := 0; i < 10; i++ {
		ctx := makeContext("1.2.3.4", "/static/page.html")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("non-API request %d: expected pass", i+1)
		}
	}

	// API path should be rate limited
	for i := 0; i < 2; i++ {
		ctx := makeContext("1.2.3.4", "/api/users")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("API request %d: expected pass", i+1)
		}
	}

	ctx := makeContext("1.2.3.4", "/api/users")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("API request 3: expected block")
	}
}

func TestRateLimit_MultipleRules(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "global",
				Scope:  "ip",
				Limit:  100,
				Window: 1 * time.Second,
				Burst:  100,
				Action: "block",
			},
			{
				ID:     "login",
				Scope:  "ip",
				Paths:  []string{"/login"},
				Limit:  3,
				Window: 1 * time.Minute,
				Burst:  3,
				Action: "block",
			},
		},
	})

	// 3 login requests should pass (both rules allow)
	for i := 0; i < 3; i++ {
		ctx := makeContext("1.2.3.4", "/login")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("login request %d: expected pass", i+1)
		}
	}

	// 4th login request should be blocked by the login rule
	ctx := makeContext("1.2.3.4", "/login")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("login request 4: expected block by login rule")
	}

	// Non-login requests should still pass (global rule has 100 limit)
	ctx = makeContext("1.2.3.4", "/dashboard")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("dashboard request: expected pass")
	}
}

func TestRateLimit_AutoBanCallback(t *testing.T) {
	var autoBanCalled atomic.Int32
	var bannedIP string
	var mu sync.Mutex

	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:           "auto-ban-test",
				Scope:        "ip",
				Limit:        2,
				Window:       1 * time.Second,
				Burst:        2,
				Action:       "block",
				AutoBanAfter: 3, // auto-ban after 3 violations
			},
		},
	})

	layer.OnAutoBan = func(ip string, reason string) {
		mu.Lock()
		bannedIP = ip
		mu.Unlock()
		autoBanCalled.Add(1)
	}

	ip := "5.5.5.5"

	// Exhaust tokens (2 pass, then violations start)
	for i := 0; i < 2; i++ {
		ctx := makeContext(ip, "/test")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}

	// Generate 3 violations
	for i := 0; i < 3; i++ {
		ctx := makeContext(ip, "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionBlock {
			t.Fatalf("violation %d: expected block", i+1)
		}
	}

	if autoBanCalled.Load() == 0 {
		t.Fatal("expected auto-ban callback to be called")
	}

	mu.Lock()
	if bannedIP != ip {
		t.Fatalf("expected banned IP %s, got %s", ip, bannedIP)
	}
	mu.Unlock()
}

func TestRateLimit_LogAction(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "log-only",
				Scope:  "ip",
				Limit:  1,
				Window: 1 * time.Second,
				Burst:  1,
				Action: "log",
			},
		},
	})

	// First request passes
	ctx := makeContext("1.2.3.4", "/test")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatalf("first request: expected pass, got %v", result.Action)
	}

	// Second request exceeds limit but action is "log" not "block"
	ctx = makeContext("1.2.3.4", "/test")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionLog {
		t.Fatalf("second request: expected log, got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestRateLimit_DisabledLayer(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: false,
		Rules: []Rule{
			{
				ID:     "disabled",
				Scope:  "ip",
				Limit:  1,
				Window: 1 * time.Second,
				Burst:  1,
				Action: "block",
			},
		},
	})

	for i := 0; i < 10; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("request %d: expected pass (disabled), got %v", i+1, result.Action)
		}
	}
}

func TestRateLimit_ConcurrentAccess(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "concurrent",
				Scope:  "ip",
				Limit:  1000,
				Window: 1 * time.Second,
				Burst:  1000,
				Action: "block",
			},
		},
	})

	var wg sync.WaitGroup
	const goroutines = 50
	const requestsPerGoroutine = 20

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < requestsPerGoroutine; i++ {
				ctx := makeContext("10.0.0.1", "/test")
				layer.Process(ctx)
				engine.ReleaseContext(ctx)
			}
		}(g)
	}

	wg.Wait()
}

func TestRateLimit_CleanupExpired(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "cleanup-test",
				Scope:  "ip",
				Limit:  10,
				Window: 1 * time.Second,
				Burst:  10,
				Action: "block",
			},
		},
	})

	// Create some buckets
	for i := 0; i < 5; i++ {
		ctx := makeContext("10.0.0.1", "/test")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}

	// Verify bucket exists
	found := false
	layer.buckets.Range(func(key, value any) bool {
		found = true
		return false
	})
	if !found {
		t.Fatal("expected at least one bucket")
	}

	// Cleanup with zero stale duration should remove everything
	// (because all buckets were accessed "in the past")
	time.Sleep(5 * time.Millisecond)
	layer.CleanupExpired(1 * time.Millisecond)

	found = false
	layer.buckets.Range(func(key, value any) bool {
		found = true
		return false
	})
	if found {
		t.Fatal("expected all buckets to be cleaned up")
	}
}

func TestRateLimit_Name(t *testing.T) {
	layer := NewLayer(Config{})
	if layer.Name() != "ratelimit" {
		t.Fatalf("expected name 'ratelimit', got %q", layer.Name())
	}
}

func TestRateLimit_RefillAllowsMoreRequests(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "refill",
				Scope:  "ip",
				Limit:  100, // 100 per second
				Window: 1 * time.Second,
				Burst:  5, // but only 5 burst
				Action: "block",
			},
		},
	})

	// Exhaust the burst
	for i := 0; i < 5; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("request %d should pass", i+1)
		}
	}

	// Should be blocked now
	ctx := makeContext("1.2.3.4", "/test")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("should be blocked after burst")
	}

	// Wait for refill (100/s = 1 per 10ms, wait 50ms for ~5 tokens)
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	ctx = makeContext("1.2.3.4", "/test")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("should pass after refill")
	}
}

func TestRateLimit_EmptyPathsMatchAll(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "no-paths",
				Scope:  "ip",
				Paths:  []string{}, // empty = match all
				Limit:  2,
				Window: 1 * time.Second,
				Burst:  2,
				Action: "block",
			},
		},
	})

	// Any path should match
	for i := 0; i < 2; i++ {
		ctx := makeContext("1.2.3.4", "/anything"+string(rune('0'+i)))
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Fatalf("request %d: expected pass", i+1)
		}
	}

	ctx := makeContext("1.2.3.4", "/other")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("expected block after exceeding limit")
	}
}

func TestRateLimit_GlobPatternMatch(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID:     "glob-test",
				Scope:  "ip",
				Paths:  []string{"/api/*"},
				Limit:  1,
				Window: 1 * time.Second,
				Burst:  1,
				Action: "block",
			},
		},
	})

	// /api/users should match /api/*
	ctx := makeContext("1.2.3.4", "/api/users")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("first matching request: expected pass")
	}

	// Second should be blocked
	ctx = makeContext("1.2.3.4", "/api/orders")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Fatal("second matching request: expected block")
	}

	// Non-matching path should pass
	ctx = makeContext("1.2.3.4", "/home")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Fatal("non-matching path: expected pass")
	}
}
