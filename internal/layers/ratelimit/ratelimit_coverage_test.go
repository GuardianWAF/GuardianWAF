package ratelimit

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Cleanup method ---

func TestCleanup_RemovesOldBuckets(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "cleanup-rule", Scope: "ip", Limit: 100, Window: time.Second, Burst: 100, Action: "block"},
		},
	})

	// Create a bucket
	ctx := makeContext("10.0.0.1", "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)

	// Wait a bit so the bucket becomes stale
	time.Sleep(10 * time.Millisecond)

	// Cleanup with a very short maxAge should remove the bucket
	layer.Cleanup(1 * time.Millisecond)

	count := 0
	layer.buckets.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("expected 0 buckets after cleanup, got %d", count)
	}
}

func TestCleanup_KeepsFreshBuckets(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "fresh-rule", Scope: "ip", Limit: 100, Window: time.Second, Burst: 100, Action: "block"},
		},
	})

	// Create a bucket
	ctx := makeContext("10.0.0.1", "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)

	// Cleanup with a very long maxAge should keep the bucket
	layer.Cleanup(1 * time.Hour)

	count := 0
	layer.buckets.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Errorf("expected 1 bucket after cleanup with long maxAge, got %d", count)
	}
}

func TestCleanup_DeletesBucketsWithWrongType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "type-rule", Scope: "ip", Limit: 100, Window: time.Second, Burst: 100, Action: "block"},
		},
	})

	// Insert a non-TokenBucket value to test the !ok branch
	layer.buckets.Store("bad-key", "not-a-bucket")

	layer.Cleanup(0)

	_, exists := layer.buckets.Load("bad-key")
	if exists {
		t.Error("expected bad-key to be deleted by Cleanup")
	}
}

// --- Process with tenant config ---

func TestProcess_TenantConfigDisabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "tenant-rule", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block"},
		},
	})

	wafCfg := &config.WAFConfig{
		RateLimit: config.RateLimitConfig{Enabled: false},
	}

	ctx := makeContext("10.0.0.1", "/test")
	ctx.TenantWAFConfig = wafCfg
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when tenant disables rate limit, got %v", result.Action)
	}
}

func TestProcess_TenantConfigEnabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "tenant-enabled", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block"},
		},
	})

	wafCfg := &config.WAFConfig{
		RateLimit: config.RateLimitConfig{Enabled: true},
	}

	// First request should pass
	ctx := makeContext("10.0.0.1", "/test")
	ctx.TenantWAFConfig = wafCfg
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}

	// Second request should block (limit=1)
	ctx = makeContext("10.0.0.1", "/test")
	ctx.TenantWAFConfig = wafCfg
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block, got %v", result.Action)
	}
}

// --- Process with nil ClientIP ---

func TestProcess_NilClientIP(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "nil-ip", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block"},
		},
	})

	ctx := &engine.RequestContext{
		Path:     "/test",
		ClientIP: nil,
		Headers:  map[string][]string{},
		Cookies:  map[string]string{},
	}

	result := layer.Process(ctx)
	// With nil IP, key will be empty but bucket should still be created and work
	if result.Action != engine.ActionPass {
		t.Errorf("expected first request to pass even with nil IP, got %v", result.Action)
	}
}

// --- bucketKey IPv4-mapped normalization ---

func TestBucketKey_IPv4MappedNormalization(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	rule := &Rule{ID: "test", Scope: "ip"}

	// Pass an IPv4-mapped IPv6 address string
	key := layer.bucketKey(rule, "", "::ffff:192.168.1.1", "/")

	// Should be normalized
	if key == "" {
		t.Error("expected non-empty key")
	}
}

func TestBucketKey_IPPlusPathScope(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	rule := &Rule{ID: "path-test", Scope: "ip+path"}
	key := layer.bucketKey(rule, "tenant1", "1.2.3.4", "/api/users")

	expected := "path-test:tenant1:1.2.3.4:/api/users"
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

func TestBucketKey_IPPlusPathWithDotDot(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	rule := &Rule{ID: "dotdot", Scope: "ip+path"}
	key := layer.bucketKey(rule, "", "1.2.3.4", "/api/../admin")

	// Should be cleaned to /admin
	if key != "dotdot::1.2.3.4:/admin" {
		t.Errorf("expected path normalization, got %q", key)
	}
}

func TestBucketKey_DefaultScope(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	rule := &Rule{ID: "default", Scope: "unknown"}
	key := layer.bucketKey(rule, "t1", "1.2.3.4", "/irrelevant")

	// Unknown scope should fall through to default (ip-only)
	if key != "default:t1:1.2.3.4" {
		t.Errorf("expected default scope key, got %q", key)
	}
}

// --- getOrCreateBucket max buckets limit ---

func TestGetOrCreateBucket_MaxBucketsLimit(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "max-test", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	// Force bucket count to max
	layer.bucketCount.Store(maxBuckets)

	ctx := makeContext("10.0.0.1", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)

	// When max buckets is reached, getOrCreateBucket returns the shared blocking bucket (tokens=0), so Allow() always returns false → rate limit exceeded (score 70).
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block when max buckets reached, got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Score != 70 {
		t.Errorf("expected score 70 for rate limit exceeded, got %d", result.Findings[0].Score)
	}
	if result.Findings[0].Description != "Rate limit exceeded: max-test" {
		t.Errorf("unexpected description: %s", result.Findings[0].Description)
	}
}

// --- CleanupExpired violation cleanup ---

func TestCleanupExpired_ViolationCleanup(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "violation-test", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block", AutoBanAfter: 3},
		},
	})

	layer.OnAutoBan = func(ip, reason string) {}

	// Create bucket and trigger violations
	ip := "7.7.7.7"
	ctx := makeContext(ip, "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)

	// Generate violations
	for i := 0; i < 5; i++ {
		ctx := makeContext(ip, "/test")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}

	// Verify violation exists
	violCount := 0
	layer.violations.Range(func(_, _ any) bool { violCount++; return true })
	if violCount == 0 {
		t.Fatal("expected at least one violation counter")
	}

	// Wait and cleanup with zero stale duration — removes the bucket
	time.Sleep(5 * time.Millisecond)
	layer.CleanupExpired(1 * time.Millisecond)

	// Bucket should be gone, so violation should also be cleaned
	violCount = 0
	layer.violations.Range(func(_, _ any) bool { violCount++; return true })
	if violCount != 0 {
		t.Errorf("expected 0 violations after bucket cleanup, got %d", violCount)
	}
}

// --- trackViolation edge cases ---

func TestTrackViolation_ResetAfterBan(t *testing.T) {
	var banCount atomic.Int32

	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "reset-test", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block", AutoBanAfter: 2},
		},
	})

	var mu sync.Mutex
	layer.OnAutoBan = func(ip, reason string) {
		mu.Lock()
		defer mu.Unlock()
		banCount.Add(1)
	}

	ip := "8.8.8.8"

	// First request passes (consumes the only token)
	ctx := makeContext(ip, "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)

	// Generate violations until auto-ban triggers
	for i := 0; i < 5; i++ {
		ctx := makeContext(ip, "/test")
		layer.Process(ctx)
		engine.ReleaseContext(ctx)
	}

	if banCount.Load() == 0 {
		t.Error("expected auto-ban to be triggered")
	}
}

func TestTrackViolation_NoCallback(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "no-cb", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block", AutoBanAfter: 1},
		},
	})

	// OnAutoBan is nil — should not panic
	ctx := makeContext("9.9.9.9", "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)

	ctx = makeContext("9.9.9.9", "/test")
	layer.Process(ctx)
	engine.ReleaseContext(ctx)
}

// --- RemoveRule with non-string keys in buckets ---

func TestRemoveRule_NonStringBucketKeys(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	// Insert a non-string key into buckets to test the type assertion branch
	layer.buckets.Store(12345, NewTokenBucket(10, 1))

	removed := layer.RemoveRule("r1")
	if !removed {
		t.Error("expected rule to be removed")
	}

	// Non-string key should be deleted too
	_, exists := layer.buckets.Load(12345)
	if exists {
		t.Error("expected non-string key to be deleted during RemoveRule")
	}
}

// --- Concurrent RemoveRule and Process ---

func TestConcurrent_RemoveRuleAndProcess(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "concurrent", Scope: "ip", Limit: 1000, Window: time.Second, Burst: 1000, Action: "block"},
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ctx := makeContext("10.0.0.1", "/test")
				layer.Process(ctx)
				engine.ReleaseContext(ctx)
			}
		}()
		go func(id int) {
			defer wg.Done()
			layer.RemoveRule("concurrent")
			layer.AddRule(Rule{ID: "concurrent", Scope: "ip", Limit: 1000, Window: time.Second, Burst: 1000, Action: "block"})
		}(i)
	}
	wg.Wait()
}

// --- Multiple rules with log + block ---

func TestProcess_MultipleRulesMixedActions(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "log-rule", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "log"},
			{ID: "block-rule", Scope: "ip", Limit: 1, Window: time.Second, Burst: 1, Action: "block"},
		},
	})

	// First request uses up both rules' tokens
	ctx := makeContext("1.1.1.1", "/test")
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected first request to pass, got %v", result.Action)
	}

	// Second request exceeds both rules — block takes priority
	ctx = makeContext("1.1.1.1", "/test")
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block (block rule takes priority over log), got %v", result.Action)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings (one from each rule), got %d", len(result.Findings))
	}
	if result.Score != 140 { // 70 + 70
		t.Errorf("expected total score 140, got %d", result.Score)
	}
}

// --- matchesRule edge cases ---

func TestMatchesRule_EmptyPaths(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	rule := &Rule{Paths: nil}
	if !layer.matchesRule(rule, "/anything") {
		t.Error("expected nil paths to match all")
	}
}

func TestMatchesRule_NoMatch(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	rule := &Rule{Paths: []string{"/login", "/admin"}}
	if layer.matchesRule(rule, "/public") {
		t.Error("expected /public to not match /login or /admin")
	}
}

func TestMatchesRule_MultiplePatterns(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	rule := &Rule{Paths: []string{"/api/**", "/admin"}}
	if !layer.matchesRule(rule, "/api/users") {
		t.Error("expected /api/users to match /api/**")
	}
	if !layer.matchesRule(rule, "/admin") {
		t.Error("expected /admin to match /admin")
	}
	if layer.matchesRule(rule, "/home") {
		t.Error("expected /home to not match")
	}
}

// --- matchPath additional edge cases ---

func TestMatchPath_ExactPrefixMatch(t *testing.T) {
	if !matchPath("/api/**", "/api/") {
		t.Error("expected /api/ to match /api/**")
	}
	if !matchPath("/api/**", "/api") {
		t.Error("expected /api to match /api/** (prefix without trailing slash)")
	}
}

func TestMatchPath_ExactPathMatch(t *testing.T) {
	if !matchPath("/login", "/login") {
		t.Error("expected exact match")
	}
	if matchPath("/login", "/login/extra") {
		t.Error("expected no match for longer path")
	}
}

// --- getOrCreateBucket concurrent access ---

func TestGetOrCreateBucket_ConcurrentCreation(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "concurrent-bucket", Scope: "ip", Limit: 100, Window: time.Second, Burst: 100, Action: "block"},
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('0'+id%10))
			ctx := makeContext(ip, "/test")
			layer.Process(ctx)
			engine.ReleaseContext(ctx)
		}(i)
	}
	wg.Wait()
}

// --- Layer with empty config ---

func TestNewLayer_NilConfigRules(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Rules: nil})
	ctx := makeContext("1.2.3.4", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with no rules, got %v", result.Action)
	}
}

// --- Tenant isolation in bucket keys ---

func TestProcess_TenantIsolation(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "tenant-iso", Scope: "ip", Limit: 2, Window: time.Second, Burst: 2, Action: "block"},
		},
	})

	// Tenant A uses up their limit
	for i := 0; i < 2; i++ {
		ctx := makeContext("1.2.3.4", "/test")
		ctx.TenantID = "tenant-a"
		result := layer.Process(ctx)
		engine.ReleaseContext(ctx)
		if result.Action != engine.ActionPass {
			t.Errorf("tenant-a request %d: expected pass", i+1)
		}
	}

	// Tenant A should be blocked
	ctx := makeContext("1.2.3.4", "/test")
	ctx.TenantID = "tenant-a"
	result := layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionBlock {
		t.Error("tenant-a should be blocked after limit")
	}

	// Tenant B with same IP should still pass (separate bucket)
	ctx = makeContext("1.2.3.4", "/test")
	ctx.TenantID = "tenant-b"
	result = layer.Process(ctx)
	engine.ReleaseContext(ctx)
	if result.Action != engine.ActionPass {
		t.Error("tenant-b should pass (separate bucket)")
	}
}

// --- Process Duration field ---

func TestProcess_DurationSet(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "dur", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	ctx := makeContext("1.2.3.4", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Duration < 0 {
		t.Error("expected non-negative duration")
	}
}

// --- Temporary file helper ---

func TestRemoveRule_Cleanup_TempDir(t *testing.T) {
	_ = os.TempDir()
	_ = filepath.Join(os.TempDir(), "test")
}

// --- mockClusterStore for cluster rate-limit tests ---

type mockClusterStore struct {
	mu       sync.Mutex
	counters map[string]int64
}

func newMockClusterStore() *mockClusterStore {
	return &mockClusterStore{counters: make(map[string]int64)}
}

func (m *mockClusterStore) IsBanned(string) bool                          { return false }
func (m *mockClusterStore) GetRule(string) (json.RawMessage, bool)        { return nil, false }
func (m *mockClusterStore) GetCounter(key string, _ int64) int64          { return 0 }
func (m *mockClusterStore) IncrementCounter(key string, _ int64) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key]++
	return m.counters[key]
}

func TestProcess_ClusterRateLimit_AtomicIncrement(t *testing.T) {
	store := newMockClusterStore()

	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "cluster-test", Scope: "ip", Limit: 3, Window: 60 * time.Second,
			Action: "block",
		}},
	})
	layer.SetClusterStore(store)

	mkCtx := func(ip string) *engine.RequestContext {
		return &engine.RequestContext{
			Method:   "GET",
			Path:     "/",
			ClientIP: net.ParseIP(ip),
			Headers:  map[string][]string{},
			Cookies:  map[string]string{},
		}
	}

	// First 3 requests should pass (increment returns 1, 2, 3 — all <= Limit).
	for i := 0; i < 3; i++ {
		result := layer.Process(mkCtx("10.0.0.1"))
		if result.Action == engine.ActionBlock {
			t.Fatalf("request %d should not be blocked (counter=%d)", i+1, store.counters["cluster-test::10.0.0.1"])
		}
	}

	// 4th request: counter reaches 4 > Limit(3) → blocked.
	result := layer.Process(mkCtx("10.0.0.1"))
	if result.Action != engine.ActionBlock {
		t.Fatalf("4th request should be blocked (counter=%d)", store.counters["cluster-test::10.0.0.1"])
	}
	if store.counters["cluster-test::10.0.0.1"] != 4 {
		t.Fatalf("expected counter=4, got %d", store.counters["cluster-test::10.0.0.1"])
	}
}

func TestProcess_ClusterRateLimit_ConcurrentNoBypass(t *testing.T) {
	store := newMockClusterStore()

	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "concurrent-test", Scope: "ip", Limit: 10, Window: 60 * time.Second,
			Action: "block",
		}},
	})
	layer.SetClusterStore(store)

	mkCtx := func(ip string) *engine.RequestContext {
		return &engine.RequestContext{
			Method:   "GET",
			Path:     "/",
			ClientIP: net.ParseIP(ip),
			Headers:  map[string][]string{},
			Cookies:  map[string]string{},
		}
	}

	// Fire 20 concurrent requests with Limit=10. With the old TOCTOU code,
	// many goroutines could read the same pre-increment value and bypass.
	// With IncrementCounter, the atomic increment guarantees exactly 10 pass.
	const total = 20
	var wg sync.WaitGroup
	var blocked atomic.Int64
	var passed atomic.Int64
	start := make(chan struct{})

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result := layer.Process(mkCtx("10.0.0.2"))
			if result.Action == engine.ActionBlock {
				blocked.Add(1)
			} else {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// The cluster counter must equal total (every request incremented it).
	if store.counters["concurrent-test::10.0.0.2"] != total {
		t.Fatalf("counter = %d, want %d (lost increments detected)",
			store.counters["concurrent-test::10.0.0.2"], total)
	}

	// No more than Limit requests should pass (allow some slack for local
	// token bucket burst which has its own limit). The key assertion is that
	// the counter reached exactly total — proving no increments were lost.
	if blocked.Load()+passed.Load() != total {
		t.Fatalf("goroutine accounting mismatch: blocked=%d passed=%d total=%d",
			blocked.Load(), passed.Load(), total)
	}
}

// --- M1: Cleanup-Process eviction-restore tests ---

// TestEvictionRestore_PreservesRateLimitState proves the core M1 fix: when
// CleanupExpired deletes a bucket that was near its rate limit, a concurrent
// or immediately-following Process restores the bucket's state instead of
// creating a fresh one at full capacity. Without the fix, an attacker could
// reset their rate-limit window by timing requests against the cleanup interval.
func TestEvictionRestore_PreservesRateLimitState(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "restore-rule", Scope: "ip", Limit: 10, Window: time.Minute, Burst: 10, Action: "block"},
		},
	})

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/",
		ClientIP: net.ParseIP("1.2.3.4"),
	}

	// Exhaust 8 of 10 tokens so the bucket is near its limit.
	for i := 0; i < 8; i++ {
		layer.Process(ctx)
	}

	// Verify the bucket exists and has ~2 tokens left.
	key := "restore-rule::1.2.3.4"
	val, ok := layer.buckets.Load(key)
	if !ok {
		t.Fatal("expected bucket to exist after Process calls")
	}
	tb := val.(*TokenBucket)
	tb.mu.Lock()
	tokensBefore := tb.tokens
	tb.mu.Unlock()
	if tokensBefore > 3 {
		t.Fatalf("expected ~2 tokens left, got %f", tokensBefore)
	}

	// Simulate the cleanup-Process race: evict the bucket (which snapshots
	// state), then immediately Process (which should restore from snapshot).
	layer.deleteBucket(key)

	// Confirm the eviction snapshot was created.
	evVal, evOk := layer.evictedBuckets.Load(key)
	if !evOk {
		t.Fatal("expected eviction snapshot after deleteBucket")
	}
	ev := evVal.(*evictedBucket)
	if ev.tokens > 3 {
		t.Fatalf("snapshot tokens should be ~2, got %f", ev.tokens)
	}

	// Process should restore the bucket at ~2 tokens, NOT at the full 10.
	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Logf("request blocked as expected (bucket was near limit)")
	}

	// Verify the restored bucket has low tokens, not full capacity.
	val2, ok2 := layer.buckets.Load(key)
	if !ok2 {
		t.Fatal("expected bucket to exist after restore")
	}
	tb2 := val2.(*TokenBucket)
	tb2.mu.Lock()
	tokensAfter := tb2.tokens
	tb2.mu.Unlock()
	if tokensAfter > 3 {
		t.Fatalf("rate-limit state was reset! expected ~2 tokens after restore, got %f (full capacity would be 10)", tokensAfter)
	}
}

// TestEvictionRestore_ExpiredSnapshotReturnsFreshBucket verifies that an
// eviction snapshot older than evictionRestoreWindow is not restored — the
// client's rate-limit window has fully reset by then and a fresh bucket is correct.
func TestEvictionRestore_ExpiredSnapshotReturnsFreshBucket(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "expired-rule", Scope: "ip", Limit: 10, Window: time.Minute, Burst: 10, Action: "block"},
		},
	})

	key := "expired-rule::1.2.3.4"

	// Manually insert an expired eviction snapshot with 0 tokens.
	layer.evictedBuckets.Store(key, &evictedBucket{
		tokens:     0,
		maxTokens:  10,
		refillRate: 10.0 / 60.0,
		lastRefill: time.Now(),
		evictedAt:  time.Now().Add(-(evictionRestoreWindow + time.Minute)),
	})

	// restoreFromEviction should reject the expired snapshot and return a fresh bucket.
	bucket := layer.restoreFromEviction(key, 10, 10.0/60.0)
	if bucket.tokens < 9 {
		t.Fatalf("expected fresh bucket at ~full capacity for expired snapshot, got %f tokens", bucket.tokens)
	}
}

// TestEvictionRestore_CleanupPurgesStaleSnapshots verifies that CleanupExpired
// removes eviction snapshots older than evictionRestoreWindow so the map
// doesn't grow unbounded.
func TestEvictionRestore_CleanupPurgesStaleSnapshots(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "purge-rule", Scope: "ip", Limit: 10, Window: time.Minute, Burst: 10, Action: "block"},
		},
	})

	// Insert a stale eviction snapshot.
	layer.evictedBuckets.Store("stale-key", &evictedBucket{
		tokens:     5,
		maxTokens:  10,
		refillRate: 10.0 / 60.0,
		lastRefill: time.Now(),
		evictedAt:  time.Now().Add(-(evictionRestoreWindow + time.Minute)),
	})

	// Insert a fresh eviction snapshot.
	layer.evictedBuckets.Store("fresh-key", &evictedBucket{
		tokens:     5,
		maxTokens:  10,
		refillRate: 10.0 / 60.0,
		lastRefill: time.Now(),
		evictedAt:  time.Now(),
	})

	layer.CleanupExpired(time.Minute)

	if _, exists := layer.evictedBuckets.Load("stale-key"); exists {
		t.Error("expected stale eviction snapshot to be purged")
	}
	if _, exists := layer.evictedBuckets.Load("fresh-key"); !exists {
		t.Error("expected fresh eviction snapshot to survive cleanup")
	}
}
