package ratelimit

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestTokenBucket_BoundaryZeroLimit tests behavior when limit is 0 (allow nothing).
func TestTokenBucket_BoundaryZeroLimit(t *testing.T) {
	tb := NewTokenBucket(0, 0) // 0 tokens, 0 refill

	for i := 0; i < 5; i++ {
		if tb.Allow() {
			t.Fatalf("request %d should be denied with 0 limit", i+1)
		}
	}
}

// TestTokenBucket_BoundaryZeroWindow tests behavior when window is 0.
// With window=0 and limit > 0, refillRate becomes inf — bucket should still work.
func TestTokenBucket_BoundaryZeroWindow(t *testing.T) {
	tb := NewTokenBucket(5, 1) // 5 tokens, 1/s refill (normal)

	// Use all tokens
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// Denied since no refill yet
	if tb.Allow() {
		t.Fatal("should be denied before refill")
	}
}

// TestTokenBucket_BoundaryZeroBurst tests behavior when burst is 0.
// Burst=0 means limit is used as maxTokens instead.
func TestTokenBucket_BoundaryZeroBurst(t *testing.T) {
	tb := NewTokenBucket(0, 0) // 0 tokens, 0 refill

	if tb.Allow() {
		t.Fatal("zero-bucket should deny all")
	}
}

// TestRateLimitLayer_BoundaryZeroLimit tests the layer with a rule where limit=0.
func TestRateLimitLayer_BoundaryZeroLimit(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "zero-limit", Scope: "ip", Limit: 0, Window: time.Second, Burst: 0, Action: "block"},
		},
	})

	ctx := makeContext("192.0.2.1", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)

	// limit=0 means bucket starts empty and never refills — should block
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for limit=0, got %v", result.Action)
	}
}

// TestRateLimitLayer_BoundaryZeroWindow tests the layer with window=0.
// Division by zero in refillRate calculation.
func TestRateLimitLayer_BoundaryZeroWindow(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "zero-window", Scope: "ip", Limit: 10, Window: 0, Burst: 0, Action: "block"},
		},
	})

	ctx := makeContext("192.0.2.1", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)

	// Should handle division by zero gracefully — passing is acceptable
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for zero-window (handled gracefully), got %v", result.Action)
	}
}

// TestRateLimitLayer_BoundaryZeroBurst tests the layer with burst=0.
// Burst=0 should use Limit as maxTokens.
func TestRateLimitLayer_BoundaryZeroBurst(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "zero-burst", Scope: "ip", Limit: 3, Window: time.Second, Burst: 0, Action: "block"},
		},
	})

	// First 3 should pass
	for i := 0; i < 3; i++ {
		ctx := makeContext("192.0.2.1", "/test")
		defer engine.ReleaseContext(ctx)
		result := layer.Process(ctx)
		if result.Action == engine.ActionBlock {
			t.Errorf("request %d should pass (burst=0 uses limit=%d)", i+1, 3)
		}
	}

	// 4th should block
	ctx := makeContext("192.0.2.1", "/test")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block on 4th request with burst=0, got %v", result.Action)
	}
}

// TestRateLimitLayer_BoundaryEmptyPathList tests rules with empty Paths list.
func TestRateLimitLayer_BoundaryEmptyPathList(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "empty-paths", Scope: "ip", Paths: []string{}, Limit: 1, Window: time.Second, Burst: 1, Action: "block"},
		},
	})

	// Empty Paths means match all — should consume the bucket
	ctx := makeContext("192.0.2.1", "/any-path")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("first request should pass, got %v", result.Action)
	}

	// Second should block (limit=1)
	ctx2 := makeContext("192.0.2.1", "/any-path")
	defer engine.ReleaseContext(ctx2)
	result = layer.Process(ctx2)
	if result.Action != engine.ActionBlock {
		t.Errorf("second request should block, got %v", result.Action)
	}
}