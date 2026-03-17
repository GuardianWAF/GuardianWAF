package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucket_InitialTokens(t *testing.T) {
	tb := NewTokenBucket(10, 1)
	tokens := tb.Tokens()
	if tokens < 9.9 || tokens > 10.1 {
		t.Fatalf("expected ~10 initial tokens, got %f", tokens)
	}
}

func TestTokenBucket_ConsumeTokens(t *testing.T) {
	tb := NewTokenBucket(5, 0) // no refill

	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Fatalf("expected allow on request %d", i+1)
		}
	}

	// 6th request should be denied
	if tb.Allow() {
		t.Fatal("expected deny after all tokens consumed")
	}
}

func TestTokenBucket_RefillOverTime(t *testing.T) {
	tb := NewTokenBucket(10, 100) // 100 tokens/sec

	// Consume all tokens
	for i := 0; i < 10; i++ {
		tb.Allow()
	}

	if tb.Allow() {
		t.Fatal("expected deny immediately after draining")
	}

	// Wait for refill (100/s means 1 token per 10ms)
	time.Sleep(50 * time.Millisecond)

	// Should have some tokens now
	if !tb.Allow() {
		t.Fatal("expected allow after refill period")
	}
}

func TestTokenBucket_BurstHandling(t *testing.T) {
	// Bucket allows burst of 20, refills at 10/s
	tb := NewTokenBucket(20, 10)

	// Burst: consume all 20
	allowed := 0
	for i := 0; i < 25; i++ {
		if tb.Allow() {
			allowed++
		}
	}

	if allowed != 20 {
		t.Fatalf("expected 20 allowed in burst, got %d", allowed)
	}
}

func TestTokenBucket_EmptyBucket(t *testing.T) {
	tb := NewTokenBucket(1, 0) // 1 token, no refill

	if !tb.Allow() {
		t.Fatal("first request should be allowed")
	}

	// All subsequent should fail
	for i := 0; i < 10; i++ {
		if tb.Allow() {
			t.Fatalf("request %d should be denied", i+2)
		}
	}
}

func TestTokenBucket_RefillCappedAtMax(t *testing.T) {
	tb := NewTokenBucket(5, 1000) // very fast refill

	// Use some tokens
	tb.Allow()
	tb.Allow()

	time.Sleep(10 * time.Millisecond)

	tokens := tb.Tokens()
	if tokens > 5.01 {
		t.Fatalf("tokens should be capped at max (5), got %f", tokens)
	}
}

func TestTokenBucket_ZeroRefillRate(t *testing.T) {
	tb := NewTokenBucket(3, 0)

	tb.Allow()
	tb.Allow()
	tb.Allow()

	time.Sleep(10 * time.Millisecond)

	if tb.Allow() {
		t.Fatal("should not refill with rate 0")
	}
}
