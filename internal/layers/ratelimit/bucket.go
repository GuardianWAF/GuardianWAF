package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket implements the token bucket algorithm with lazy refill.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	lastAccess time.Time // for cleanup of stale buckets
}

// NewTokenBucket creates a new token bucket starting full.
func NewTokenBucket(maxTokens float64, refillRate float64) *TokenBucket {
	now := time.Now()
	return &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: now,
		lastAccess: now,
	}
}

// Allow checks if a request is allowed. Returns true and consumes a token if allowed.
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	tb.lastAccess = time.Now()

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// refill adds tokens based on elapsed time since last refill.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens = min(tb.maxTokens, tb.tokens+elapsed*tb.refillRate)
	tb.lastRefill = now
}

// Tokens returns the current token count (after refill).
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

// LastAccess returns the last time this bucket was accessed.
func (tb *TokenBucket) LastAccess() time.Time {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.lastAccess
}
