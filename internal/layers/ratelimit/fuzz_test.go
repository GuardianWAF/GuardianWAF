package ratelimit

import (
	"testing"
	"time"
)

func FuzzTokenBucket(f *testing.F) {
	f.Add(10.0, 1.0)                  // normal tokens, refill rate
	f.Add(0.0, 0.0)                   // zero tokens, zero refill
	f.Add(100.0, 0.0)                 // burst with no refill
	f.Add(1.0, 1000.0)                // fast refill
	f.Add(0.0, 100.0)                 // zero initial, positive refill

	f.Fuzz(func(t *testing.T, maxTokens, refillRate float64) {
		// Reject negative inputs which cause invalid token states
		if maxTokens < 0 || refillRate < 0 {
			t.Skip()
		}

		tb := NewTokenBucket(maxTokens, refillRate)

		// Allow should not panic
		tb.Allow()

		// Tokens should not panic
		_ = tb.Tokens()
	})
}

func FuzzRateLimitRule(f *testing.F) {
	f.Add("ip", 10, int64(1*time.Second), 10, "block", 0)
	f.Add("ip+path", 100, int64(10*time.Second), 50, "log", 5)
	f.Add("ip", 0, int64(0), 0, "block", 0)
	f.Add("", 0, int64(0), 0, "log", 0)

	f.Fuzz(func(t *testing.T, scope string, limit int, window int64, burst int, action string, autoBanAfter int) {
		rule := Rule{
			ID:           "fuzz",
			Scope:        scope,
			Limit:        limit,
			Window:       time.Duration(window),
			Burst:        burst,
			Action:       action,
			AutoBanAfter: autoBanAfter,
		}

		_ = rule
	})
}