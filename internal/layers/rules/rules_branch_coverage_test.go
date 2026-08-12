package rules

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestCoverage_Order(t *testing.T) {
	layer := NewLayer(&Config{}, nil)
	if got := layer.Order(); got != engine.OrderRules {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderRules)
	}
}

func TestCoverage_RegexMatch_CacheEvictionWithUniquePatterns(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true}, nil)

	for i := range 10001 {
		pattern := "^a" + strconv.Itoa(i) + "$"
		layer.regexMatch(pattern, "miss", nil)
	}

	layer.mu.RLock()
	cacheLen := len(layer.regexCache)
	_, newestPresent := layer.regexCache["^a10000$"]
	layer.mu.RUnlock()

	if cacheLen != 10000 {
		t.Fatalf("expected cache length 10000 after eviction, got %d", cacheLen)
	}
	if !newestPresent {
		t.Fatalf("expected the newest compiled pattern to remain cached")
	}
}

func TestCoverage_RegexMatch_RejectsUnsafePattern(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true}, nil)

	if matched := layer.regexMatch("(((((((a)))))))", "a", nil); matched {
		t.Fatal("expected false for unsafe regex pattern")
	}

	layer.mu.RLock()
	cacheLen := len(layer.regexCache)
	layer.mu.RUnlock()
	if cacheLen != 0 {
		t.Fatalf("expected unsafe regex to avoid cache insert, got cache len %d", cacheLen)
	}
}

func TestCoverage_RegexMatchWithTimeout_ConcurrencyLimit(t *testing.T) {
	// Fill the semaphore to capacity so no slot is available.
	for range maxConcurrentRegex {
		regexSem <- struct{}{}
	}
	defer func() {
		// Drain so other tests are not affected.
		for range maxConcurrentRegex {
			select {
			case <-regexSem:
			default:
			}
		}
	}()

	// Force immediate timeout so the semaphore wait fails fast.
	oldAfter := regexTimeoutAfter
	regexTimeoutAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	t.Cleanup(func() { regexTimeoutAfter = oldAfter })

	// Under overload the function must fail CLOSED (return true) so the
	// security rule condition matches and the request is treated as suspicious.
	if matched := regexMatchWithTimeout(regexp.MustCompile(`.`), "x", nil); !matched {
		t.Fatal("expected true (fail-closed) when regex concurrency limit is saturated")
	}
}

func TestCoverage_RegexMatch_BudgetExhausted(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true}, nil)

	// Create a deadline already in the past — budget is exhausted.
	dl := &regexDeadline{deadline: time.Now().Add(-1 * time.Second)}
	if !dl.exhausted() {
		t.Fatal("deadline should be exhausted")
	}

	// Must fail closed (return true) without spawning a goroutine.
	if matched := layer.regexMatch("a", "a", dl); !matched {
		t.Fatal("expected true (fail-closed) when per-request regex budget is exhausted")
	}
}

func TestCoverage_RegexMatchWithTimeout_BudgetClampsPerRegexTimeout(t *testing.T) {
	// Create a deadline with very little budget left — less than regexMatchTimeout.
	dl := &regexDeadline{deadline: time.Now().Add(5 * time.Millisecond)}
	if remaining := dl.remaining(); remaining > regexMatchTimeout {
		t.Fatalf("remaining %v should be < regexMatchTimeout %v", remaining, regexMatchTimeout)
	}

	// A pathological backtracking regex that would take well beyond 5ms.
	re := regexp.MustCompile(`(a+)+$`)
	input := strings.Repeat("a", 30) + "!"

	// The clamped deadline should kick in well before the full regexMatchTimeout.
	// Result is false (per-regex timeout, not budget exhaustion — budget exhaustion
	// returns true from regexMatch, not from regexMatchWithTimeout).
	start := time.Now()
	matched := regexMatchWithTimeout(re, input, dl)
	elapsed := time.Since(start)

	if matched {
		t.Fatal("expected false (regex timed out on pathological input)")
	}
	// Must complete in well under the 500ms ceiling — proves clamping works.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("elapsed %v too high; per-regex timeout was not clamped to remaining budget", elapsed)
	}
}
