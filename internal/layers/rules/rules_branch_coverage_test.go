package rules

import (
	"regexp"
	"strconv"
	"testing"

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
		layer.regexMatch(pattern, "miss")
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

	if matched := layer.regexMatch("(((((((a)))))))", "a"); matched {
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
	old := activeRegexCount
	activeRegexCount = maxConcurrentRegex
	defer func() { activeRegexCount = old }()

	if matched := regexMatchWithTimeout(regexp.MustCompile(`.`), "x"); matched {
		t.Fatal("expected false when regex concurrency limit is reached")
	}
}
