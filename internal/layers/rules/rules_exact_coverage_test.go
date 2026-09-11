package rules

import (
	"regexp"
	"testing"
	"time"
)

func TestRegexMatchWithTimeout_Timeout(t *testing.T) {
	oldAfter := regexTimeoutAfter
	regexTimeoutAfter = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	t.Cleanup(func() { regexTimeoutAfter = oldAfter })

	// Per-regex ceiling timeout must fail CLOSED (round 29): a rule whose
	// regex exceeds its ceiling fires, it does not silently vanish.
	if !regexMatchWithTimeout(regexp.MustCompile(`a`), "a", nil) {
		t.Fatal("expected forced timeout to fail closed (return true)")
	}
}
