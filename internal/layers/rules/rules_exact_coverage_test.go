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

	if regexMatchWithTimeout(regexp.MustCompile(`a`), "a", nil) {
		t.Fatal("expected forced timeout to return false")
	}
}
