package openredirect

import (
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: the same-host classification in checkValue must be
// case-insensitive — DNS names are case-insensitive, and the previous
// byte-exact comparison (host != reqHost + case-sensitive suffix check)
// false-positively blocked same-site redirects spelled in a different case
// (e.g. an app echoing "Host: EXAMPLE.com" into a redirect to
// https://EXAMPLE.com/), scoring 60 → ActionBlock.

func newCaseDetector() *Detector { return NewDetector(true, 1.0) }

func runCase(host, next string) engine.Action {
	d := newCaseDetector()
	req := httptest.NewRequest("GET", "https://"+host+"/login", nil)
	ctx := &engine.RequestContext{
		Method:      "GET",
		Path:        "/login",
		Request:     req,
		QueryParams: map[string][]string{"next": {next}},
	}
	return d.Process(ctx).Action
}

func TestSameHostIsCaseInsensitive(t *testing.T) {
	cases := []struct {
		name, reqHost, next string
	}{
		{"uppercase target", "example.com", "https://EXAMPLE.com/path"},
		{"mixed-case target", "example.com", "https://Example.com/path"},
		{"case-varied request host", "EXAMPLE.com", "https://Example.com/path"},
	}
	for _, tc := range cases {
		if a := runCase(tc.reqHost, tc.next); a != engine.ActionPass {
			t.Errorf("FAIL: %s: same-site redirect was blocked as external (action %v)", tc.name, a)
		}
	}
}

func TestSubdomainSuffixIsCaseInsensitive(t *testing.T) {
	// Uppercase subdomain of the request host must stay trusted.
	if a := runCase("example.com", "https://API.EXAMPLE.com/path"); a != engine.ActionPass {
		t.Fatalf("FAIL: uppercase subdomain was blocked as external (action %v)", a)
	}
}

// Controls: the true positives must keep blocking under the case-insensitive
// comparison.
func TestExternalHostsStillBlocked(t *testing.T) {
	if a := runCase("example.com", "https://evil.com/"); a != engine.ActionBlock {
		t.Fatalf("FAIL: external host was not blocked (action %v)", a)
	}
	if a := runCase("example.com", "https://sub.evil.com/"); a != engine.ActionBlock {
		t.Fatalf("FAIL: external subdomain was not blocked (action %v)", a)
	}
	if a := runCase("example.com", "https://example.com.evil.com/"); a != engine.ActionBlock {
		t.Fatalf("FAIL: evil.com-suffixed host was not blocked (action %v)", a)
	}
}
