package rules

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: `header:` conditions match header names case-insensitively.
//
// ctx.Headers keys are canonical MIME form (net/http canonicalization), but a
// rule author may write the header name in any casing — header names are
// case-insensitive per RFC 9110 §5.1. Before the fix, getFieldValue looked up
// the author's raw spelling, so a rule with Field "header:x-api-key" silently
// never fired against a real "X-Api-Key" header: an operator security rule
// that was inert without any error.
//
// Boundary pinned below: cookie names stay case-sensitive (RFC 6265), so the
// cookie: lookup must NOT be canonicalized.
func headerCaseRegressionCtx(t *testing.T) *engine.RequestContext {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path?q=1", nil)
	req.Header.Set("X-Api-Key", "sk-live-123")
	req.Header.Set("User-Agent", "probe-agent/1.0")
	req.AddCookie(&http.Cookie{Name: "SessionID", Value: "abc"})
	return engine.AcquireContext(req, 2, 1<<20)
}

func TestHeaderAndCookieConditionCasing(t *testing.T) {
	ctx := headerCaseRegressionCtx(t)

	cases := []struct {
		name     string
		field    string
		value    string
		wantFire bool
	}{
		{"header-canonical", "header:X-Api-Key", "sk-live-123", true},
		{"header-lowercase-author-form", "header:x-api-key", "sk-live-123", true},
		{"header-casing-variant-same-name", "header:X-API-KEY", "sk-live-123", true},
		{"header-user-agent-lowercase", "header:user-agent", "probe-agent/1.0", true},
		{"header-different-name-not-matched", "header:Api-Key", "sk-live-123", false},
		{"header-absent", "header:X-Missing", "sk-live-123", false},
		{"cookie-exact-case", "cookie:SessionID", "abc", true},
		{"cookie-lowercase-is-a-different-name", "cookie:sessionid", "abc", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			layer := NewLayer(&Config{
				Enabled: true,
				Rules: []Rule{{
					ID: "reg-casing", Name: "casing regression", Enabled: true, Priority: 0,
					Action: "block", Score: 100,
					Conditions: []Condition{{Field: tc.field, Op: "equals", Value: tc.value}},
				}},
			}, nil)

			res := layer.Process(ctx)
			fired := res.Action == engine.ActionBlock && len(res.Findings) > 0
			if fired != tc.wantFire {
				t.Fatalf("field %q fired=%v, want %v (action=%v findings=%d)", tc.field, fired, tc.wantFire, res.Action, len(res.Findings))
			}
		})
	}
}
