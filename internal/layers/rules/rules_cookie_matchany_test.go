package rules

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests (round 85): the rules layer's cookie: field accessor
// returned vals[0] (the r.Cookie() first-match view), so a deny rule keyed
// to a cookie value was evadable: valid-first + trigger-last passed the
// rule while a last-wins backend (PHP/Python-style parsers) read the
// trigger value. Cookie conditions now match if ANY transmitted value
// satisfies the op — uniform for all ops (fail-closed for deny rules;
// position-independent whitelists for pass rules). Cookie names stay
// case-sensitive (RFC 6265): conditions are NOT canonicalized.

func newCookieRuleLayer(action string) *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r85", Name: "cookie role rule", Enabled: true,
			Conditions: []Condition{{Field: "cookie:role", Op: "equals", Value: "admin"}},
			Action:     action, Score: 100,
		}},
	}, nil)
}

func TestRuleCookieTriggerLastStillBlocked(t *testing.T) {
	layer := newCookieRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", nil)
	ctx.Cookies = map[string][]string{"role": {"guest", "admin"}}
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-last cookie value not blocked, got %s", result.Action)
	}
}

func TestRuleCookieOrderSwapStillBlocked(t *testing.T) {
	layer := newCookieRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", nil)
	ctx.Cookies = map[string][]string{"role": {"admin", "guest"}}
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: trigger-first cookie value not blocked, got %s", result.Action)
	}
}

func TestRuleCookieSingleNonMatchClean(t *testing.T) {
	layer := newCookieRuleLayer("block")
	ctx := testCtx("GET", "/admin", "1.2.3.4", nil)
	ctx.Cookies = map[string][]string{"role": {"guest"}}
	if result := layer.Process(ctx); result.Action == engine.ActionBlock {
		t.Fatal("FAIL: non-matching cookie value was blocked")
	}
}

func TestRuleCookieNegatedOpFiresOnAnyDifference(t *testing.T) {
	// not_equals under match-any: fires when ANY transmitted value differs
	// (fail-closed for deny rules).
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "n85", Name: "non-internal tier", Enabled: true,
			Conditions: []Condition{{Field: "cookie:tier", Op: "not_equals", Value: "internal"}},
			Action:     "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.Cookies = map[string][]string{"tier": {"internal", "guest"}}
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Fatalf("FAIL: negated op should fire when any value differs, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	ctx2.Cookies = map[string][]string{"tier": {"internal"}}
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Fatalf("FAIL: all-equal values should not fire, got %s", result.Action)
	}
}

func TestRuleCookiePassRulePositionIndependent(t *testing.T) {
	// pass rules are whitelist semantics: a match short-circuits remaining
	// rules. Under match-any the whitelist fires regardless of which
	// position carries the whitelisted value.
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "p85", Name: "bypass token", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "cookie:bypass", Op: "equals", Value: "allow-me"}},
				Action:     "pass", Score: 0,
			},
			{
				ID: "l85", Name: "log all", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "path", Op: "equals", Value: "/"}},
				Action:     "log", Score: 5,
			},
		},
	}, nil)

	// Whitelisted value in the SECOND position: the pass rule must fire and
	// short-circuit the later log rule (score stays 0).
	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.Cookies = map[string][]string{"bypass": {"nope", "allow-me"}}
	if result := layer.Process(ctx); result.Score != 0 {
		t.Fatalf("FAIL: pass whitelist in second position did not short-circuit (score=%d)", result.Score)
	}

	// Without the whitelisted value the log rule fires.
	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	ctx2.Cookies = map[string][]string{"bypass": {"nope"}}
	if result := layer.Process(ctx2); result.Score != 5 {
		t.Fatalf("FAIL: log rule should fire when not whitelisted (score=%d)", result.Score)
	}
}

func TestRuleCookieAbsentNegatedOpFires(t *testing.T) {
	// Absent cookie: the condition resolves against "" exactly as before
	// multi-value support — not_equals fires on a missing cookie
	// (mirrors the pre-existing TestRuleMissingCookie equals-"" pin).
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "a85", Name: "missing session", Enabled: true,
			Conditions: []Condition{{Field: "cookie:session", Op: "not_equals", Value: "valid-token"}},
			Action:     "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Fatalf("FAIL: not_equals should fire on an absent cookie (empty-value resolution), got %s", result.Action)
	}
}
