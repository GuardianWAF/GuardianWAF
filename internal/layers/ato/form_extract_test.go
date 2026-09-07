package ato

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: ATO form-format credential extraction must URL-decode
// form values before matching. Browsers percent-encode '@' as %40 in
// application/x-www-form-urlencoded bodies, so the raw value
// "user%40example.com" failed emailRe, extractEmail returned "", and
// Process returned ActionPass before any ATO check ran and before the
// attempt was recorded — brute-force, credential-stuffing, and
// password-spray detection were inert for urlencoded form logins.

func newTestLayer(t *testing.T) *Layer {
	t.Helper()
	layer, err := NewLayer(&Config{
		Enabled:    true,
		LoginPaths: []string{"/login"},
		BruteForce: BruteForceConfig{
			Enabled:             true,
			MaxAttemptsPerIP:    3,
			MaxAttemptsPerEmail: 3,
			Window:              time.Minute,
			BlockDuration:       time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	return layer
}

func TestExtractEmailFormURLDecoding(t *testing.T) {
	l, err := NewLayer(&Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	// Percent-encoded '@' must decode and match.
	if got := l.extractEmail("email=user%40example.com&password=x"); got != "user@example.com" {
		t.Fatalf("FAIL: urlencoded email extracted as %q, want user@example.com", got)
	}

	// Literal '@' keeps working.
	if got := l.extractEmail("email=user@example.com&password=x"); got != "user@example.com" {
		t.Fatalf("FAIL: literal-@ email extracted as %q", got)
	}

	// Username and login keys work too.
	if got := l.extractEmail("username=admin%40corp.example&password=x"); got != "admin@corp.example" {
		t.Fatalf("FAIL: urlencoded username extracted as %q", got)
	}

	// Invalid escape sequences fall back to the raw value (which the email
	// regex rejects — no extraction, not a panic).
	if got := l.extractEmail("email=a%zz%40example.com"); got != "" {
		t.Fatalf("FAIL: invalid-escape email extracted as %q, want empty", got)
	}
}

func TestExtractPasswordFormURLDecoding(t *testing.T) {
	l, err := NewLayer(&Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	if got := l.extractPassword("email=user%40example.com&password=p%40ss%26word"); got != "p@ss&word" {
		t.Fatalf("FAIL: urlencoded password extracted as %q, want p@ss&word", got)
	}

	if got := l.extractPassword("email=user@example.com&password=plain"); got != "plain" {
		t.Fatalf("FAIL: plain password extracted as %q", got)
	}

	// Invalid escapes fall back to the raw value.
	if got := l.extractPassword("password=p%zz"); got != "p%zz" {
		t.Fatalf("FAIL: invalid-escape password extracted as %q, want %q", got, "p%zz")
	}
}

// Integration: a urlencoded form login must engage brute-force protection —
// attempts 1-3 pass, 4+ block (MaxAttemptsPerIP=3) — with literal-@ and JSON
// logins as controls.
func TestATOBruteForceUrlencodedFormLogin(t *testing.T) {
	run := func(body string) []engine.Action {
		layer := newTestLayer(t)
		actions := make([]engine.Action, 0, 5)
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("POST", "/login", nil)
			ctx := &engine.RequestContext{
				Method:     "POST",
				Path:       "/login",
				BodyString: body,
				ClientIP:   net.ParseIP("10.9.9.9"),
				Request:    req,
			}
			actions = append(actions, layer.Process(ctx).Action)
		}
		return actions
	}

	assertProgression := func(label string, actions []engine.Action) {
		t.Helper()
		for i := 0; i < 3; i++ {
			if actions[i] != engine.ActionPass {
				t.Fatalf("FAIL: %s attempt %d blocked before the threshold (action %v)", label, i+1, actions[i])
			}
		}
		for i := 3; i < 5; i++ {
			if actions[i] != engine.ActionBlock {
				t.Fatalf("FAIL: %s attempt %d did not block after the threshold (action %v)", label, i+1, actions[i])
			}
		}
	}

	// THE DEFECT: urlencoded form login must engage protection.
	assertProgression("urlencoded", run("email=user%40example.com&password=guess"))
	// Controls.
	assertProgression("literal-@", run("email=user@example.com&password=guess"))
	assertProgression("json", run(`{"email":"user@example.com","password":"guess"}`))
}
