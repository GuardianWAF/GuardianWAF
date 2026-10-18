package ratelimit

// Regression: the canonical-path dual view in Process must work in the REAL
// pipeline, not only in hand-built contexts.
//
// ctx.NormalizedPath is written only by the sanitizer (sanitizer.go:63/103),
// which runs at engine.OrderSanitizer = 300, while this layer runs at
// engine.OrderRateLimit = 200. A previous fix read the field and fell back to
// the raw ctx.Path when it was empty — on every live request it WAS empty, so
// the fallback silently re-opened the bypass: an ip+path rate limit on /login
// was never applied at all to "/x/../login", which upstreams serve as /login.
//
// The earlier regression (encoded_path_test.go) hand-builds a RequestContext
// with NormalizedPath already set (line 29) — a state the pipeline never
// produces — so it stayed green while the live path was open. These tests
// drive the real engine pipeline over layers sorted by their real Order()
// constants, which is the only way to observe the defect.
//
// Note on mechanism: ctx.Path is r.URL.Path, and net/url ALREADY resolves
// percent-escapes there — so percent-encoding alone does not evade a rule.
// The live bypass is the dot-segment / double-slash class, which net/url does
// not resolve. encoded_path_test.go's percent-encoding framing therefore does
// not describe the reachable evasion; these tests pin the class that is.

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

const orderProbeClientIP = "203.0.113.10:5555"

func newOrderProbeEngine(t *testing.T, rules []Rule) *engine.Engine {
	t.Helper()

	eng, err := engine.NewEngine(config.DefaultConfig(),
		events.NewMemoryStore(256), events.NewEventBus())
	if err != nil {
		t.Fatalf("harness setup failed: NewEngine: %v", err)
	}

	rlLayer := NewLayer(&Config{Enabled: true, Rules: rules})
	sanLayer := sanitizer.NewLayer(&sanitizer.Config{
		MaxURLLength:   8192,
		MaxHeaderSize:  64 * 1024,
		MaxHeaderCount: 150,
		MaxBodySize:    1 << 20,
		MaxCookieSize:  4096,
		BlockNullBytes: true,
	})

	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: rlLayer.Order()})
	eng.AddLayer(engine.OrderedLayer{Layer: sanLayer, Order: sanLayer.Order()})

	if rlLayer.Order() >= sanLayer.Order() {
		t.Fatalf("harness assumption broken: ratelimit order %d must be < sanitizer order %d",
			rlLayer.Order(), sanLayer.Order())
	}
	return eng
}

func orderProbeAction(t *testing.T, eng *engine.Engine, target string) engine.Action {
	t.Helper()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(
		"GET " + target + " HTTP/1.1\r\nHost: app.example.com\r\n\r\n")))
	if err != nil {
		t.Fatalf("harness setup failed: could not parse request: %v", err)
	}
	req.RemoteAddr = orderProbeClientIP

	ev := eng.Check(req)
	if ev == nil {
		t.Fatalf("harness setup failed: Check returned nil event")
	}
	return ev.Action
}

func orderProbeBurst(t *testing.T, eng *engine.Engine, target string, n int) (blocked bool, at int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if orderProbeAction(t, eng, target) == engine.ActionBlock {
			return true, i
		}
	}
	return false, -1
}

func loginProbeRule() []Rule {
	return []Rule{{
		ID: "R-LOGIN", Scope: "ip+path", Paths: []string{"/login"},
		Limit: 2, Window: time.Minute, Burst: 2, Action: "block",
	}}
}

func adminProbeRule() []Rule {
	return []Rule{{
		ID: "R-ADMIN", Scope: "ip+path", Paths: []string{"/admin/**"},
		Limit: 2, Window: time.Minute, Burst: 2, Action: "block",
	}}
}

// THE DEFECT: alternate spellings of a rate-limited route must be limited too.
// Pre-fix every one of these returned action=pass forever.
func TestRateLimitPath_RealPipelineNotBypassed(t *testing.T) {
	cases := []struct {
		name   string
		rules  []Rule
		target string
	}{
		{"traversal_login", loginProbeRule(), "/x/../login"},
		{"traversal_admin", adminProbeRule(), "/admin/../admin/api/users"},
		{"double_slash_login", loginProbeRule(), "//login"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newOrderProbeEngine(t, tc.rules)
			blocked, _ := orderProbeBurst(t, eng, tc.target, 10)
			if !blocked {
				t.Errorf("ip+path rate limit was fully bypassed by %s "+
					"(10 requests, none blocked); upstream resolves it to the ruled route",
					tc.target)
			}
		})
	}
}

// Controls: legitimate behaviour must survive the same pipeline. A fix that
// broke limiting, or that widened a rule to every path, would be unacceptable.
func TestRateLimitPath_RealPipelineControls(t *testing.T) {
	t.Run("literal_ruled_path_is_limited", func(t *testing.T) {
		eng := newOrderProbeEngine(t, loginProbeRule())
		blocked, at := orderProbeBurst(t, eng, "/login", 10)
		if !blocked {
			t.Fatalf("literal /login was never rate limited; harness is not exercising a real bucket")
		}
		if at > 5 {
			t.Errorf("/login blocked only at request %d, expected early exhaustion", at)
		}
	})

	t.Run("path_outside_rule_is_not_limited", func(t *testing.T) {
		eng := newOrderProbeEngine(t, loginProbeRule())
		if blocked, _ := orderProbeBurst(t, eng, "/public/blog", 10); blocked {
			t.Errorf("/public/blog is outside the rule but got rate limited")
		}
	})

	t.Run("sibling_prefix_is_not_limited", func(t *testing.T) {
		// "/loginfoo" is not the "/login" route; canonicalization must not
		// widen an exact rule into a prefix match.
		eng := newOrderProbeEngine(t, loginProbeRule())
		if blocked, _ := orderProbeBurst(t, eng, "/loginfoo", 10); blocked {
			t.Errorf("/loginfoo is a sibling of /login but got rate limited")
		}
	})

	t.Run("catch_all_rule_still_limited", func(t *testing.T) {
		eng := newOrderProbeEngine(t, []Rule{{
			ID: "R-ALL", Scope: "ip", Paths: nil,
			Limit: 2, Window: time.Minute, Burst: 2, Action: "block",
		}})
		if blocked, _ := orderProbeBurst(t, eng, "/anything/at/all", 10); !blocked {
			t.Errorf("catch-all rule never limited /anything/at/all")
		}
	})
}

// The unit-level contract the hand-built tests missed: with NormalizedPath
// EMPTY — the state every live request is in, because this layer runs before
// the sanitizer — the layer must canonicalize ctx.Path itself instead of
// falling back to the raw wire path. A ratelimit finding only appears once the
// bucket is exhausted, so each case drives Process until the rule fires.
func TestRateLimitPath_UsesWirePathWhenNormalizedAbsent(t *testing.T) {
	newCtx := func(path, normalized string) *engine.RequestContext {
		return &engine.RequestContext{
			Path:           path,
			NormalizedPath: normalized,
			ClientIP:       net.ParseIP("203.0.113.10"),
			Method:         http.MethodGet,
			Headers:        map[string][]string{},
			QueryParams:    map[string][]string{},
			Metadata:       map[string]any{},
		}
	}

	// ruleFires drives Process until the rule produces a ratelimit finding.
	ruleFires := func(t *testing.T, layer *Layer, ctx *engine.RequestContext) bool {
		t.Helper()
		for i := 0; i < 5; i++ {
			res := layer.Process(ctx)
			for _, f := range res.Findings {
				if f.DetectorName == "ratelimit" {
					return true
				}
			}
		}
		return false
	}

	t.Run("empty_normalized_still_matches_rule", func(t *testing.T) {
		// Production state at order 200.
		layer := NewLayer(&Config{Enabled: true, Rules: loginProbeRule()})
		ctx := newCtx("/x/../login", "")
		if !ruleFires(t, layer, ctx) {
			t.Errorf("rule /login never fired for raw wire path %q with NormalizedPath empty", ctx.Path)
		}
	})

	t.Run("populated_normalized_still_honoured", func(t *testing.T) {
		// The scenario encoded_path_test.go covers; it must keep working and
		// must not be the ONLY covered state.
		layer := NewLayer(&Config{Enabled: true, Rules: loginProbeRule()})
		ctx := newCtx("/x/../login", "/login")
		if !ruleFires(t, layer, ctx) {
			t.Errorf("rule /login never fired for normalized path %q", ctx.NormalizedPath)
		}
	})

	t.Run("unrelated_path_still_does_not_match", func(t *testing.T) {
		layer := NewLayer(&Config{Enabled: true, Rules: loginProbeRule()})
		ctx := newCtx("/public/blog", "")
		if ruleFires(t, layer, ctx) {
			t.Errorf("rule /login wrongly fired for %q", "/public/blog")
		}
	})

	t.Run("sibling_prefix_still_does_not_match", func(t *testing.T) {
		// Canonicalization must not widen an exact rule into a prefix match.
		layer := NewLayer(&Config{Enabled: true, Rules: loginProbeRule()})
		ctx := newCtx("/loginfoo", "")
		if ruleFires(t, layer, ctx) {
			t.Errorf("rule /login wrongly fired for the sibling %q", "/loginfoo")
		}
	})
}
