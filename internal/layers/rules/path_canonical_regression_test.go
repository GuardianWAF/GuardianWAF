package rules

// Regression: the "path" condition field must be resolved to the path the
// upstream actually serves, not the raw wire path.
//
// ctx.Path is r.URL.Path: net/url decodes percent-escapes but never resolves
// dot-segments, so "/admin/./panel" and "/x/../admin/panel" reach the backend
// as "/admin/panel" while an operator's path-scoped deny rule written against
// the real route silently never fired — a fail-open custom rule.
//
// The ordering matters and is asserted here: the rules layer is order 155 and
// the sanitizer that populates ctx.NormalizedPath is order 300, so in the real
// pipeline NormalizedPath is STILL EMPTY when these conditions are evaluated.
// The tests therefore drive the rules layer FIRST, exactly as production does,
// which is what keeps the layer from depending on a field it never sees.

import (
	"bufio"
	"net/http"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// newDenyRuleLayer builds the rules layer with one operator deny rule.
func newDenyRuleLayer(op, value string) *Layer {
	return NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{{
			ID:       "R-DENY-ADMIN",
			Name:     "deny admin panel",
			Enabled:  true,
			Priority: 1,
			Conditions: []Condition{{
				Field: "path",
				Op:    op,
				Value: value,
			}},
			Action: "block",
			Score:  90,
		}},
	}, nil)
}

// runRuleFirst drives one raw HTTP request through the rules layer in
// PRODUCTION order (rules 155, then the sanitizer at 300).
func runRuleFirst(t *testing.T, rawRequest, op, condValue string) engine.LayerResult {
	t.Helper()

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawRequest)))
	if err != nil {
		t.Fatalf("harness setup failed: could not parse request: %v", err)
	}
	req.RemoteAddr = "203.0.113.10:5555"

	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)

	res := newDenyRuleLayer(op, condValue).Process(ctx)

	// Order 300, after the layer under test. Guards against a fix that
	// "passes" by canonicalizing to something the sanitizer disagrees with.
	_ = sanitizer.NewLayer(&sanitizer.Config{
		MaxURLLength:   8192,
		MaxHeaderSize:  64 * 1024,
		MaxHeaderCount: 150,
		MaxBodySize:    1 << 20,
		MaxCookieSize:  4096,
		BlockNullBytes: true,
	}).Process(ctx)

	if ctx.NormalizedPath == "" {
		t.Fatalf("harness setup failed: sanitizer left NormalizedPath empty")
	}
	return res
}

func get(target string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
}

// The defect: path spellings that the backend resolves to the protected route
// must not bypass the operator's deny rule.
func TestRulesPathCondition_NotBypassedByEquivalentSpellings(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		op      string
		condVal string
	}{
		{"dot_segment_contains", "/admin/./panel", "contains", "/admin/panel"},
		{"double_slash_contains", "/admin//panel", "contains", "/admin/panel"},
		{"traversal_equals", "/x/../admin/panel", "equals", "/admin/panel"},
		{"traversal_matches", "/public/../admin/panel", "matches", "^/admin/panel$"},
		{"dot_segment_equals", "/admin/./panel", "equals", "/admin/panel"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runRuleFirst(t, get(tc.target), tc.op, tc.condVal)
			if res.Action != engine.ActionBlock {
				t.Errorf("deny rule (path %s %q) bypassed by %s: action=%v score=%d findings=%d",
					tc.op, tc.condVal, tc.target, res.Action, res.Score, len(res.Findings))
			}
		})
	}
}

// Control: the canonical spelling keeps blocking. Fails if the fix REPLACED
// the raw form instead of adding the canonical one.
func TestRulesPathCondition_CanonicalPathStillBlocked(t *testing.T) {
	for _, op := range []string{"equals", "contains", "matches"} {
		val := "/admin/panel"
		if op == "matches" {
			val = "^/admin/panel$"
		}
		res := runRuleFirst(t, get("/admin/panel"), op, val)
		if res.Action != engine.ActionBlock {
			t.Errorf("canonical /admin/panel not blocked for op=%s (action=%v)", op, res.Action)
		}
	}
}

// Control: paths the rule does not target must still pass — canonicalization
// must not widen the rule into matching everything.
func TestRulesPathCondition_UnrelatedPathsStillPass(t *testing.T) {
	for _, target := range []string{
		"/public/blog",
		"/adminx/panel",
		"/administrator/panelx",
		"/",
	} {
		res := runRuleFirst(t, get(target), "contains", "/admin/panel")
		if res.Action != engine.ActionPass {
			t.Errorf("unrelated path %s blocked (action=%v score=%d)", target, res.Action, res.Score)
		}
	}
}

// canonicalPath must be correct in both states the layer can observe:
// NormalizedPath already populated, and empty (the real pipeline at order 155).
func TestCanonicalPath_BothStates(t *testing.T) {
	t.Run("prefers_populated_normalized_path", func(t *testing.T) {
		ctx := &engine.RequestContext{Path: "/admin/./panel", NormalizedPath: "/admin/panel"}
		if got := canonicalPath(ctx); got != "/admin/panel" {
			t.Errorf("got %q, want %q", got, "/admin/panel")
		}
	})

	t.Run("computes_when_empty_as_in_production", func(t *testing.T) {
		// This is the production state at order 155 — NormalizedPath unset.
		ctx := &engine.RequestContext{Path: "/admin/./panel"}
		if ctx.NormalizedPath != "" {
			t.Fatalf("harness assumption broken: NormalizedPath should be empty here")
		}
		if got := canonicalPath(ctx); got != "/admin/panel" {
			t.Errorf("got %q, want %q", got, "/admin/panel")
		}
	})

	t.Run("ordinary_paths_are_unchanged", func(t *testing.T) {
		// Ordinary paths must be a no-op so existing operator rules and the
		// existing suite keep their exact-match semantics.
		for _, p := range []string{"/", "/api/users", "/api/v1/things", "/index.html"} {
			ctx := &engine.RequestContext{Path: p}
			if got := canonicalPath(ctx); got != p {
				t.Errorf("ordinary path %q was rewritten to %q", p, got)
			}
		}
	})

	t.Run("empty_path_stays_empty", func(t *testing.T) {
		// NormalizeAll("") is "" and ctx.Path is "", so the pre-fix
		// behaviour (empty path -> empty field value) is preserved exactly.
		// An absent path must not silently become "/" and start matching
		// operator rules written against an empty field value.
		if got := canonicalPath(&engine.RequestContext{}); got != "" {
			t.Errorf("empty path got %q, want %q", got, "")
		}
	})
}

// The rule's own Field vocabulary documents "path"; the resolved value must be
// the canonical route for every op, including the CIDR-adjacent numeric ones
// staying untouched (path is a string field, so only string ops apply).
func TestGetFieldValue_PathFieldIsCanonical(t *testing.T) {
	l := newDenyRuleLayer("contains", "/admin/panel")
	ctx := &engine.RequestContext{Path: "/x/../admin/panel"}

	got := l.getFieldValue("path", ctx)
	if got != "/admin/panel" {
		t.Errorf("getFieldValue(\"path\") = %q, want %q", got, "/admin/panel")
	}

	// Other fields must remain exactly as before this change.
	if got := l.getFieldValue("method", ctx); got != "" {
		t.Errorf("method field should be empty, got %q", got)
	}
	if got := l.getFieldValue("nonexistent_field", ctx); got != "" {
		t.Errorf("unknown field should be empty, got %q", got)
	}
}
