package config

import (
	"testing"
)

// Regression (round 2026-09-18): parseRateLimitRule validated id/limit/window/
// burst/auto_ban_after but not the path patterns, and matchPath in
// internal/layers/ratelimit maps path.Match's ErrPattern to "no match" — so a
// rule with a malformed glob (unclosed '[', trailing '\', empty '[]') loaded
// cleanly, reported live, and silently never fired: the rate limit did not
// apply. Malformed globs now fail the rule load (fail-closed, same policy as
// unsupported transformations and SecLang phases 1-5). Validation uses
// path.Match(pattern, pattern) — the same engine as runtime matching, so the
// accepted set cannot diverge from what the layer will actually parse.

func TestParseRateLimitRuleRejectsMalformedGlobs(t *testing.T) {
	mk := func(paths string) *Node {
		return &Node{Kind: MapNode, MapItems: map[string]*Node{
			"id":     {Kind: ScalarNode, Value: "glob-rule"},
			"scope":  {Kind: ScalarNode, Value: "ip+path"},
			"paths":  {Kind: SequenceNode, Items: []*Node{{Kind: ScalarNode, Value: paths}}},
			"limit":  {Kind: ScalarNode, Value: "5"},
			"window": {Kind: ScalarNode, Value: "60s"},
		}, MapKeys: []string{"id", "scope", "paths", "limit", "window"}}
	}

	for _, bad := range []string{"/api/[bad", "/x\\", "[]"} {
		if _, err := parseRateLimitRule(mk(bad)); err == nil {
			t.Fatalf("malformed path pattern %q accepted at load — the rule would load and silently never match", bad)
		}
	}
}

func TestParseRateLimitRuleAcceptsValidGlobs(t *testing.T) {
	mk := func(paths string) *Node {
		return &Node{Kind: MapNode, MapItems: map[string]*Node{
			"id":     {Kind: ScalarNode, Value: "glob-rule"},
			"scope":  {Kind: ScalarNode, Value: "ip+path"},
			"paths":  {Kind: SequenceNode, Items: []*Node{{Kind: ScalarNode, Value: paths}}},
			"limit":  {Kind: ScalarNode, Value: "5"},
			"window": {Kind: ScalarNode, Value: "60s"},
		}, MapKeys: []string{"id", "scope", "paths", "limit", "window"}}
	}

	for _, ok := range []string{"/api/**", "/api/*", "/login", "[a]", "[^a]", "/x[z-a]"} {
		r, err := parseRateLimitRule(mk(ok))
		if err != nil {
			t.Fatalf("valid path pattern %q rejected: %v", ok, err)
		}
		if len(r.Paths) != 1 || r.Paths[0] != ok {
			t.Fatalf("paths round-trip failed: %v", r.Paths)
		}
	}
}
