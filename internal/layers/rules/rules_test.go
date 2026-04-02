package rules

import (
	"net"
	"net/http"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func testCtx(method, path string, ip string, headers map[string][]string) *engine.RequestContext {
	req, _ := http.NewRequest(method, "http://localhost"+path, nil)
	for k, v := range headers {
		req.Header[k] = v
	}
	ctx := &engine.RequestContext{
		Request:     req,
		Method:      method,
		Path:        path,
		ClientIP:    net.ParseIP(ip),
		Headers:     headers,
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}
	return ctx
}

func TestRuleMatchPath(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Block /admin", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/admin"}},
			Action:     "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/admin/settings", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}

	// Non-matching path
	ctx2 := testCtx("GET", "/api/users", "1.2.3.4", nil)
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionPass {
		t.Errorf("expected pass for /api, got %s", result2.Action)
	}
}

func TestRuleMatchMethod(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r2", Name: "Log DELETE", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "equals", Value: "DELETE"}},
			Action:     "log", Score: 20,
		}},
	}, nil)

	ctx := testCtx("DELETE", "/api/resource", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log, got %s", result.Action)
	}
}

func TestRuleMatchUserAgent(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r3", Name: "Challenge bots", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "user_agent", Op: "contains", Value: "bot"}},
			Action:     "challenge", Score: 40,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", map[string][]string{
		"User-Agent": {"Googlebot/2.1"},
	})
	result := layer.Process(ctx)
	if result.Action != engine.ActionChallenge {
		t.Errorf("expected challenge, got %s", result.Action)
	}
}

func TestRuleMatchHeader(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r4", Name: "Block bad referer", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "header:Referer", Op: "contains", Value: "evil.com"}},
			Action:     "block", Score: 80,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", map[string][]string{
		"Referer": {"https://evil.com/spam"},
	})
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block, got %s", result.Action)
	}
}

func TestRuleMatchIPCIDR(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r5", Name: "Block internal", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "ip", Op: "in_cidr", Value: "10.0.0.0/8"}},
			Action:     "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "10.0.0.1", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for 10.0.0.1, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "192.168.1.1", nil)
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionPass {
		t.Errorf("expected pass for 192.168.1.1, got %s", result2.Action)
	}
}

func TestRuleMultipleConditionsAND(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r6", Name: "Block POST /admin", Enabled: true, Priority: 1,
			Conditions: []Condition{
				{Field: "method", Op: "equals", Value: "POST"},
				{Field: "path", Op: "starts_with", Value: "/admin"},
			},
			Action: "block", Score: 100,
		}},
	}, nil)

	// Both match
	ctx := testCtx("POST", "/admin/login", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for POST /admin, got %s", result.Action)
	}

	// Only path matches
	ctx2 := testCtx("GET", "/admin/login", "1.2.3.4", nil)
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionPass {
		t.Errorf("expected pass for GET /admin (method doesn't match), got %s", result2.Action)
	}
}

func TestRuleDisabled(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r7", Name: "Disabled rule", Enabled: false, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "equals", Value: "/"}},
			Action:     "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("disabled rule should not match, got %s", result.Action)
	}
}

func TestRulePassAction(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "whitelist", Name: "Whitelist /health", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "equals", Value: "/health"}},
				Action:     "pass", Score: 0,
			},
			{ID: "block-all", Name: "Block all", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action:     "block", Score: 100,
			},
		},
	}, nil)

	// /health should pass (whitelist rule has higher priority)
	ctx := testCtx("GET", "/health", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for /health whitelist, got %s", result.Action)
	}

	// /other should block
	ctx2 := testCtx("GET", "/other", "1.2.3.4", nil)
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionBlock {
		t.Errorf("expected block for /other, got %s", result2.Action)
	}
}

func TestRuleRegexMatch(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "regex", Name: "Regex test", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "matches", Value: `^/api/v[0-9]+/`}},
			Action:     "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/api/v2/users", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log for regex match, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/api/legacy/users", "1.2.3.4", nil)
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionPass {
		t.Errorf("expected pass for no regex match, got %s", result2.Action)
	}
}

func TestRuleInList(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "methods", Name: "Block unsafe methods", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "in", Value: []string{"DELETE", "PATCH"}}},
			Action:     "block", Score: 50,
		}},
	}, nil)

	ctx := testCtx("DELETE", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for DELETE, got %s", result.Action)
	}
}

func TestRuleCRUD(t *testing.T) {
	layer := NewLayer(Config{Enabled: true}, nil)

	// Add
	layer.AddRule(Rule{ID: "a", Name: "A", Enabled: true, Priority: 2})
	layer.AddRule(Rule{ID: "b", Name: "B", Enabled: true, Priority: 1})
	rules := layer.Rules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "b" {
		t.Errorf("expected b first (priority 1), got %s", rules[0].ID)
	}

	// Toggle
	layer.ToggleRule("a", false)
	rules = layer.Rules()
	for _, r := range rules {
		if r.ID == "a" && r.Enabled {
			t.Error("rule a should be disabled")
		}
	}

	// Update
	layer.UpdateRule(Rule{ID: "a", Name: "A-updated", Enabled: true, Priority: 0})
	rules = layer.Rules()
	if rules[0].ID != "a" {
		t.Errorf("a should be first after priority 0, got %s", rules[0].ID)
	}

	// Remove
	layer.RemoveRule("b")
	if len(layer.Rules()) != 1 {
		t.Errorf("expected 1 rule after delete, got %d", len(layer.Rules()))
	}
}

func TestLayerName(t *testing.T) {
	layer := NewLayer(Config{}, nil)
	if layer.Name() != "rules" {
		t.Errorf("expected 'rules', got %s", layer.Name())
	}
}

func BenchmarkRuleEvaluation(b *testing.B) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/api"}},
				Action:     "log", Score: 10},
			{ID: "r2", Enabled: true, Priority: 2,
				Conditions: []Condition{
					{Field: "method", Op: "equals", Value: "POST"},
					{Field: "user_agent", Op: "contains", Value: "bot"},
				},
				Action: "block", Score: 100},
		},
	}, nil)

	ctx := testCtx("GET", "/api/users", "1.2.3.4", map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
	})

	b.ResetTimer()
	for range b.N {
		layer.Process(ctx)
	}
}
