package rules

import (
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
)

func TestRuleNotEquals(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Non-GET", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "not_equals", Value: "GET"}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("POST", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for POST, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for GET, got %s", result.Action)
	}
}

func TestRuleNotContains(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "No api", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "not_contains", Value: "api"}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/home", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for /home, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/api/users", "1.2.3.4", nil)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for /api, got %s", result.Action)
	}
}

func TestRuleEndsWith(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "PHP files", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "ends_with", Value: ".php"}},
			Action: "block", Score: 50,
		}},
	}, nil)

	ctx := testCtx("GET", "/wp-admin/index.php", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for .php, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/index.html", "1.2.3.4", nil)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for .html, got %s", result.Action)
	}
}

func TestRuleNotIn(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Block non-standard", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "not_in", Value: []string{"GET", "POST", "PUT"}}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("DELETE", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for DELETE, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for GET, got %s", result.Action)
	}
}

func TestRuleGreaterThan(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Large body", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "body_size", Op: "greater_than", Value: "100"}},
			Action: "log", Score: 20,
		}},
	}, nil)

	ctx := testCtx("POST", "/", "1.2.3.4", nil)
	ctx.Body = make([]byte, 200)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for large body, got %s", result.Action)
	}

	ctx2 := testCtx("POST", "/", "1.2.3.4", nil)
	ctx2.Body = make([]byte, 50)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for small body, got %s", result.Action)
	}
}

func TestRuleLessThan(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Tiny body", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "body_size", Op: "less_than", Value: "10"}},
			Action: "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("POST", "/", "1.2.3.4", nil)
	ctx.Body = make([]byte, 5)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for tiny body, got %s", result.Action)
	}
}

func TestRuleMatchHost(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Admin host", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "host", Op: "equals", Value: "admin.example.com"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	req, _ := http.NewRequest("GET", "http://admin.example.com/", nil)
	ctx := &engine.RequestContext{
		Request:     req,
		Method:      "GET",
		Path:        "/",
		ClientIP:    net.ParseIP("1.2.3.4"),
		Headers:     map[string][]string{},
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}

	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for admin host, got %s", result.Action)
	}
}

func TestRuleMatchContentType(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Block XML", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "content_type", Op: "contains", Value: "xml"}},
			Action: "block", Score: 80,
		}},
	}, nil)

	ctx := testCtx("POST", "/api", "1.2.3.4", nil)
	ctx.ContentType = "application/xml"
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for XML, got %s", result.Action)
	}
}

func TestRuleMatchQuery(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Block debug", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "query", Op: "contains", Value: "debug=true"}},
			Action: "block", Score: 50,
		}},
	}, nil)

	req, _ := http.NewRequest("GET", "http://localhost/?debug=true&foo=bar", nil)
	ctx := &engine.RequestContext{
		Request:     req,
		Method:      "GET",
		Path:        "/",
		ClientIP:    net.ParseIP("1.2.3.4"),
		Headers:     map[string][]string{},
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}

	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for debug query, got %s", result.Action)
	}
}

func TestRuleMatchCookie(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Admin cookie", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "cookie:role", Op: "equals", Value: "admin"}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.Cookies = map[string]string{"role": "admin"}
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for admin cookie, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	ctx2.Cookies = map[string]string{"role": "user"}
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for user cookie, got %s", result.Action)
	}
}

func TestRuleMatchScore(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "High score", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "score", Op: "greater_than", Value: "50"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.Accumulator.Add(engine.Finding{DetectorName: "test", Score: 60})
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for high score, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "1.2.3.4", nil)
	ctx2.Accumulator.Add(engine.Finding{DetectorName: "test", Score: 10})
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for low score, got %s", result.Action)
	}
}

func TestRuleMatchIP(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Match IP", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "ip", Op: "equals", Value: "10.0.0.1"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "10.0.0.1", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for matching IP, got %s", result.Action)
	}
}

func TestRuleMatchNilIP(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Match empty IP", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "ip", Op: "equals", Value: ""}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "", nil)
	ctx.ClientIP = nil
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for nil IP, got %s", result.Action)
	}
}

func TestRuleInvalidRegex(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Bad regex", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "matches", Value: "[invalid"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/test", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionPass {
		t.Errorf("expected pass for invalid regex, got %s", result.Action)
	}
}

func TestRuleInCIDR_PlainIP(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Match exact IP", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "ip", Op: "in_cidr", Value: "10.0.0.1"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "10.0.0.1", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for exact IP CIDR match, got %s", result.Action)
	}

	ctx2 := testCtx("GET", "/", "10.0.0.2", nil)
	if result := layer.Process(ctx2); result.Action != engine.ActionPass {
		t.Errorf("expected pass for different IP, got %s", result.Action)
	}
}

func TestRuleInCIDR_NilIP(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "CIDR nil", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "ip", Op: "in_cidr", Value: "10.0.0.0/8"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "", nil)
	ctx.ClientIP = nil
	if result := layer.Process(ctx); result.Action != engine.ActionPass {
		t.Errorf("expected pass for nil IP in CIDR check, got %s", result.Action)
	}
}

func TestRuleInList_StringValue(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Single value in", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "in", Value: "DELETE"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("DELETE", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Errorf("expected block for string value in, got %s", result.Action)
	}
}

func TestRuleInList_AnySlice(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Any slice in", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "method", Op: "in", Value: []any{"GET", "POST"}}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("POST", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for any slice in, got %s", result.Action)
	}
}

func TestRuleActionPromotion(t *testing.T) {
	// Test that block > challenge > log
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Name: "Log rule", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action: "log", Score: 10},
			{ID: "r2", Name: "Challenge rule", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action: "challenge", Score: 20},
		},
	}, nil)

	ctx := testCtx("GET", "/test", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionChallenge {
		t.Errorf("expected challenge (promoted from log), got %s", result.Action)
	}
	if result.Score != 30 {
		t.Errorf("expected total score 30, got %d", result.Score)
	}
}

func TestRuleBlockPromotesOverChallenge(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Name: "Challenge", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action: "challenge", Score: 20},
			{ID: "r2", Name: "Block", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action: "block", Score: 80},
		},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block to promote over challenge, got %s", result.Action)
	}
}

func TestRuleUnknownOperator(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Unknown op", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "fizzbuzz", Value: "test"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/test", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionPass {
		t.Errorf("expected pass for unknown operator, got %s", result.Action)
	}
}

func TestRuleUnknownField(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Unknown field", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "nonexistent", Op: "equals", Value: "anything"}},
			Action: "block", Score: 100,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	// Empty string field won't equal "anything"
	if result := layer.Process(ctx); result.Action != engine.ActionPass {
		t.Errorf("expected pass for unknown field, got %s", result.Action)
	}
}

func TestRuleUnknownAction(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Unknown action", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "equals", Value: "/"}},
			Action: "unknown_action", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	// Default action for unknown is log
	if result.Action != engine.ActionLog {
		t.Errorf("expected log for unknown action, got %s", result.Action)
	}
}

func TestRuleWithGeoIP(t *testing.T) {
	// Create a test geoip DB
	db := geoip.New()
	// We can't easily add ranges to geoip.New() since it's empty,
	// so we test with nil geoip and country field returns ""
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Block country", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "country", Op: "equals", Value: ""}},
			Action: "log", Score: 10,
		}},
	}, db)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for empty country, got %s", result.Action)
	}
}

func TestRuleCountryNilGeoDB(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Country nil", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "country", Op: "equals", Value: ""}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for nil geodb, got %s", result.Action)
	}
}

func TestRuleUpdateNonExistent(t *testing.T) {
	layer := NewLayer(Config{Enabled: true}, nil)
	ok := layer.UpdateRule(Rule{ID: "nope"})
	if ok {
		t.Error("expected false for non-existent rule update")
	}
}

func TestRuleRemoveNonExistent(t *testing.T) {
	layer := NewLayer(Config{Enabled: true}, nil)
	ok := layer.RemoveRule("nope")
	if ok {
		t.Error("expected false for non-existent rule remove")
	}
}

func TestRuleToggleNonExistent(t *testing.T) {
	layer := NewLayer(Config{Enabled: true}, nil)
	ok := layer.ToggleRule("nope", true)
	if ok {
		t.Error("expected false for non-existent rule toggle")
	}
}

func TestRuleSetRulesClearsCache(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "matches", Value: `^/api`}},
			Action: "log", Score: 10,
		}},
	}, nil)

	// Trigger regex cache
	ctx := testCtx("GET", "/api/test", "1.2.3.4", nil)
	layer.Process(ctx)

	// SetRules should clear cache
	layer.SetRules([]Rule{{
		ID: "r2", Enabled: true, Priority: 1,
		Conditions: []Condition{{Field: "path", Op: "matches", Value: `^/new`}},
		Action: "log", Score: 10,
	}})

	layer.mu.RLock()
	cacheLen := len(layer.regexCache)
	layer.mu.RUnlock()

	if cacheLen != 0 {
		t.Errorf("expected empty regex cache after SetRules, got %d", cacheLen)
	}
}

func TestToString_Nil(t *testing.T) {
	if s := toString(nil); s != "" {
		t.Errorf("expected empty for nil, got %q", s)
	}
}

func TestToString_Number(t *testing.T) {
	if s := toString(42); s != "42" {
		t.Errorf("expected '42', got %q", s)
	}
}

func TestToFloat_Invalid(t *testing.T) {
	if f := toFloat("not-a-number"); f != 0 {
		t.Errorf("expected 0 for invalid, got %f", f)
	}
}

func TestParseAction(t *testing.T) {
	tests := []struct {
		input    string
		expected engine.Action
	}{
		{"block", engine.ActionBlock},
		{"BLOCK", engine.ActionBlock},
		{"log", engine.ActionLog},
		{"challenge", engine.ActionChallenge},
		{"pass", engine.ActionPass},
		{"unknown", engine.ActionLog},
	}
	for _, tt := range tests {
		if got := parseAction(tt.input); got != tt.expected {
			t.Errorf("parseAction(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestActionToSeverity(t *testing.T) {
	if s := actionToSeverity(engine.ActionBlock); s != engine.SeverityHigh {
		t.Errorf("expected high, got %v", s)
	}
	if s := actionToSeverity(engine.ActionChallenge); s != engine.SeverityMedium {
		t.Errorf("expected medium, got %v", s)
	}
	if s := actionToSeverity(engine.ActionLog); s != engine.SeverityLow {
		t.Errorf("expected low, got %v", s)
	}
	if s := actionToSeverity(engine.ActionPass); s != engine.SeverityInfo {
		t.Errorf("expected info, got %v", s)
	}
}

func TestRuleEmptyConditions(t *testing.T) {
	// A rule with no conditions should match everything
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Empty conds", Enabled: true, Priority: 1,
			Conditions: []Condition{},
			Action: "log", Score: 5,
		}},
	}, nil)

	ctx := testCtx("GET", "/anything", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for empty conditions, got %s", result.Action)
	}
}

func TestRuleMissingHeader(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Check missing header", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "header:X-Custom", Op: "equals", Value: ""}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for missing header, got %s", result.Action)
	}
}

func TestRuleMissingCookie(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Check missing cookie", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "cookie:session", Op: "equals", Value: ""}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	if result := layer.Process(ctx); result.Action != engine.ActionLog {
		t.Errorf("expected log for missing cookie, got %s", result.Action)
	}
}

func TestRuleScoreAccumulation(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action: "log", Score: 15},
			{ID: "r2", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "method", Op: "equals", Value: "POST"}},
				Action: "log", Score: 25},
		},
	}, nil)

	ctx := testCtx("POST", "/api", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Score != 40 {
		t.Errorf("expected total score 40, got %d", result.Score)
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestRuleFindingFields(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "test-rule", Name: "Test Rule Name", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "equals", Value: "/"}},
			Action: "block", Score: 42,
		}},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.DetectorName != "rule:test-rule" {
		t.Errorf("expected 'rule:test-rule', got %q", f.DetectorName)
	}
	if f.Category != "custom-rule" {
		t.Errorf("expected 'custom-rule', got %q", f.Category)
	}
	if f.Description != "Test Rule Name" {
		t.Errorf("expected 'Test Rule Name', got %q", f.Description)
	}
	if f.Score != 42 {
		t.Errorf("expected score 42, got %d", f.Score)
	}
	if f.Confidence != 1.0 {
		t.Errorf("expected confidence 1.0, got %f", f.Confidence)
	}
}

func TestRuleNilRequest(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Name: "Query check", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "query", Op: "equals", Value: ""}},
			Action: "log", Score: 5,
		}},
	}, nil)

	ctx := &engine.RequestContext{
		Request:     nil,
		Method:      "GET",
		Path:        "/",
		ClientIP:    net.ParseIP("1.2.3.4"),
		Headers:     map[string][]string{},
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log for nil request query, got %s", result.Action)
	}
}

func TestRuleNilAccumulator(t *testing.T) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "r1", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "score", Op: "equals", Value: "0"}},
			Action: "log", Score: 5,
		}},
	}, nil)

	ctx := &engine.RequestContext{
		Method:      "GET",
		Path:        "/",
		ClientIP:    net.ParseIP("1.2.3.4"),
		Headers:     map[string][]string{},
		Cookies:     make(map[string]string),
		Accumulator: nil,
		Metadata:    make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log for nil accumulator score=0, got %s", result.Action)
	}
}

func BenchmarkRuleWithRegex(b *testing.B) {
	layer := NewLayer(Config{
		Enabled: true,
		Rules: []Rule{{
			ID: "regex", Enabled: true, Priority: 1,
			Conditions: []Condition{{Field: "path", Op: "matches", Value: `^/api/v[0-9]+/users/[0-9]+$`}},
			Action: "log", Score: 10,
		}},
	}, nil)

	ctx := testCtx("GET", "/api/v2/users/12345", "1.2.3.4", map[string][]string{
		"User-Agent": {"Mozilla/5.0"},
	})

	b.ResetTimer()
	for range b.N {
		layer.Process(ctx)
	}
}

func BenchmarkRuleMultipleConditions(b *testing.B) {
	rules := make([]Rule, 20)
	for i := range 20 {
		rules[i] = Rule{
			ID: fmt.Sprintf("r%d", i), Enabled: true, Priority: i,
			Conditions: []Condition{
				{Field: "path", Op: "starts_with", Value: "/api"},
				{Field: "method", Op: "equals", Value: "POST"},
			},
			Action: "log", Score: 5,
		}
	}

	layer := NewLayer(Config{Enabled: true, Rules: rules}, nil)
	ctx := testCtx("GET", "/home", "1.2.3.4", nil)

	b.ResetTimer()
	for range b.N {
		layer.Process(ctx)
	}
}
