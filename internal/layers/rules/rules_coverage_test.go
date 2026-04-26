package rules

import (
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// =============================================================================
// convertConfigRules: was 0%
// =============================================================================

func TestCoverage_ConvertConfigRules(t *testing.T) {
	cfgRules := []config.CustomRule{
		{
			ID: "cr-1", Name: "Config rule 1", Enabled: true, Priority: 2,
			Conditions: []config.RuleCondition{
				{Field: "path", Op: "starts_with", Value: "/admin"},
			},
			Action: "block", Score: 100,
		},
		{
			ID: "cr-2", Name: "Config rule 2", Enabled: true, Priority: 1,
			Conditions: []config.RuleCondition{
				{Field: "method", Op: "equals", Value: "POST"},
			},
			Action: "log", Score: 20,
		},
	}

	rules := convertConfigRules(cfgRules)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Verify fields are properly mapped
	if rules[0].ID != "cr-1" {
		t.Errorf("expected ID 'cr-1', got %q", rules[0].ID)
	}
	if rules[0].Name != "Config rule 1" {
		t.Errorf("expected Name 'Config rule 1', got %q", rules[0].Name)
	}
	if len(rules[0].Conditions) != 1 {
		t.Errorf("expected 1 condition, got %d", len(rules[0].Conditions))
	}
	if rules[0].Conditions[0].Field != "path" {
		t.Errorf("expected field 'path', got %q", rules[0].Conditions[0].Field)
	}

	// Empty input
	empty := convertConfigRules(nil)
	if len(empty) != 0 {
		t.Errorf("expected 0 rules for nil input, got %d", len(empty))
	}
}

// =============================================================================
// Process with tenant-specific custom rules
// =============================================================================

func TestCoverage_Process_TenantCustomRules(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "global-1", Name: "Global block", Enabled: true, Priority: 10,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/blocked"}},
				Action:     "block", Score: 100,
			},
		},
	}, nil)

	req, _ := http.NewRequest("GET", "http://localhost/tenant-path", nil)
	ctx := &engine.RequestContext{
		Request:     req,
		Method:      "GET",
		Path:        "/tenant-path",
		ClientIP:    net.ParseIP("1.2.3.4"),
		Headers:     map[string][]string{},
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
		TenantWAFConfig: &config.WAFConfig{
			CustomRules: config.CustomRulesConfig{
				Rules: []config.CustomRule{
					{
						ID: "tenant-1", Name: "Tenant log", Enabled: true, Priority: 1,
						Conditions: []config.RuleCondition{
							{Field: "path", Op: "starts_with", Value: "/tenant"},
						},
						Action: "log", Score: 30,
					},
				},
			},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log from tenant rule, got %s", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding from tenant rule, got %d", len(result.Findings))
	}
	if result.Findings[0].DetectorName != "rule:tenant-1" {
		t.Errorf("expected finding from tenant-1, got %q", result.Findings[0].DetectorName)
	}
}

// =============================================================================
// isRegexSafe: comprehensive coverage
// =============================================================================

func TestCoverage_IsRegexSafe(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"simple", `^/api/v[0-9]+$`, false},
		{"deep nesting", "(((((((a)))))))", true}, // 7 levels > 6
		{"at limit", "((((((a))))))", false},    // 6 levels (this is exactly 6)
		{"too long", strings.Repeat("a", 2001), true},
		{"at length limit", strings.Repeat("a", 2000), false},
		{"balanced parens", "(a)(b)(c)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isRegexSafe(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("isRegexSafe(%q) err = %v, wantErr %v", tt.pattern[:min(20, len(tt.pattern))], err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// regexMatch: cache eviction
// =============================================================================

func TestCoverage_RegexMatch_CacheEviction(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true}, nil)

	// Fill cache beyond limit
	for i := range 10001 {
		pattern := "^" + strings.Repeat("a", i%10) + "$"
		layer.regexMatch(pattern, "test")
	}

	// Cache should not exceed 10000 entries
	layer.mu.RLock()
	cacheLen := len(layer.regexCache)
	layer.mu.RUnlock()

	if cacheLen > 10000 {
		t.Errorf("expected cache <= 10000 entries, got %d", cacheLen)
	}
}

// =============================================================================
// toFloat: Sscanf fallback path
// =============================================================================

func TestCoverage_ToFloat_SscanfFallback(t *testing.T) {
	// The first branch (Sscanf) should parse "3.14"
	if f := toFloat("3.14"); f != 3.14 {
		t.Errorf("expected 3.14, got %f", f)
	}

	// Sscanf fails on "0x10" but ParseFloat also fails -> 0
	if f := toFloat("0x10"); f != 0 {
		t.Errorf("expected 0 for hex string, got %f", f)
	}

	// Large number
	if f := toFloat("999999999"); f != 999999999 {
		t.Errorf("expected 999999999, got %f", f)
	}
}

// =============================================================================
// Process: multiple rules with block > challenge > log promotion
// =============================================================================

func TestCoverage_Process_BlockOverridesLog(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "log-rule", Name: "Log", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action:     "log", Score: 10,
			},
			{
				ID: "block-rule", Name: "Block", Enabled: true, Priority: 2,
				Conditions: []Condition{{Field: "path", Op: "starts_with", Value: "/"}},
				Action:     "block", Score: 80,
			},
		},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block to override log, got %s", result.Action)
	}
	if result.Score != 90 {
		t.Errorf("expected total score 90, got %d", result.Score)
	}
}

// =============================================================================
// Process: tenant rules with no tenant config
// =============================================================================

func TestCoverage_Process_NoTenantConfig(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{
				ID: "r1", Name: "Test", Enabled: true, Priority: 1,
				Conditions: []Condition{{Field: "path", Op: "equals", Value: "/"}},
				Action:     "log", Score: 5,
			},
		},
	}, nil)

	ctx := testCtx("GET", "/", "1.2.3.4", nil)
	ctx.TenantWAFConfig = nil
	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected log, got %s", result.Action)
	}
}
