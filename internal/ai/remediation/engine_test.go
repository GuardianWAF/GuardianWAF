package remediation

import (
	"fmt"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected remediation to be disabled by default")
	}

	if cfg.AutoApply {
		t.Error("expected auto_apply to be false by default")
	}

	if cfg.ConfidenceThreshold != 85 {
		t.Errorf("confidence_threshold = %d, want 85", cfg.ConfidenceThreshold)
	}

	if cfg.MaxRulesPerDay != 10 {
		t.Errorf("max_rules_per_day = %d, want 10", cfg.MaxRulesPerDay)
	}

	if cfg.RuleTTL != 24*time.Hour {
		t.Errorf("rule_ttl = %v, want 24h", cfg.RuleTTL)
	}
}

func TestNewEngine(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	if engine == nil {
		t.Fatal("expected engine, got nil")
	}

	if engine.config != cfg {
		t.Error("config mismatch")
	}
}

func TestEngine_ProcessAnalysis_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/api/test",
	}

	rule, err := engine.ProcessAnalysis(analysis)
	if err != nil {
		t.Errorf("ProcessAnalysis failed: %v", err)
	}

	if rule != nil {
		t.Error("should not generate rule when disabled")
	}
}

func TestEngine_ProcessAnalysis_LowConfidence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ConfidenceThreshold = 90

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 80, // Below threshold
		Path:       "/api/test",
	}

	rule, err := engine.ProcessAnalysis(analysis)
	if err != nil {
		t.Errorf("ProcessAnalysis failed: %v", err)
	}

	if rule != nil {
		t.Error("should not generate rule when confidence is below threshold")
	}
}

func TestEngine_ProcessAnalysis_ExcludedPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ExcludedPaths = []string{"/healthz", "/metrics"}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/healthz",
	}

	rule, err := engine.ProcessAnalysis(analysis)
	if err != nil {
		t.Errorf("ProcessAnalysis failed: %v", err)
	}

	if rule != nil {
		t.Error("should not generate rule for excluded path")
	}
}

func TestEngine_ProcessAnalysis_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoApply = false
	cfg.StoragePath = t.TempDir()

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/api/test",
		Method:     "POST",
		Payload:    "' OR '1'='1",
		Severity:   "high",
	}

	rule, err := engine.ProcessAnalysis(analysis)
	if err != nil {
		t.Fatalf("ProcessAnalysis failed: %v", err)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	if rule.AnalysisID != "test-1" {
		t.Errorf("analysis_id = %s, want test-1", rule.AnalysisID)
	}

	if rule.RuleType != "sqli_block" {
		t.Errorf("rule_type = %s, want sqli_block", rule.RuleType)
	}

	if rule.Action != "block" {
		t.Errorf("action = %s, want block", rule.Action)
	}

	if rule.Applied {
		t.Error("rule should not be applied yet")
	}

	if rule.ExpiresAt.Before(time.Now()) {
		t.Error("rule should have future expiry")
	}
}

func TestEngine_ProcessAnalysis_AutoApply(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoApply = true
	cfg.ConfidenceThreshold = 90

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "xss",
		Confidence: 95, // High enough for auto-apply
		Path:       "/api/test",
		Severity:   "critical",
	}

	rule, err := engine.ProcessAnalysis(analysis)
	if err != nil {
		t.Fatalf("ProcessAnalysis failed: %v", err)
	}

	if rule == nil {
		t.Fatal("expected rule, got nil")
	}

	if !rule.Applied {
		t.Error("rule should be auto-applied")
	}

	if !rule.AutoApplied {
		t.Error("rule should be marked as auto-applied")
	}
}

func TestEngine_ProcessAnalysis_DailyLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxRulesPerDay = 2

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Generate 2 rules (at limit)
	for i := 0; i < 2; i++ {
		analysis := &AnalysisResult{
			ID:         fmt.Sprintf("test-%d", i),
			AttackType: "sqli",
			Confidence: 95,
			Path:       fmt.Sprintf("/api/test%d", i),
		}
		engine.ProcessAnalysis(analysis)
	}

	// Third rule should be rejected
	analysis := &AnalysisResult{
		ID:         "test-3",
		AttackType: "xss",
		Confidence: 95,
		Path:       "/api/test3",
	}

	rule, _ := engine.ProcessAnalysis(analysis)
	if rule != nil {
		t.Error("should not generate rule when daily limit reached")
	}
}

func TestEngine_ApplyRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Create a rule
	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/api/test",
	}

	rule, _ := engine.ProcessAnalysis(analysis)
	if rule == nil {
		t.Fatal("expected rule")
	}

	ruleID := rule.ID

	// Apply the rule
	if err := engine.ApplyRule(ruleID); err != nil {
		t.Fatalf("ApplyRule failed: %v", err)
	}

	// Check that rule is now applied
	updatedRule := engine.GetRule(ruleID)
	if !updatedRule.Applied {
		t.Error("rule should be applied")
	}

	// Check stats
	stats := engine.GetStats()
	if stats.TotalApplied != 1 {
		t.Errorf("total_applied = %d, want 1", stats.TotalApplied)
	}
}

func TestEngine_ApplyRule_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	err = engine.ApplyRule("non-existent")
	if err == nil {
		t.Error("expected error for non-existent rule")
	}
}

func TestEngine_RevokeRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Create and apply a rule
	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/api/test",
	}

	rule, _ := engine.ProcessAnalysis(analysis)
	ruleID := rule.ID
	engine.ApplyRule(ruleID)

	// Revoke the rule
	if err := engine.RevokeRule(ruleID); err != nil {
		t.Fatalf("RevokeRule failed: %v", err)
	}

	// Check that rule is no longer applied
	updatedRule := engine.GetRule(ruleID)
	if updatedRule.Applied {
		t.Error("rule should not be applied after revoke")
	}
}

func TestEngine_DeleteRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Create a rule
	analysis := &AnalysisResult{
		ID:         "test-1",
		AttackType: "sqli",
		Confidence: 95,
		Path:       "/api/test",
	}

	rule, _ := engine.ProcessAnalysis(analysis)
	ruleID := rule.ID

	// Delete the rule
	if err := engine.DeleteRule(ruleID); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}

	// Check that rule is gone
	if engine.GetRule(ruleID) != nil {
		t.Error("rule should be deleted")
	}

	// Check active rules
	activeRules := engine.GetActiveRules()
	for _, r := range activeRules {
		if r.ID == ruleID {
			t.Error("deleted rule should not be in active list")
		}
	}
}

func TestEngine_GetAllRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Create multiple rules
	for i := 0; i < 3; i++ {
		analysis := &AnalysisResult{
			ID:         fmt.Sprintf("test-%d", i),
			AttackType: "sqli",
			Confidence: 95,
			Path:       fmt.Sprintf("/api/test%d", i),
		}
		engine.ProcessAnalysis(analysis)
	}

	rules := engine.GetAllRules()
	if len(rules) != 3 {
		t.Errorf("got %d rules, want 3", len(rules))
	}
}

func TestEngine_GetActiveRules(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Create rules
	for i := 0; i < 3; i++ {
		analysis := &AnalysisResult{
			ID:         fmt.Sprintf("test-%d", i),
			AttackType: "sqli",
			Confidence: 95,
			Path:       fmt.Sprintf("/api/test%d", i),
		}
		rule, _ := engine.ProcessAnalysis(analysis)
		if i < 2 {
			engine.ApplyRule(rule.ID) // Apply only first 2
		}
	}

	activeRules := engine.GetActiveRules()
	if len(activeRules) != 2 {
		t.Errorf("got %d active rules, want 2", len(activeRules))
	}
}

func TestEngine_GetStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	// Generate some rules
	for i := 0; i < 5; i++ {
		analysis := &AnalysisResult{
			ID:         fmt.Sprintf("test-%d", i),
			AttackType: "sqli",
			Confidence: 95,
			Path:       fmt.Sprintf("/api/test%d", i),
		}
		rule, _ := engine.ProcessAnalysis(analysis)
		if i < 3 {
			engine.ApplyRule(rule.ID)
		}
	}

	stats := engine.GetStats()

	if stats.TotalGenerated != 5 {
		t.Errorf("total_generated = %d, want 5", stats.TotalGenerated)
	}

	if stats.TotalApplied != 3 {
		t.Errorf("total_applied = %d, want 3", stats.TotalApplied)
	}

	if stats.RulesToday != 5 {
		t.Errorf("rules_today = %d, want 5", stats.RulesToday)
	}
}

func TestDetermineRuleType(t *testing.T) {
	engine, _ := NewEngine(DefaultConfig())

	tests := []struct {
		attackType string
		expected   string
	}{
		{"sqli", "sqli_block"},
		{"sql_injection", "sqli_block"},
		{"xss", "xss_block"},
		{"cross_site_scripting", "xss_block"},
		{"lfi", "lfi_block"},
		{"cmdi", "cmdi_block"},
		{"command_injection", "cmdi_block"},
		{"xxe", "xxe_block"},
		{"ssrf", "ssrf_block"},
		{"brute_force", "rate_limit"},
		{"bot", "bot_block"},
		{"unknown", "custom_block"},
	}

	for _, tt := range tests {
		analysis := &AnalysisResult{AttackType: tt.attackType}
		result := engine.determineRuleType(analysis)
		if result != tt.expected {
			t.Errorf("determineRuleType(%s) = %s, want %s", tt.attackType, result, tt.expected)
		}
	}
}

func TestDetermineAction(t *testing.T) {
	engine, _ := NewEngine(DefaultConfig())

	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "block"},
		{"high", "block"},
		{"medium", "challenge"},
		{"low", "log"},
		{"unknown", "log"},
	}

	for _, tt := range tests {
		analysis := &AnalysisResult{Severity: tt.severity}
		result := engine.determineAction(analysis)
		if result != tt.expected {
			t.Errorf("determineAction(%s) = %s, want %s", tt.severity, result, tt.expected)
		}
	}
}

func TestSanitizePattern(t *testing.T) {
	engine, _ := NewEngine(DefaultConfig())

	tests := []struct {
		input    string
		expected string
	}{
		{"test", "test"},
		{"test.value", `test\.value`},
		{"test*", `test\*`},
		{"test+", `test\+`},
		{"test?", `test\?`},
		{"test[abc]", `test\[abc\]`},
		{"test(pattern)", `test\(pattern\)`},
	}

	for _, tt := range tests {
		result := engine.sanitizePattern(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizePattern(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestIsExcludedPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ExcludedPaths = []string{"/healthz", "/metrics", "/api/status"}

	engine, _ := NewEngine(cfg)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/healthz", true},
		{"/healthz/ready", true},
		{"/metrics", true},
		{"/metrics/prometheus", true},
		{"/api/status", true},
		{"/api/users", false},
		{"/", false},
	}

	for _, tt := range tests {
		result := engine.isExcludedPath(tt.path)
		if result != tt.expected {
			t.Errorf("isExcludedPath(%s) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestIsSameDay(t *testing.T) {
	tests := []struct {
		t1       time.Time
		t2       time.Time
		expected bool
	}{
		{time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), time.Date(2024, 1, 15, 15, 0, 0, 0, time.UTC), true},
		{time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), time.Date(2024, 1, 16, 10, 0, 0, 0, time.UTC), false},
		{time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC), time.Date(2024, 2, 15, 10, 0, 0, 0, time.UTC), false},
	}

	for _, tt := range tests {
		result := isSameDay(tt.t1, tt.t2)
		if result != tt.expected {
			t.Errorf("isSameDay(%v, %v) = %v, want %v", tt.t1, tt.t2, result, tt.expected)
		}
	}
}

func TestGenerateRuleID(t *testing.T) {
	id1 := generateRuleID()
	id2 := generateRuleID()

	if len(id1) != 16 {
		t.Errorf("ID length = %d, want 16", len(id1))
	}

	if id1 == id2 {
		t.Error("IDs should be unique")
	}
}

func TestLayer_NewLayer_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.engine != nil {
		t.Error("engine should be nil when disabled")
	}

	if layer.Name() != "remediation" {
		t.Errorf("name = %s, want remediation", layer.Name())
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	ctx := &RequestContext{Path: "/api/test"}
	result := layer.Process(ctx)

	if result != nil {
		t.Error("should return nil when disabled")
	}
}

func TestLayer_matchesRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	engine, _ := NewEngine(cfg)
	layer := &Layer{
		engine: engine,
		config: &Config{Enabled: true},
	}

	rule := &GeneratedRule{
		Pattern: "/api/sensitive",
	}

	tests := []struct {
		path     string
		body     string
		expected bool
	}{
		{"/api/sensitive", "", true},
		{"/api/sensitive/data", "", true},
		{"/api/other", "", false},
		{"/api/other", "/api/sensitive", true}, // body match
		{"/", "", false},
	}

	for _, tt := range tests {
		ctx := &RequestContext{Path: tt.path, Body: tt.body}
		result := layer.matchesRule(ctx, rule)
		if result != tt.expected {
			t.Errorf("matchesRule(path=%s, body=%s) = %v, want %v", tt.path, tt.body, result, tt.expected)
		}
	}
}
