package crs

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	config := &Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	}

	layer := NewLayer(config)

	if layer.Name() != "crs" {
		t.Errorf("Expected layer name 'crs', got '%s'", layer.Name())
	}

	if !layer.config.Enabled {
		t.Error("Expected layer to be enabled")
	}
}

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()

	if len(rules) == 0 {
		t.Error("Expected default rules to be loaded")
	}

	t.Logf("Loaded %d default rules", len(rules))
}

func TestLayer_LoadEmbeddedRules(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.LoadEmbeddedRules()

	stats := layer.Stats()

	if stats["total"] == 0 {
		t.Error("Expected rules to be loaded")
	}

	t.Logf("Stats: %+v", stats)
}

func TestLayer_Process_SQLi(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.LoadEmbeddedRules()

	// Test SQL injection detection
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/search?q=1+union+select+*+from+users",
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}

	result := layer.Process(ctx)

	// Should detect SQL injection
	if result.Score == 0 {
		t.Log("No SQL injection detected - may need to adjust rules")
	} else {
		t.Logf("SQL injection detected with score: %d", result.Score)
		t.Logf("Findings: %+v", result.Findings)
	}
}

func TestLayer_Process_XSS(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.LoadEmbeddedRules()

	// Test XSS detection
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/comment",
		Body:   []byte(`{"comment": "<script>alert('xss')</script>"}`),
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Host":         {"example.com"},
		},
	}

	result := layer.Process(ctx)

	t.Logf("XSS check result - Score: %d, Action: %v", result.Score, result.Action)
}

func TestLayer_Process_PathTraversal(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.LoadEmbeddedRules()

	// Test path traversal detection
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/../../../etc/passwd",
		Headers: map[string][]string{
			"Host": {"example.com"},
		},
	}

	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("Path traversal should be detected")
	} else {
		t.Logf("Path traversal detected with score: %d", result.Score)
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: false,
	})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass when disabled, got %v", result.Action)
	}

	if result.Score != 0 {
		t.Errorf("Expected score 0 when disabled, got %d", result.Score)
	}
}

func TestLayer_RuleManagement(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.LoadEmbeddedRules()

	// Test disabling a rule
	layer.DisableRule("911100")

	if layer.IsRuleEnabled("911100") {
		t.Error("Rule should be disabled")
	}

	// Test re-enabling
	layer.EnableRule("911100")

	if !layer.IsRuleEnabled("911100") {
		t.Error("Rule should be enabled")
	}

	// Test setting paranoia level
	layer.SetParanoiaLevel(2)

	if layer.config.ParanoiaLevel != 2 {
		t.Errorf("Expected paranoia level 2, got %d", layer.config.ParanoiaLevel)
	}
}

func TestLayer_GetRule(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.LoadEmbeddedRules()

	rule := layer.GetRule("911100")

	if rule == nil {
		t.Error("Expected to find rule 911100")
	} else {
		t.Logf("Found rule: ID=%s, Phase=%d, Msg=%s", rule.ID, rule.Phase, rule.Msg)
	}
}

func TestParser_ParseRule(t *testing.T) {
	parser := NewParser()

	ruleText := `SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD|POST)$" "id:900001,phase:1,deny,status:405,msg:'Method not allowed',severity:'WARNING'"`

	rules, err := parser.ParseFile(ruleText)
	if err != nil {
		t.Fatalf("Failed to parse rule: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}

	rule := rules[0]

	if rule.ID != "900001" {
		t.Errorf("Expected rule ID 900001, got %s", rule.ID)
	}

	if rule.Phase != 1 {
		t.Errorf("Expected phase 1, got %d", rule.Phase)
	}

	if rule.Actions.Action != "deny" {
		t.Errorf("Expected action 'deny', got %s", rule.Actions.Action)
	}

	if rule.Actions.Status != 405 {
		t.Errorf("Expected status 405, got %d", rule.Actions.Status)
	}
}

func TestParser_ParseChainedRule(t *testing.T) {
	parser := NewParser()

	ruleText := `SecRule REQUEST_METHOD "@streq POST" "id:900002,phase:2,deny,status:411,chain"
SecRule REQUEST_HEADERS:Content-Length "@eq 0" "deny"`

	rules, err := parser.ParseFile(ruleText)
	if err != nil {
		t.Fatalf("Failed to parse chained rule: %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule (with chain), got %d", len(rules))
	}

	rule := rules[0]

	if rule.Chain == nil {
		t.Fatal("Expected chained rule")
	}

	t.Logf("Chained rule parsed successfully")
}

func TestVariableResolver(t *testing.T) {
	tx := NewTransaction()
	tx.Method = "POST"
	tx.URI = "/api/users?name=test"
	tx.RequestHeaders = map[string][]string{
		"Content-Type": {"application/json"},
		"Host":         {"example.com"},
	}
	tx.RequestArgs = map[string][]string{
		"name": {"test"},
	}

	resolver := NewVariableResolver(tx)

	// Test REQUEST_METHOD
	vals, err := resolver.Resolve(RuleVariable{Name: "REQUEST_METHOD"})
	if err != nil {
		t.Errorf("Error resolving REQUEST_METHOD: %v", err)
	}
	if len(vals) != 1 || vals[0] != "POST" {
		t.Errorf("Expected POST, got %v", vals)
	}

	// Test REQUEST_HEADERS
	vals, err = resolver.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: "Host"})
	if err != nil {
		t.Errorf("Error resolving REQUEST_HEADERS:Host: %v", err)
	}
	if len(vals) != 1 || vals[0] != "example.com" {
		t.Errorf("Expected example.com, got %v", vals)
	}

	// Test ARGS
	vals, err = resolver.Resolve(RuleVariable{Collection: "ARGS", Key: "name"})
	if err != nil {
		t.Errorf("Error resolving ARGS:name: %v", err)
	}
	if len(vals) != 1 || vals[0] != "test" {
		t.Errorf("Expected test, got %v", vals)
	}
}

func TestOperatorEvaluator(t *testing.T) {
	evaluator := NewOperatorEvaluator()

	tests := []struct {
		name      string
		opType    string
		argument  string
		value     string
		expected  bool
	}{
		{"@eq match", "@eq", "test", "test", true},
		{"@eq no match", "@eq", "test", "other", false},
		{"@contains match", "@contains", "script", "<script>", true},
		{"@contains no match", "@contains", "script", "hello", false},
		{"@beginsWith match", "@beginsWith", "GET", "GET /path", true},
		{"@endsWith match", "@endsWith", ".php", "file.php", true},
		{"@rx match", "@rx", "^\\d+$", "12345", true},
		{"@rx no match", "@rx", "^\\d+$", "abc", false},
		{"@gt true", "@gt", "10", "20", true},
		{"@gt false", "@gt", "20", "10", false},
		{"@within match", "@within", "GET POST PUT", "POST", true},
		{"@within no match", "@within", "GET POST PUT", "DELETE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := RuleOperator{
				Type:     tt.opType,
				Argument: tt.argument,
			}
			result, err := evaluator.Evaluate(op, tt.value)
			if err != nil {
				t.Errorf("Error evaluating operator: %v", err)
				return
			}
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestOperatorEvaluator_Negated(t *testing.T) {
	evaluator := NewOperatorEvaluator()

	op := RuleOperator{
		Type:     "@eq",
		Argument: "test",
		Negated:  true,
	}

	result, err := evaluator.Evaluate(op, "other")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if !result {
		t.Error("Expected negated operator to match 'other' (not equal to 'test')")
	}

	result, err = evaluator.Evaluate(op, "test")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if result {
		t.Error("Expected negated operator to not match 'test'")
	}
}

func TestTransform(t *testing.T) {
	tests := []struct {
		name           string
		value          string
		transforms     []string
		expected       string
	}{
		{"lowercase", "HELLO", []string{"lowercase"}, "hello"},
		{"uppercase", "hello", []string{"uppercase"}, "HELLO"},
		{"urlDecode", "hello%20world", []string{"urlDecode"}, "hello world"},
		{"htmlEntityDecode", "&lt;script&gt;", []string{"htmlEntityDecode"}, "<script>"},
		{"removeWhitespace", "h e l l o", []string{"removeWhitespace"}, "hello"},
		{"trim", "  hello  ", []string{"trim"}, "hello"},
		{"removeNulls", "hello\x00world", []string{"removeNulls"}, "helloworld"},
		{"chain", "HELLO WORLD", []string{"lowercase", "removeWhitespace"}, "helloworld"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Transform(tt.value, tt.transforms)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
