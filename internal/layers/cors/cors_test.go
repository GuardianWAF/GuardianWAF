package cors

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com", "https://*.test.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowCredentials: true,
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.Name() != "cors" {
		t.Errorf("Expected name 'cors', got '%s'", layer.Name())
	}

	// Check compiled patterns
	if len(layer.exactOrigins) != 1 {
		t.Errorf("Expected 1 exact origin, got %d", len(layer.exactOrigins))
	}

	if len(layer.originRegex) != 1 {
		t.Errorf("Expected 1 regex pattern, got %d", len(layer.originRegex))
	}
}

func TestIsOriginAllowed(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AllowOrigins: []string{
			"https://example.com",
			"https://*.test.com",
			"http://app-*.internal.local",
		},
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	tests := []struct {
		origin   string
		expected bool
	}{
		{"https://example.com", true},
		{"https://Example.com", false}, // case sensitive
		{"https://sub.test.com", true},
		{"https://a.b.test.com", true},
		{"https://test.com", false}, // wildcard needs subdomain
		{"http://app-prod.internal.local", true},
		{"http://app-staging.internal.local", true},
		{"http://evil.com", false},
		{"", false},
	}

	for _, tt := range tests {
		result := layer.isOriginAllowed(tt.origin)
		if result != tt.expected {
			t.Errorf("isOriginAllowed(%q) = %v, want %v", tt.origin, result, tt.expected)
		}
	}
}

func TestProcess_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://evil.com"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass when disabled, got %v", result.Action)
	}
}

func TestProcess_NoOrigin(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass without Origin header, got %v", result.Action)
	}
}

func TestProcess_AllowedOrigin(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com"},
		AllowCredentials: true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://example.com"}},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for allowed origin, got %v", result.Action)
	}

	// Check CORS headers were set
	headers, ok := ctx.Metadata["cors_headers"].(map[string]string)
	if !ok {
		t.Fatal("Expected cors_headers in metadata")
	}
	if headers["Access-Control-Allow-Origin"] != "https://example.com" {
		t.Errorf("Unexpected Allow-Origin header: %v", headers["Access-Control-Allow-Origin"])
	}
}

func TestProcess_BlockedOrigin_StrictMode(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		StrictMode:    true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://evil.com"}},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for disallowed origin in strict mode, got %v", result.Action)
	}
	if result.Score != 30 {
		t.Errorf("Expected score 30, got %d", result.Score)
	}
}

func TestProcess_BlockedOrigin_NonStrict(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		StrictMode:   false,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Headers: map[string][]string{"Origin": {"https://evil.com"}},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for disallowed origin in non-strict mode, got %v", result.Action)
	}
}

func TestProcess_Preflight_Allowed(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AllowOrigins:  []string{"https://example.com"},
		AllowMethods:  []string{"GET", "POST", "PUT"},
		AllowHeaders:  []string{"Content-Type", "Authorization"},
		MaxAgeSeconds: 3600,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                         {"https://example.com"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"Content-Type, Authorization"},
		},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for valid preflight, got %v", result.Action)
	}

	headers, ok := ctx.Metadata["cors_preflight_headers"].(map[string]string)
	if !ok {
		t.Fatal("Expected cors_preflight_headers in metadata")
	}
	if headers["Access-Control-Allow-Methods"] != "GET, POST, PUT" {
		t.Errorf("Unexpected Allow-Methods: %v", headers["Access-Control-Allow-Methods"])
	}
}

func TestProcess_Preflight_BlockedMethod(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
		AllowMethods: []string{"GET", "POST"},
		StrictMode:   true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "OPTIONS",
		Headers: map[string][]string{
			"Origin":                        {"https://example.com"},
			"Access-Control-Request-Method": {"DELETE"},
		},
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for disallowed method in preflight, got %v", result.Action)
	}
}

func TestCompileWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		match   bool
	}{
		{"https://*.example.com", "https://api.example.com", true},
		{"https://*.example.com", "https://www.example.com", true},
		{"https://*.example.com", "https://example.com", false},
		{"https://*.example.com", "https://evil.com", false},
		{"https://app-*.test.com", "https://app-prod.test.com", true},
		{"https://app-*.test.com", "https://app-staging.test.com", true},
		{"*://*.example.com", "https://api.example.com", true},
		{"*://*.example.com", "http://api.example.com", true},
	}

	for _, tt := range tests {
		re := compileWildcard(tt.pattern)
		if re == nil {
			t.Errorf("Failed to compile pattern: %s", tt.pattern)
			continue
		}
		if re.MatchString(tt.input) != tt.match {
			t.Errorf("Pattern %q matching %q: got %v, want %v", tt.pattern, tt.input, !tt.match, tt.match)
		}
	}
}

func TestUpdateConfig(t *testing.T) {
	cfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://example.com"},
	}
	layer, _ := NewLayer(&cfg)

	// Update with new origins
	newCfg := Config{
		Enabled:      true,
		AllowOrigins: []string{"https://new.com", "https://*.new.com"},
	}

	err := layer.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	if !layer.isOriginAllowed("https://new.com") {
		t.Error("Expected new.com to be allowed after update")
	}
	if layer.isOriginAllowed("https://example.com") {
		t.Error("Expected example.com to NOT be allowed after update")
	}
	if !layer.isOriginAllowed("https://sub.new.com") {
		t.Error("Expected sub.new.com to be allowed (wildcard)")
	}
}

// Benchmark
func BenchmarkProcess(b *testing.B) {
	cfg := Config{
		Enabled:          true,
		AllowOrigins:     []string{"https://example.com", "https://*.test.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowCredentials: true,
	}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Headers: map[string][]string{
			"Origin": {"https://api.test.com"},
		},
		Metadata: make(map[string]any),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Metadata = make(map[string]any)
		layer.Process(ctx)
	}
}
