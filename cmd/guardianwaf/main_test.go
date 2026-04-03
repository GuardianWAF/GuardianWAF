package main

import (
	"context"
	"encoding/json"
	"reflect"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apisecurity"
	"github.com/guardianwaf/guardianwaf/internal/layers/ato"
	"github.com/guardianwaf/guardianwaf/internal/layers/cors"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/threatintel"
)

// --- isValidIPOrCIDR ---

func TestIsValidIPOrCIDR_ValidIP(t *testing.T) {
	if !isValidIPOrCIDR("10.0.0.1") {
		t.Error("expected valid IPv4")
	}
}

func TestIsValidIPOrCIDR_ValidIPv6(t *testing.T) {
	if !isValidIPOrCIDR("::1") {
		t.Error("expected valid IPv6")
	}
}

func TestIsValidIPOrCIDR_ValidCIDR(t *testing.T) {
	if !isValidIPOrCIDR("10.0.0.0/8") {
		t.Error("expected valid CIDR")
	}
}

func TestIsValidIPOrCIDR_InvalidIP(t *testing.T) {
	if isValidIPOrCIDR("not-an-ip") {
		t.Error("expected invalid")
	}
}

func TestIsValidIPOrCIDR_InvalidCIDR(t *testing.T) {
	if isValidIPOrCIDR("10.0.0.0/99") {
		t.Error("expected invalid CIDR")
	}
}

// --- upstreamSummary ---

func TestUpstreamSummary_Empty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = nil
	result := upstreamSummary(cfg)
	if result != "(no upstream)" {
		t.Errorf("expected '(no upstream)', got %q", result)
	}
}

func TestUpstreamSummary_MultipleTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "backend",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:3000"},
				{URL: "http://localhost:3001"},
			},
		},
	}
	result := upstreamSummary(cfg)
	if !strings.Contains(result, "http://localhost:3000") {
		t.Error("expected first target in summary")
	}
	if !strings.Contains(result, "http://localhost:3001") {
		t.Error("expected second target in summary")
	}
}

// --- loadConfig ---

func TestLoadConfig_DefaultFallback(t *testing.T) {
	// When default path doesn't exist, should return defaults silently
	cfg := loadConfig("guardianwaf.yaml")
	if cfg == nil {
		t.Fatal("expected non-nil config from default fallback")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("expected default mode 'enforce', got %q", cfg.Mode)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("mode: monitor\nlisten: \":9090\"\n"), 0644)

	cfg := loadConfig(path)
	if cfg.Mode != "monitor" {
		t.Errorf("expected mode 'monitor', got %q", cfg.Mode)
	}
}

// --- addLayers ---

func TestAddLayers_AllEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"192.168.1.100"}
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []config.RateLimitRule{
		{ID: "test", Scope: "ip", Limit: 10, Window: 60_000_000_000, Burst: 5, Action: "block"},
	}
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.BotDetection.Enabled = true

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	// Verify engine works by processing a request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	event := eng.Check(req)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
}

func TestAddLayers_IPACLInvalidCIDR(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"invalid-cidr-xyz"} // Invalid CIDR

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	// This should log a warning but not crash
	addLayers(eng, cfg)
}

func TestAddLayers_ResponseWithHSTS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Response.SecurityHeaders.Enabled = true
	cfg.WAF.Response.SecurityHeaders.HSTS.Enabled = true
	cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge = 31536000
	cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains = true
	cfg.WAF.Response.SecurityHeaders.XFrameOptions = "DENY"
	cfg.WAF.Response.SecurityHeaders.ReferrerPolicy = "no-referrer"
	cfg.WAF.Response.SecurityHeaders.PermissionsPolicy = "camera=()"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- buildReverseProxy ---

func TestBuildReverseProxy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "backend",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:9999"},
			},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/api", Upstream: "backend", StripPrefix: true},
	}

	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBuildReverseProxy_InvalidUpstream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "bad",
			Targets: []config.TargetConfig{{URL: "://invalid"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "bad"},
	}
	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler even with invalid upstream")
	}
}

func TestBuildReverseProxy_MissingUpstream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "nonexistent"},
	}
	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

// --- printUsage ---

func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

// --- cmdVersion ---

func TestCmdVersion(t *testing.T) {
	// Just verify it doesn't panic
	cmdVersion()
}

// --- headerSlice ---

func TestHeaderSlice_StringAndSet(t *testing.T) {
	var hs headerSlice
	hs.Set("Content-Type: application/json")
	hs.Set("X-Custom: value")
	s := hs.String()
	if !strings.Contains(s, "Content-Type") {
		t.Error("expected Content-Type in string")
	}
	if !strings.Contains(s, "X-Custom") {
		t.Error("expected X-Custom in string")
	}
}

// --- mcpEngineAdapter ---

func newTestAdapter(t *testing.T) *mcpEngineAdapter {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Detectors = map[string]config.DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.0},
		"xss":  {Enabled: true, Multiplier: 1.0},
	}
	cfg.WAF.RateLimit.Enabled = true
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	// Add IP ACL layer for testing
	ipaclLayer, err := ipacl.NewLayer(ipacl.Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewLayer ipacl error: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: 100})
	// Add rate limit layer for testing
	rlLayer := ratelimit.NewLayer(ratelimit.Config{Enabled: true})
	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: 200})
	// Add detection layer for testing
	detLayer := detection.NewLayer(detection.Config{
		Enabled: true,
		Detectors: map[string]detection.DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
			"xss":  {Enabled: true, Multiplier: 1.0},
		},
	})
	eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: 400})
	t.Cleanup(func() { eng.Close() })
	return &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
}

func TestMCPAdapter_GetStats(t *testing.T) {
	a := newTestAdapter(t)
	stats := a.GetStats()
	m, ok := stats.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := m["total_requests"]; !ok {
		t.Error("expected total_requests in stats")
	}
}

func TestMCPAdapter_GetConfig(t *testing.T) {
	a := newTestAdapter(t)
	cfg := a.GetConfig()
	m, ok := cfg.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := m["mode"]; !ok {
		t.Error("expected mode in config")
	}
}

func TestMCPAdapter_GetMode(t *testing.T) {
	a := newTestAdapter(t)
	mode := a.GetMode()
	if mode != "enforce" {
		t.Errorf("expected 'enforce', got %q", mode)
	}
}

func TestMCPAdapter_SetMode(t *testing.T) {
	a := newTestAdapter(t)
	err := a.SetMode("monitor")
	if err != nil {
		t.Fatalf("SetMode error: %v", err)
	}
	if a.GetMode() != "monitor" {
		t.Error("expected mode to be 'monitor' after SetMode")
	}
}

func TestMCPAdapter_WhitelistBlacklist(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.AddWhitelist("10.0.0.1"); err != nil {
		t.Errorf("AddWhitelist error: %v", err)
	}
	if err := a.AddWhitelist("not-valid"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := a.RemoveWhitelist("10.0.0.1"); err != nil {
		t.Errorf("RemoveWhitelist error: %v", err)
	}

	if err := a.AddBlacklist("192.168.1.0/24"); err != nil {
		t.Errorf("AddBlacklist error: %v", err)
	}
	if err := a.AddBlacklist("invalid"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := a.RemoveBlacklist("192.168.1.0/24"); err != nil {
		t.Errorf("RemoveBlacklist error: %v", err)
	}
}

func TestMCPAdapter_RateLimit(t *testing.T) {
	a := newTestAdapter(t)
	if err := a.AddRateLimit(map[string]any{"id": "r1", "scope": "ip", "limit": 10, "window": "1m", "action": "block"}); err != nil {
		t.Errorf("AddRateLimit error: %v", err)
	}
	if err := a.RemoveRateLimit("r1"); err != nil {
		t.Errorf("RemoveRateLimit error: %v", err)
	}
}

func TestMCPAdapter_Exclusion(t *testing.T) {
	a := newTestAdapter(t)
	if err := a.AddExclusion("/api", []string{"sqli"}, "test"); err != nil {
		t.Errorf("AddExclusion error: %v", err)
	}
	if err := a.RemoveExclusion("/api"); err != nil {
		t.Errorf("RemoveExclusion error: %v", err)
	}
}

func TestMCPAdapter_GetEvents(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.GetEvents(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("GetEvents error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if m["total"] != 0 {
		t.Error("expected total 0")
	}
}

func TestMCPAdapter_GetTopIPs(t *testing.T) {
	a := newTestAdapter(t)
	result := a.GetTopIPs(10)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPAdapter_GetDetectors(t *testing.T) {
	a := newTestAdapter(t)
	result := a.GetDetectors()
	detectors, ok := result.([]map[string]any)
	if !ok {
		t.Fatal("expected slice result")
	}
	if len(detectors) == 0 {
		t.Error("expected at least one detector")
	}
}

func TestMCPAdapter_TestRequest(t *testing.T) {
	a := newTestAdapter(t)

	// Clean request
	result, err := a.TestRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if m["action"] == nil {
		t.Error("expected action in result")
	}
}

func TestMCPAdapter_TestRequest_WithHeaders(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.TestRequest("GET", "http://example.com/test", map[string]string{
		"User-Agent": "TestBot/1.0",
	})
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPAdapter_TestRequest_Attack(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.TestRequest("GET", "/search?q='+OR+1=1--", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	m := result.(map[string]any)
	findings, ok := m["findings"].([]map[string]any)
	if ok && len(findings) > 0 {
		// Attack was detected — verify finding has expected fields
		if findings[0]["detector"] == nil {
			t.Error("expected detector field in finding")
		}
	}
}

// --- cmdCheck (via dry-run) ---

func TestCmdCheck_MissingURL(t *testing.T) {
	// cmdCheck calls os.Exit on missing URL, so we can't test it directly.
	// But we can verify the config loading and engine creation path.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("mode: monitor\n"), 0644)

	cfg := loadConfig(path)
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	addLayers(eng, cfg)

	// Simulate the check logic
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://localhost/search?q=test", nil)
	req.RemoteAddr = "127.0.0.1:0"
	event := eng.Check(req)
	if event.Action.String() == "" {
		t.Error("expected non-empty action")
	}
}

// --- startDashboard ---

func TestStartDashboard(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0" // random port
	cfg.Dashboard.APIKey = "test-key"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	srv, _, _ := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	defer srv.Close()
}

// --- cmdValidate path ---

func TestCmdValidate_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	config.LoadEnv(cfg)
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
}

// --- buildReverseProxy StripPrefix ---

func TestBuildReverseProxy_StripPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: backendURL.String()}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/api", Upstream: "backend", StripPrefix: true},
	}

	handler, _ := buildReverseProxy(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users", nil)
	handler.ServeHTTP(rr, req)
	// The reverse proxy should have forwarded the request
		_ = rr.Code // proxy attempted forwarding
}

// --- Subprocess CLI tests for os.Exit-calling commands ---

func buildBinary(t *testing.T) string {
	t.Helper()
	binName := "guardianwaf_test_bin"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(".", "")
	// Build from the cmd/guardianwaf directory
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binPath
}

func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "guardianwaf.yaml")
	content := `mode: enforce
listen: ":18088"
waf:
  detection:
    enabled: true
  sanitizer:
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)
	return path
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "guardianwaf") {
		t.Errorf("expected 'guardianwaf' in version output, got: %s", out)
	}
}

func TestCLI_Help(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "help").CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "COMMANDS") {
		t.Errorf("expected 'COMMANDS' in help output, got: %s", out)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "nonexistent")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown command")
	}
	if !strings.Contains(string(out), "Unknown command") {
		t.Errorf("expected 'Unknown command' in output, got: %s", out)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for no args")
	}
	if !strings.Contains(string(out), "USAGE") {
		t.Errorf("expected 'USAGE' in output, got: %s", out)
	}
}

func TestCLI_Validate_Valid(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, err := exec.Command(bin, "validate", "-config", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "valid") {
		t.Errorf("expected 'valid' in output, got: %s", out)
	}
}

func TestCLI_Validate_InvalidFile(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "validate", "-config", "/nonexistent/file.yaml")
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid config file")
	}
}

func TestCLI_Check_Clean(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, err := exec.Command(bin, "check", "-config", cfgPath, "-url", "/hello",
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0").CombinedOutput()
	if err != nil {
		// exit code 2 = blocked, which is also a valid test path
		if !strings.Contains(string(out), "Action:") {
			t.Fatalf("check failed unexpectedly: %v\n%s", err, out)
		}
	}
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_Attack(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	cmd := exec.Command(bin, "check", "-config", cfgPath, "-url", "/search?q='+OR+1=1--", "-v")
	out, err := cmd.CombinedOutput()
	// Exit code 2 = blocked
	if err == nil {
		// Might pass if score is below threshold
		if !strings.Contains(string(out), "PASSED") && !strings.Contains(string(out), "BLOCKED") {
			t.Errorf("expected PASSED or BLOCKED, got: %s", out)
		}
	} else {
		if !strings.Contains(string(out), "BLOCKED") {
			t.Errorf("expected 'BLOCKED' for attack, got: %s", out)
		}
	}
}

func TestCLI_Check_WithBody(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, _ := exec.Command(bin, "check", "-config", cfgPath, "-url", "/api/data", "-method", "POST",
		"-body", `{"user":"test"}`,
		"-H", "User-Agent: Mozilla/5.0 Chrome/120.0",
		"-H", "Content-Type: application/json").CombinedOutput()
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_WithHeaders(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, _ := exec.Command(bin, "check", "-config", cfgPath, "-url", "/test",
		"-H", "User-Agent: Mozilla/5.0 Chrome/120.0",
		"-H", "X-Custom: value",
		"-H", "Accept: text/html").CombinedOutput()
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_MissingURL(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	cmd := exec.Command(bin, "check", "-config", cfgPath)
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for missing --url")
	}
}

func TestCLI_Serve_Startup(t *testing.T) {
	bin := buildBinary(t)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardianwaf.yaml")
	cfgContent := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
`, port)
	os.WriteFile(cfgPath, []byte(cfgContent), 0644)

	cmd := exec.Command(bin, "serve", "-config", cfgPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start serve: %v", err)
	}

	// Wait for server to start
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		cmd.Process.Kill()
		t.Fatal("server did not start within timeout")
	}

	// Send a request
	req, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/health", addr), nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}

	// Kill the server
	cmd.Process.Kill()
	cmd.Wait()
}

func TestCLI_Sidecar_Startup(t *testing.T) {
	bin := buildBinary(t)

	// Start a backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "backend ok")
	}))
	defer backend.Close()

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command(bin, "sidecar", "-upstream", backend.URL, "-listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sidecar: %v", err)
	}

	// Wait for sidecar to start
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		cmd.Process.Kill()
		t.Fatal("sidecar did not start within timeout")
	}

	// Hit the healthz endpoint
	r, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/health", addr), nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthz, got %d", resp.StatusCode)
	}

	// Hit a proxied endpoint
	reqProxy, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/test", addr), nil)
	resp2, err := http.DefaultClient.Do(reqProxy)
	if err == nil {
		resp2.Body.Close()
	}

	// Kill the sidecar
	cmd.Process.Kill()
	cmd.Wait()
}

// --- startDashboard endpoints ---

func TestStartDashboard_Endpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.Dashboard.APIKey = ""

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	// Use a listener to get the actual port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg.Dashboard.Listen = addr
	srv, _, _ := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	defer srv.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Test /healthz
	r, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/health", addr), nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthz, got %d", resp.StatusCode)
	}

	// Test /api/stats
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/stats", addr), nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from stats, got %d", resp2.StatusCode)
	}
}

func TestStartDashboard_WithAPIKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.APIKey = "secret-key"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg.Dashboard.Listen = addr
	srv, _, _ := startDashboard(cfg, eng)
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	// Without key — should get 401
	r, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/stats", addr), nil)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without API key, got %d", resp.StatusCode)
	}

	// With correct key
	req, _ := http.NewRequestWithContext(context.Background(), "GET", fmt.Sprintf("http://%s/api/v1/stats", addr), nil)
	req.Header.Set("X-API-Key", "secret-key")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stats request with key failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct API key, got %d", resp2.StatusCode)
	}
}

// --- loadConfig edge cases ---

func TestLoadConfig_NonDefaultPathNotFound(t *testing.T) {
	// Non-default path that doesn't exist — should call os.Exit
	// We can't test os.Exit directly, but we can test the file-exists path
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.yaml")
	os.WriteFile(path, []byte("mode: monitor\n"), 0644)
	cfg := loadConfig(path)
	if cfg.Mode != "monitor" {
		t.Errorf("expected 'monitor', got %q", cfg.Mode)
	}
}

// --- TestRequest edge case ---

func TestMCPAdapter_TestRequest_InvalidMethod(t *testing.T) {
	a := newTestAdapter(t)
	// Invalid HTTP method with space causes NewRequest to fail
	_, err := a.TestRequest("BAD METHOD", "/test", nil)
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
}

// --- collectACMEDomains tests ---

func TestCollectACMEDomains_ExplicitDomains(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			ACME: config.ACMEConfig{
				Domains: []string{"example.com", "www.example.com"},
			},
		},
	}
	result := collectACMEDomains(cfg)
	if len(result) != 1 {
		t.Fatalf("expected 1 domain group, got %d", len(result))
	}
	if result[0][0] != "example.com" || result[0][1] != "www.example.com" {
		t.Errorf("expected example.com domains, got %v", result[0])
	}
}

func TestCollectACMEDomains_VirtualHostWithManualCert(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			ACME: config.ACMEConfig{
				Domains: []string{"explicit.com"},
			},
		},
		VirtualHosts: []config.VirtualHostConfig{
			{
				Domains: []string{"vh1.com", "www.vh1.com"},
				TLS: config.VHostTLSConfig{
					CertFile: "/path/to/cert.pem", // Has manual cert - NOT included
					KeyFile:  "/path/to/key.pem",
				},
			},
		},
	}
	result := collectACMEDomains(cfg)
	// Only the explicit ACME domain should be included, not the vhost with manual cert
	if len(result) != 1 {
		t.Fatalf("expected 1 domain group (vhost has manual cert), got %d", len(result))
	}
}

func TestCollectACMEDomains_VirtualHostWildcard(t *testing.T) {
	cfg := &config.Config{
		VirtualHosts: []config.VirtualHostConfig{
			{
				Domains: []string{"*.wildcard.com", "regular.com"},
				TLS:     config.VHostTLSConfig{
					// No manual cert - will be included
				},
			},
		},
	}
	result := collectACMEDomains(cfg)
	// Wildcard should be filtered out, only regular.com remains
	if len(result) != 1 {
		t.Fatalf("expected 1 domain group, got %d", len(result))
	}
	if len(result[0]) != 1 {
		t.Errorf("expected 1 domain (wildcard filtered), got %d", len(result[0]))
	}
	if result[0][0] != "regular.com" {
		t.Errorf("expected regular.com, got %v", result[0])
	}
}

func TestCollectACMEDomains_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	result := collectACMEDomains(cfg)
	if len(result) != 0 {
		t.Errorf("expected no domains for empty config, got %d", len(result))
	}
}

// --- mapToRule tests ---

func TestMapToRule_Complete(t *testing.T) {
	raw := map[string]any{
		"id":       "rule-1",
		"name":     "Block SQLi",
		"enabled":  true,
		"priority": float64(100), // JSON numbers become float64
		"action":   "block",
		"score":    float64(50), // JSON numbers become float64
		"conditions": []any{
			map[string]any{"field": "path", "op": "contains", "value": "sql"},
			map[string]any{"field": "method", "op": "equals", "value": "POST"},
		},
	}
	r := mapToRule(raw)
	if r.ID != "rule-1" {
		t.Errorf("expected ID rule-1, got %s", r.ID)
	}
	if r.Name != "Block SQLi" {
		t.Errorf("expected Name 'Block SQLi', got %s", r.Name)
	}
	if !r.Enabled {
		t.Error("expected Enabled true")
	}
	if r.Priority != 100 {
		t.Errorf("expected Priority 100, got %d", r.Priority)
	}
	if r.Action != "block" {
		t.Errorf("expected Action block, got %s", r.Action)
	}
	if r.Score != 50 {
		t.Errorf("expected Score 50, got %d", r.Score)
	}
	if len(r.Conditions) != 2 {
		t.Errorf("expected 2 conditions, got %d", len(r.Conditions))
	}
}

func TestMapToRule_PriorityFloat(t *testing.T) {
	raw := map[string]any{
		"id":       "rule-2",
		"priority": 50.5, // float, should convert to int
	}
	r := mapToRule(raw)
	if r.Priority != 50 {
		t.Errorf("expected Priority 50 (int), got %d", r.Priority)
	}
}

func TestMapToRule_ScoreFloat(t *testing.T) {
	raw := map[string]any{
		"id":    "rule-3",
		"score": 25.5, // float, should convert to int
	}
	r := mapToRule(raw)
	if r.Score != 25 {
		t.Errorf("expected Score 25 (int), got %d", r.Score)
	}
}

func TestMapToRule_InvalidCondition(t *testing.T) {
	raw := map[string]any{
		"id": "rule-4",
		"conditions": []any{
			"not a map", // invalid condition
			map[string]any{"field": "path", "op": "contains", "value": "test"},
		},
	}
	r := mapToRule(raw)
	if len(r.Conditions) != 1 {
		t.Errorf("expected 1 valid condition, got %d", len(r.Conditions))
	}
	if r.Conditions[0].Field != "path" {
		t.Errorf("expected field 'path', got %s", r.Conditions[0].Field)
	}
}

func TestMapToRule_EmptyConditions(t *testing.T) {
	raw := map[string]any{
		"id":         "rule-5",
		"conditions": []any{},
	}
	r := mapToRule(raw)
	if len(r.Conditions) != 0 {
		t.Errorf("expected 0 conditions, got %d", len(r.Conditions))
	}
}

func TestMapToRule_MissingFields(t *testing.T) {
	raw := map[string]any{} // empty map
	r := mapToRule(raw)
	if r.ID != "" {
		t.Errorf("expected empty ID, got %s", r.ID)
	}
	if r.Name != "" {
		t.Errorf("expected empty Name, got %s", r.Name)
	}
	if r.Enabled {
		t.Error("expected Enabled false")
	}
}

// --- loadGeoIP tests ---

func TestLoadGeoIP_Disabled(t *testing.T) {
	cfg := &config.Config{
		WAF: config.WAFConfig{
			GeoIP: config.GeoIPConfig{
				Enabled:      false,
				DBPath:       "",
				AutoDownload: false,
			},
		},
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1000), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	db, _ := loadGeoIP(cfg, eng)
	if db != nil {
		t.Error("expected nil when GeoIP disabled")
	}
}

func TestLoadGeoIP_ValidDBPath(t *testing.T) {
	// Create a valid GeoIP CSV file
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "geoip.csv")
	csvContent := "1.0.0.0,1.0.0.255,US\n2.0.0.0,2.0.0.255,DE\n"
	os.WriteFile(csvPath, []byte(csvContent), 0644)

	cfg := &config.Config{
		WAF: config.WAFConfig{
			GeoIP: config.GeoIPConfig{
				Enabled: true,
				DBPath:  csvPath,
			},
		},
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1000), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	db, _ := loadGeoIP(cfg, eng)
	if db == nil {
		t.Error("expected non-nil DB when valid path provided")
	} else if db.Count() != 2 {
		t.Errorf("expected 2 ranges, got %d", db.Count())
	}
}

func TestLoadGeoIP_InvalidDBPath(t *testing.T) {
	cfg := &config.Config{
		WAF: config.WAFConfig{
			GeoIP: config.GeoIPConfig{
				Enabled:      true,
				DBPath:       "/nonexistent/path/geoip.csv",
				AutoDownload: false,
			},
		},
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1000), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	db, _ := loadGeoIP(cfg, eng)
	// Should return nil when file doesn't exist and auto-download disabled
	if db != nil {
		t.Error("expected nil when file doesn't exist")
	}
}

func TestLoadGeoIP_AutoDownloadEnabled(t *testing.T) {
	// Test the auto-download path with a non-existent path
	// This will fail but exercises the AutoDownload code path
	cfg := &config.Config{
		WAF: config.WAFConfig{
			GeoIP: config.GeoIPConfig{
				Enabled:      true,
				DBPath:       "", // Empty path, should use default
				AutoDownload: true,
			},
		},
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1000), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	// This will fail because /var/lib/guardianwaf/geoip.csv doesn't exist
	// and network download will fail, but it exercises the code path
	db, _ := loadGeoIP(cfg, eng)
	// On most systems this will return nil because download will fail
	_ = db // Just exercising the path
}

func TestLoadGeoIP_AutoDownloadWithCustomPath(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom-geoip.csv")

	cfg := &config.Config{
		WAF: config.WAFConfig{
			GeoIP: config.GeoIPConfig{
				Enabled:      true,
				DBPath:       customPath,
				AutoDownload: true,
			},
		},
	}

	eng, err := engine.NewEngine(cfg, events.NewMemoryStore(1000), events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	// This will fail because customPath doesn't exist and download will fail
	// but exercises the code path where DBPath is set but file doesn't exist
	db, _ := loadGeoIP(cfg, eng)
	_ = db // Just exercising the path
}

// --- mapToRule with condition values ---

func TestMapToRule_ConditionValues(t *testing.T) {
	raw := map[string]any{
		"id": "rule-cond",
		"conditions": []any{
			map[string]any{
				"field": "path",
				"op":    "in",
				"value": []string{"/admin", "/login", "/api"},
			},
			map[string]any{
				"field": "score",
				"op":    "greater_than",
				"value": 50.5,
			},
		},
	}
	r := mapToRule(raw)
	if len(r.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(r.Conditions))
	}
	// First condition: "in" with array value
	if r.Conditions[0].Op != "in" {
		t.Errorf("expected op 'in', got %s", r.Conditions[0].Op)
	}
	// Second condition: "greater_than" with float value
	if r.Conditions[1].Op != "greater_than" {
		t.Errorf("expected op 'greater_than', got %s", r.Conditions[1].Op)
	}
}

func TestMapToRule_ConditionMissingFields(t *testing.T) {
	raw := map[string]any{
		"id": "rule-missing",
		"conditions": []any{
			map[string]any{"field": "path"},  // missing op and value
			map[string]any{"op": "contains"}, // missing field
			map[string]any{"value": "test"},  // missing field and op
		},
	}
	r := mapToRule(raw)
	// Conditions with missing fields are still added but empty
	if len(r.Conditions) != 3 {
		t.Errorf("expected 3 conditions, got %d", len(r.Conditions))
	}
}

// --- collectACMEDomains with mixed scenarios ---

func TestCollectACMEDomains_MixedVirtualHosts(t *testing.T) {
	cfg := &config.Config{
		TLS: config.TLSConfig{
			ACME: config.ACMEConfig{
				Domains: []string{"explicit.com"},
			},
		},
		VirtualHosts: []config.VirtualHostConfig{
			{
				// No manual cert - will be included
				Domains: []string{"vh-no-cert.com"},
			},
			{
				// Has manual cert - will NOT be included
				Domains: []string{"vh-manual.com"},
				TLS: config.VHostTLSConfig{
					CertFile: "/cert.pem",
					KeyFile:  "/key.pem",
				},
			},
			{
				// No domains - should not cause issues
				Domains: []string{},
			},
		},
	}
	result := collectACMEDomains(cfg)
	// Should have 2 groups: explicit + vh-no-cert
	if len(result) != 2 {
		t.Fatalf("expected 2 domain groups, got %d", len(result))
	}
}

// --- upstreamSummary edge cases ---

func TestUpstreamSummary_NilUpstreams(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = nil
	got := upstreamSummary(cfg)
	if got != "(no upstream)" {
		t.Errorf("expected '(no upstream)', got %q", got)
	}
}

func TestUpstreamSummary_SingleTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "single",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:3000"},
			},
		},
	}
	got := upstreamSummary(cfg)
	if !strings.Contains(got, "http://localhost:3000") {
		t.Errorf("expected target URL in summary, got %q", got)
	}
}

// --- buildReverseProxy with VirtualHosts ---

func TestBuildReverseProxy_VirtualHosts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "api",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
		},
		{
			Name:    "web",
			Targets: []config.TargetConfig{{URL: "http://localhost:8088"}},
		},
	}
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"api.example.com"},
			Routes: []config.RouteConfig{
				{Path: "/", Upstream: "api"},
			},
		},
		{
			Domains: []string{"www.example.com"},
			Routes: []config.RouteConfig{
				{Path: "/", Upstream: "web"},
			},
		},
	}

	handler, hcs := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if len(hcs) != 0 {
		t.Errorf("expected no health checkers without health config, got %d", len(hcs))
	}
}

func TestBuildReverseProxy_HealthChecks(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
			HealthCheck: config.HealthCheckConfig{
				Enabled:  true,
				Interval: 5 * time.Second,
				Timeout:  2 * time.Second,
				Path:     "/health",
			},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "backend"},
	}

	handler, hcs := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if len(hcs) != 1 {
		t.Fatalf("expected 1 health checker, got %d", len(hcs))
	}
	// Stop the health checker
	hcs[0].Stop()
}

func TestBuildReverseProxy_EmptyTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "empty",
			Targets: []config.TargetConfig{}, // Empty targets
		},
		{
			Name:    "valid",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "valid"},
	}

	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBuildReverseProxy_AllInvalidTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "all-bad",
			Targets: []config.TargetConfig{{URL: "://invalid1"}, {URL: "://invalid2"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "all-bad"},
	}

	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler even with all invalid targets")
	}
}

func TestBuildReverseProxy_LoadBalancerStrategies(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:         "weighted",
			LoadBalancer: "weighted",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:3000", Weight: 3},
				{URL: "http://localhost:3001", Weight: 1},
			},
		},
		{
			Name:         "least_conn",
			LoadBalancer: "least_conn",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:4000"},
			},
		},
		{
			Name:         "ip_hash",
			LoadBalancer: "ip_hash",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:5000"},
			},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/w", Upstream: "weighted"},
		{Path: "/l", Upstream: "least_conn"},
		{Path: "/i", Upstream: "ip_hash"},
	}

	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBuildReverseProxy_VirtualHostMissingUpstream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
		},
	}
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"example.com"},
			Routes: []config.RouteConfig{
				{Path: "/", Upstream: "nonexistent"}, // Missing upstream
			},
		},
	}

	handler, _ := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

// --- addLayers with Custom Rules + GeoIP ---

func TestAddLayers_CustomRulesWithGeoIP(t *testing.T) {
	// Create a valid GeoIP CSV file
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "geoip.csv")
	csvContent := "1.0.0.0,1.0.0.255,US\n"
	os.WriteFile(csvPath, []byte(csvContent), 0644)

	cfg := config.DefaultConfig()
	cfg.WAF.CustomRules.Enabled = true
	cfg.WAF.CustomRules.Rules = []config.CustomRule{
		{
			ID:         "rule-1",
			Name:       "Block country",
			Enabled:    true,
			Priority:   1,
			Conditions: []config.RuleCondition{{Field: "country", Op: "equals", Value: "XX"}},
			Action:     "block",
			Score:      10,
		},
	}
	cfg.WAF.GeoIP.Enabled = true
	cfg.WAF.GeoIP.DBPath = csvPath

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- addLayers with Data Masking ---

func TestAddLayers_DataMasking(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Response.DataMasking.Enabled = true
	cfg.WAF.Response.DataMasking.MaskCreditCards = true
	cfg.WAF.Response.DataMasking.MaskSSN = true
	cfg.WAF.Response.DataMasking.MaskAPIKeys = true
	cfg.WAF.Response.DataMasking.StripStackTraces = true
	cfg.WAF.Response.ErrorPages.Mode = "production"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- addLayers with Bot Detection TLS Fingerprint ---

func TestAddLayers_BotDetectionTLS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.BotDetection.Enabled = true
	cfg.WAF.BotDetection.Mode = "challenge"
	cfg.WAF.BotDetection.TLSFingerprint.Enabled = true
	cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction = "allow"
	cfg.WAF.BotDetection.TLSFingerprint.UnknownAction = "challenge"
	cfg.WAF.BotDetection.TLSFingerprint.MismatchAction = "block"
	cfg.WAF.BotDetection.UserAgent.Enabled = true
	cfg.WAF.BotDetection.UserAgent.BlockEmpty = true
	cfg.WAF.BotDetection.UserAgent.BlockKnownScanners = true
	cfg.WAF.BotDetection.Behavior.Enabled = true
	cfg.WAF.BotDetection.Behavior.Window = 60 * time.Second
	cfg.WAF.BotDetection.Behavior.RPSThreshold = 100
	cfg.WAF.BotDetection.Behavior.ErrorRateThreshold = 50

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- addLayers with Detection Exclusions ---

func TestAddLayers_DetectionWithExclusions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Threshold.Block = 50
	cfg.WAF.Detection.Threshold.Log = 25
	cfg.WAF.Detection.Detectors = map[string]config.DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.0},
		"xss":  {Enabled: true, Multiplier: 1.5},
	}
	cfg.WAF.Detection.Exclusions = []config.ExclusionConfig{
		{Path: "/api/webhook", Detectors: []string{"sqli"}, Reason: "Webhook SQL patterns"},
		{Path: "/admin/sql", Detectors: []string{"sqli", "xss"}, Reason: "Admin panel"},
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- addLayers with Rate Limit AutoBan ---

func TestAddLayers_RateLimitWithAutoBan(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []config.RateLimitRule{
		{
			ID:           "api-limit",
			Scope:        "ip",
			Paths:        []string{"/api/"},
			Limit:        100,
			Window:       60 * time.Second,
			Burst:        20,
			Action:       "block",
			AutoBanAfter: 3,
		},
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- addLayers with Sanitizer Path Overrides ---

func TestAddLayers_SanitizerPathOverrides(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.MaxBodySize = 1048576
	cfg.WAF.Sanitizer.MaxURLLength = 2048
	cfg.WAF.Sanitizer.MaxHeaderSize = 8192
	cfg.WAF.Sanitizer.MaxHeaderCount = 50
	cfg.WAF.Sanitizer.MaxCookieSize = 4096
	cfg.WAF.Sanitizer.BlockNullBytes = true
	cfg.WAF.Sanitizer.NormalizeEncoding = true
	cfg.WAF.Sanitizer.StripHopByHop = true
	cfg.WAF.Sanitizer.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE"}
	cfg.WAF.Sanitizer.PathOverrides = []config.PathOverride{
		{Path: "/upload", MaxBodySize: 104857600},
		{Path: "/api/big", MaxBodySize: 52428800},
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- startDashboard tests ---

func TestStartDashboard_Basic(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0" // Use port 0 for random available port

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	srv, sse, dash := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if sse == nil {
		t.Fatal("expected non-nil SSE broadcaster")
	}
	if dash == nil {
		t.Fatal("expected non-nil dashboard")
	}

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// minimalEventStore only implements engine.EventStorer, not events.EventStore
type minimalEventStore struct{}

func (m *minimalEventStore) Store(e engine.Event) error { return nil }
func (m *minimalEventStore) Close() error               { return nil }

func TestStartDashboard_EventStoreNotQueryable(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"

	// Use a minimal store that doesn't implement events.EventStore
	store := &minimalEventStore{}
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	srv, sse, dash := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	if sse == nil {
		t.Fatal("expected non-nil SSE broadcaster")
	}
	if dash == nil {
		t.Fatal("expected non-nil dashboard")
	}

	// Clean up
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// --- TestRequest tests ---

func TestTestRequest_Basic(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}

	result, err := adapter.TestRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["action"] == "" {
		t.Error("expected action in result")
	}
}

func TestTestRequest_WithHeaders(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}

	headers := map[string]string{
		"User-Agent": "test-client",
		"X-Custom":   "value",
	}

	result, err := adapter.TestRequest("POST", "/api/data", headers)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestTestRequest_FullURL(t *testing.T) {
	cfg := config.DefaultConfig()

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}

	// Test with full URL
	result, err := adapter.TestRequest("GET", "https://example.com/path", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestTestRequest_InvalidURL(t *testing.T) {
	cfg := config.DefaultConfig()

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}

	// Test with invalid URL that causes http.NewRequest to fail
	_, err = adapter.TestRequest("INVALID METHOD", "http://example.com/path", nil)
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
}

// --- validateConfigFile tests ---

func TestValidateConfigFile_Valid(t *testing.T) {
	// Create a valid config file
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "valid.yaml")
	content := "mode: enforce\nlisten: \":8088\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, summary, err := validateConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("validateConfigFile: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("expected mode 'enforce', got %q", cfg.Mode)
	}
}

func TestValidateConfigFile_NonExistent(t *testing.T) {
	_, _, err := validateConfigFile("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("expected 'loading config' error, got: %v", err)
	}
}

func TestValidateConfigFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	content := "mode: [invalid\n  unclosed"
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, _, err := validateConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidateConfigFile_WithUpstreams(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "with-upstreams.yaml")
	content := `
mode: enforce
listen: ":8088"
upstreams:
  - name: backend
    targets:
      - url: http://localhost:3000
routes:
  - path: /api
    upstream: backend
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, summary, err := validateConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("validateConfigFile: %v", err)
	}
	if summary.Upstreams != 1 {
		t.Errorf("expected 1 upstream, got %d", summary.Upstreams)
	}
	if summary.Routes != 1 {
		t.Errorf("expected 1 route, got %d", summary.Routes)
	}
}

func TestValidateConfigFile_WithDetection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "with-detection.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    detectors:
      sqli:
        enabled: true
        multiplier: 1.0
      xss:
        enabled: true
        multiplier: 1.5
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, summary, err := validateConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("validateConfigFile: %v", err)
	}
	if !cfg.WAF.Detection.Enabled {
		t.Error("expected detection to be enabled")
	}
	// DefaultConfig has 6 detectors that get merged with YAML-specified ones
	// We just verify at least 2 detectors exist (sqli and xss from YAML + defaults)
	if summary.Detectors < 2 {
		t.Errorf("expected at least 2 detectors, got %d", summary.Detectors)
	}
	// Verify specific detectors from YAML are present
	if _, ok := cfg.WAF.Detection.Detectors["sqli"]; !ok {
		t.Error("expected sqli detector to be present")
	}
	if _, ok := cfg.WAF.Detection.Detectors["xss"]; !ok {
		t.Error("expected xss detector to be present")
	}
}

func TestValidateConfigFile_WithRateLimit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "with-ratelimit.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  rate_limit:
    enabled: true
    rules:
      - id: api-limit
        scope: ip
        limit: 100
        window: 60s
        action: block
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	cfg, summary, err := validateConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("validateConfigFile: %v", err)
	}
	if !cfg.WAF.RateLimit.Enabled {
		t.Error("expected rate limit to be enabled")
	}
	if summary.RateLimitRules != 1 {
		t.Errorf("expected 1 rate limit rule, got %d", summary.RateLimitRules)
	}
}

// --- loadConfig with existing default path ---

func TestLoadConfig_ExistingDefaultPath(t *testing.T) {
	// Save current directory
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)

	// Create temp directory with a guardianwaf.yaml file
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardianwaf.yaml")
	content := "mode: enforce\nlisten: \":9090\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	os.Chdir(dir)

	// loadConfig should load the existing file
	cfg := loadConfig("guardianwaf.yaml")
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("expected mode 'enforce', got %q", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("expected listen ':9090', got %q", cfg.Listen)
	}
}

// --- validateConfigFile with validation error ---

func TestValidateConfigFile_ValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid-config.yaml")
	// Invalid threshold (block < log should fail validation)
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    threshold:
      block: 10
      log: 50
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, _, err := validateConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected validation error for block < log threshold")
	}
	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// --- runValidate tests ---

func TestRunValidate_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "valid.yaml")
	content := "mode: enforce\nlisten: \":8088\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runValidate(cfgPath)
	if err != nil {
		t.Fatalf("runValidate error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Config == nil {
		t.Fatal("expected non-nil config")
	}
	if result.Summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if result.Config.Mode != "enforce" {
		t.Errorf("expected mode 'enforce', got %q", result.Config.Mode)
	}
}

func TestRunValidate_NonExistent(t *testing.T) {
	_, err := runValidate("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent config")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected 'validation failed' error, got: %v", err)
	}
}

func TestRunValidate_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "invalid.yaml")
	content := "mode: [invalid\n  unclosed"
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, err := runValidate(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// --- runCheck tests ---

func TestRunCheck_MissingURL(t *testing.T) {
	_, err := runCheck(&CheckOptions{
		ConfigPath: "guardianwaf.yaml",
		URL:        "", // Missing URL
		Method:     "GET",
	})
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
	if !strings.Contains(err.Error(), "--url is required") {
		t.Errorf("expected '--url is required' error, got: %v", err)
	}
}

func TestRunCheck_ValidRequest(t *testing.T) {
	// Create a valid config
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/test",
		Method:     "GET",
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Action == "" {
		t.Error("expected non-empty action")
	}
}

func TestRunCheck_WithHeaders(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := "mode: monitor\nlisten: \":8088\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/api/test",
		Method:     "POST",
		Headers:    []string{"X-Custom: value", "Authorization: Bearer token"},
		Body:       `{"test": "data"}`,
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRunCheck_FullURL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := "mode: monitor\nlisten: \":8088\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "https://example.com/api/test",
		Method:     "GET",
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestRunCheck_InvalidMethod(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := "mode: monitor\nlisten: \":8088\"\n"
	os.WriteFile(cfgPath, []byte(content), 0644)

	_, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/test",
		Method:     "BAD METHOD", // Invalid method
	})
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
}

func TestRunCheck_SQLInjection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    detectors:
      sqli:
        enabled: true
        multiplier: 1.0
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/search?q=' OR '1'='1",
		Method:     "GET",
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	// Should detect SQL injection
	if result.Score == 0 {
		t.Error("expected non-zero score for SQL injection attempt")
	}
}

// --- runCheck additional tests ---

// Note: ConfigNotFound test skipped because loadConfig calls os.Exit(1)
// for missing non-default config paths, which cannot be tested easily.

// Note: TestRunCheck_InvalidYAML skipped - loadConfig calls os.Exit(1)

func TestRunCheck_InvalidHeader(t *testing.T) {
	// Invalid headers are silently ignored, not an error
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	os.WriteFile(cfgPath, []byte("mode: monitor\n"), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/test",
		Method:     "GET",
		Headers:    []string{"InvalidHeader"},
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected result")
	}
}

func TestRunCheck_XSSDetection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    detectors:
      xss:
        enabled: true
        multiplier: 1.0
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/search?q=<script>alert(1)</script>",
		Method:     "GET",
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	if result.Score == 0 {
		t.Error("expected non-zero score for XSS attempt")
	}
}

func TestRunCheck_LFIDetection(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "test.yaml")
	content := `
mode: enforce
listen: ":8088"
waf:
  detection:
    enabled: true
    detectors:
      lfi:
        enabled: true
        multiplier: 1.0
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := runCheck(&CheckOptions{
		ConfigPath: cfgPath,
		URL:        "/file?path=../../../etc/passwd",
		Method:     "GET",
	})
	if err != nil {
		t.Fatalf("runCheck error: %v", err)
	}
	if result.Score == 0 {
		t.Error("expected non-zero score for LFI attempt")
	}
}

// --- mcpEngineAdapter additional tests ---

func TestMCPEngineAdapter_GetConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}
	result := adapter.GetConfig()

	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map result")
	}
	if m["mode"] != cfg.Mode {
		t.Errorf("expected mode %q, got %q", cfg.Mode, m["mode"])
	}
}

func TestMCPEngineAdapter_AddRateLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	eng.AddLayer(engine.OrderedLayer{Layer: ratelimit.NewLayer(ratelimit.Config{Enabled: true}), Order: 200})

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.AddRateLimit(map[string]any{"id": "r1", "scope": "ip", "limit": 10, "window": "1m", "action": "block"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPEngineAdapter_RemoveRateLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	rlLayer := ratelimit.NewLayer(ratelimit.Config{Enabled: true})
	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: 200})

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	// Add a rule first, then remove it
	_ = adapter.AddRateLimit(map[string]any{"id": "test-id", "scope": "ip", "limit": 10, "window": "1m", "action": "block"})
	err = adapter.RemoveRateLimit("test-id")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPEngineAdapter_AddExclusion(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	eng.AddLayer(engine.OrderedLayer{Layer: detection.NewLayer(detection.Config{Enabled: true}), Order: 400})

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.AddExclusion("/api", []string{"sqli"}, "test reason")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPEngineAdapter_RemoveExclusion(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	eng.AddLayer(engine.OrderedLayer{Layer: detection.NewLayer(detection.Config{Enabled: true}), Order: 400})

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	// Add first, then remove
	_ = adapter.AddExclusion("/api", []string{"sqli"}, "test reason")
	err = adapter.RemoveExclusion("/api")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPEngineAdapter_GetEvents(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}
	result, err := adapter.GetEvents(json.RawMessage("{}"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPEngineAdapter_GetTopIPs(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg}
	result := adapter.GetTopIPs(10)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestHealthzEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		s := eng.Stats()
		fmt.Fprintf(w, `{"status":"ok","mode":%q,"total_requests":%d,"blocked_requests":%d}`,
			cfg.Mode, s.TotalRequests, s.BlockedRequests)
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("expected status ok in body, got: %s", body)
	}
	if !strings.Contains(body, `"mode"`) {
		t.Errorf("expected mode in body, got: %s", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s := eng.Stats()
		fmt.Fprintf(w, "# HELP guardianwaf_requests_total Total number of requests processed.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_total %d\n", s.TotalRequests)
		fmt.Fprintf(w, "# HELP guardianwaf_requests_blocked_total Total number of blocked requests.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_requests_blocked_total counter\n")
		fmt.Fprintf(w, "guardianwaf_requests_blocked_total %d\n", s.BlockedRequests)
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "guardianwaf_requests_total") {
		t.Errorf("expected guardianwaf_requests_total in body, got: %s", body)
	}
	if !strings.Contains(body, "# TYPE guardianwaf_requests_total counter") {
		t.Errorf("expected Prometheus TYPE annotation, got: %s", body)
	}
	if !strings.Contains(body, "guardianwaf_requests_blocked_total") {
		t.Errorf("expected blocked_total metric, got: %s", body)
	}
}

// --- addLayers: ThreatIntel ---

func TestAddLayers_ThreatIntel(t *testing.T) {
	// Set up a test HTTP server to serve an empty threat feed
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"ips":[]}`)
	}))
	defer srv.Close()

	cfg := config.DefaultConfig()
	cfg.WAF.ThreatIntel.Enabled = true
	cfg.WAF.ThreatIntel.IPReputation.Enabled = true
	cfg.WAF.ThreatIntel.IPReputation.BlockMalicious = true
	cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold = 50
	cfg.WAF.ThreatIntel.CacheSize = 100
	cfg.WAF.ThreatIntel.CacheTTL = 5 * time.Minute
	cfg.WAF.ThreatIntel.Feeds = []config.ThreatFeedConfig{
		{
			Type:    "url",
			URL:     srv.URL,
			Format:  "json",
			Refresh: 10 * time.Second,
		},
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	layer := eng.FindLayer("threat_intel")
	if layer == nil {
		t.Fatal("expected threat_intel layer to be added")
	}

	// Clean up feed refresh goroutines
	tiLayer, ok := layer.(*threatintel.Layer)
	if !ok {
		t.Fatal("expected *threatintel.Layer type")
	}
	tiLayer.Stop()
}

// --- addLayers: CORS ---

func TestAddLayers_CORS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CORS.AllowOrigins = []string{"https://example.com", "https://app.example.com"}
	cfg.WAF.CORS.AllowMethods = []string{"GET", "POST"}
	cfg.WAF.CORS.AllowHeaders = []string{"Content-Type", "Authorization"}
	cfg.WAF.CORS.AllowCredentials = true
	cfg.WAF.CORS.MaxAgeSeconds = 3600
	cfg.WAF.CORS.PreflightCacheSeconds = 300

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	layer := eng.FindLayer("cors")
	if layer == nil {
		t.Fatal("expected cors layer to be added")
	}
	if _, ok := layer.(*cors.Layer); !ok {
		t.Fatal("expected *cors.Layer type")
	}
}

// --- addLayers: ATO Protection ---

func TestAddLayers_ATOProtection(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ATOProtection.Enabled = true
	cfg.WAF.ATOProtection.LoginPaths = []string{"/login", "/auth/token"}
	cfg.WAF.ATOProtection.BruteForce = config.BruteForceConfig{
		Enabled:             true,
		Window:              5 * time.Minute,
		MaxAttemptsPerIP:    10,
		MaxAttemptsPerEmail: 5,
		BlockDuration:       15 * time.Minute,
	}
	cfg.WAF.ATOProtection.CredStuffing = config.CredentialStuffingConfig{
		Enabled:              true,
		DistributedThreshold: 5,
		Window:               10 * time.Minute,
		BlockDuration:        30 * time.Minute,
	}
	cfg.WAF.ATOProtection.PasswordSpray = config.PasswordSprayConfig{
		Enabled:       true,
		Threshold:     20,
		Window:        5 * time.Minute,
		BlockDuration: 15 * time.Minute,
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	layer := eng.FindLayer("ato_protection")
	if layer == nil {
		t.Fatal("expected ato_protection layer to be added")
	}
	if _, ok := layer.(*ato.Layer); !ok {
		t.Fatal("expected *ato.Layer type")
	}
}

// --- addLayers: APISecurity ---

func TestAddLayers_APISecurity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APISecurity.Enabled = true
	cfg.WAF.APISecurity.JWT = config.JWTConfig{
		Enabled:          true,
		Issuer:           "test-issuer",
		Audience:         "test-audience",
		Algorithms:       []string{"HS256"},
		ClockSkewSeconds: 30,
	}
	cfg.WAF.APISecurity.APIKeys = config.APIKeysConfig{
		Enabled: false,
	}

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	layer := eng.FindLayer("api_security")
	if layer == nil {
		t.Fatal("expected api_security layer to be added")
	}
	if _, ok := layer.(*apisecurity.Layer); !ok {
		t.Fatal("expected *apisecurity.Layer type")
	}
}

// --- MCP Adapter: AddRateLimit layer not found ---

func TestMCPAdapter_AddRateLimit_LayerNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	// No rate limit layer added

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.AddRateLimit(map[string]any{
		"id": "r1", "scope": "ip", "limit": 10, "window": "1m", "action": "block",
	})
	if err == nil {
		t.Fatal("expected error when rate limit layer not found")
	}
	if !strings.Contains(err.Error(), "rate limit layer not available") {
		t.Errorf("expected 'rate limit layer not available' error, got: %v", err)
	}
}

// --- MCP Adapter: RemoveRateLimit layer not found ---

func TestMCPAdapter_RemoveRateLimit_LayerNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	// No rate limit layer added

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.RemoveRateLimit("r1")
	if err == nil {
		t.Fatal("expected error when rate limit layer not found")
	}
	if !strings.Contains(err.Error(), "rate limit layer not available") {
		t.Errorf("expected 'rate limit layer not available' error, got: %v", err)
	}
}

// --- MCP Adapter: RemoveBlacklist layer not found ---

func TestMCPAdapter_RemoveBlacklist_LayerNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	// No IP ACL layer added

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.RemoveBlacklist("10.0.0.1")
	if err == nil {
		t.Fatal("expected error when IP ACL layer not found")
	}
	if !strings.Contains(err.Error(), "IP ACL layer not available") {
		t.Errorf("expected 'IP ACL layer not available' error, got: %v", err)
	}
}

// --- MCP Adapter: RemoveWhitelist layer not found ---

func TestMCPAdapter_RemoveWhitelist_LayerNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	// No IP ACL layer added

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.RemoveWhitelist("10.0.0.1")
	if err == nil {
		t.Fatal("expected error when IP ACL layer not found")
	}
	if !strings.Contains(err.Error(), "IP ACL layer not available") {
		t.Errorf("expected 'IP ACL layer not available' error, got: %v", err)
	}
}

// --- MCP Adapter: RemoveExclusion layer not found ---

func TestMCPAdapter_RemoveExclusion_LayerNotFound(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	// No detection layer added

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = adapter.RemoveExclusion("/api")
	if err == nil {
		t.Fatal("expected error when detection layer not found")
	}
	if !strings.Contains(err.Error(), "detection layer not available") {
		t.Errorf("expected 'detection layer not available' error, got: %v", err)
	}
}

// --- MCP Adapter: GetTopIPs with data ---

func TestMCPAdapter_GetTopIPs_WithData(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	// Add events with different IPs and varying counts
	ips := []struct {
		ip    string
		count int
		score int
	}{
		{"1.1.1.1", 5, 10},
		{"2.2.2.2", 3, 5},
		{"3.3.3.3", 8, 20},
		{"4.4.4.4", 1, 0},
	}
	for _, entry := range ips {
		for i := 0; i < entry.count; i++ {
			evt := engine.Event{
				ID:        fmt.Sprintf("%s-%d", entry.ip, i),
				Timestamp: time.Now(),
				ClientIP:  entry.ip,
				Method:    "GET",
				Path:      "/test",
				Action:    engine.ActionPass,
				Score:     entry.score / entry.count,
			}
			if err := store.Store(evt); err != nil {
				t.Fatalf("Store error: %v", err)
			}
		}
	}

	adapter := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	result := adapter.GetTopIPs(5)

	// Result is []ipStat where ipStat is a local struct inside GetTopIPs.
	// Use reflection to access the slice elements and their fields.
	val := reflect.ValueOf(result)
	if val.Kind() != reflect.Slice {
		t.Fatalf("expected slice, got %T", result)
	}
	if val.Len() != 4 {
		t.Fatalf("expected 4 IPs, got %d", val.Len())
	}

	// Helper to get string field by JSON tag name from a struct value
	getField := func(v reflect.Value, fieldName string) reflect.Value {
		tStruct := v.Type()
		for i := 0; i < tStruct.NumField(); i++ {
			if tStruct.Field(i).Name == fieldName {
				return v.Field(i)
			}
		}
		return reflect.Value{}
	}

	// Should be sorted by request count descending: 3.3.3.3 (8), 1.1.1.1 (5), 2.2.2.2 (3), 4.4.4.4 (1)
	type expectedEntry struct {
		IP       string
		Requests int
	}
	expected := []expectedEntry{
		{"3.3.3.3", 8},
		{"1.1.1.1", 5},
		{"2.2.2.2", 3},
		{"4.4.4.4", 1},
	}
	for i, exp := range expected {
		elem := val.Index(i)
		ip := getField(elem, "IP").String()
		requests := int(getField(elem, "Requests").Int())
		if ip != exp.IP {
			t.Errorf("entry %d: expected IP %s, got %s", i, exp.IP, ip)
		}
		if requests != exp.Requests {
			t.Errorf("entry %d: expected %d requests, got %d", i, exp.Requests, requests)
		}
	}
}

// --- MCP Adapter: AddBlacklist with CIDR ---

func TestMCPAdapter_AddBlacklist_CIDR(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.AddBlacklist("10.0.0.0/8"); err != nil {
		t.Errorf("AddBlacklist CIDR error: %v", err)
	}

	// Verify it was added by removing it
	if err := a.RemoveBlacklist("10.0.0.0/8"); err != nil {
		t.Errorf("RemoveBlacklist CIDR error: %v", err)
	}
}

// --- MCP Adapter: AddWhitelist with CIDR ---

func TestMCPAdapter_AddWhitelist_CIDR(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.AddWhitelist("172.16.0.0/12"); err != nil {
		t.Errorf("AddWhitelist CIDR error: %v", err)
	}

	// Verify it was added by removing it
	if err := a.RemoveWhitelist("172.16.0.0/12"); err != nil {
		t.Errorf("RemoveWhitelist CIDR error: %v", err)
	}
}
