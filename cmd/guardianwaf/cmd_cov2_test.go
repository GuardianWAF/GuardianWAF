package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/compliance"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

func init() {
	proxy.AllowPrivateTargets()
}

// --- readLine with actual input that returns non-default via subprocess ---

func TestReadLine_WithActualInput(t *testing.T) {
	if os.Getenv("GUARDIANWAF_COV2_READLINE") == "1" {
		result := readLine("default-val")
		if result != "custom-input" {
			fmt.Printf("expected 'custom-input', got %q\n", result)
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadLine_WithActualInput")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_COV2_READLINE=1")
	cmd.Stdin = strings.NewReader("custom-input\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v, output: %s", err, output)
	}
}

// --- readLine with whitespace-only input ---

func TestReadLine_WhitespaceInput(t *testing.T) {
	if os.Getenv("GUARDIANWAF_COV2_READLINE_WS") == "1" {
		result := readLine("fallback")
		if result != "fallback" {
			fmt.Printf("expected 'fallback', got %q\n", result)
			os.Exit(1)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadLine_WhitespaceInput")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_COV2_READLINE_WS=1")
	cmd.Stdin = strings.NewReader("   \n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v, output: %s", err, output)
	}
}

// --- generateDashboardPassword uniqueness check ---

func TestGenerateDashboardPassword_Uniqueness(t *testing.T) {
	pwds := make(map[string]bool)
	for range 10 {
		pwd := generateDashboardPassword()
		if len(pwd) != 24 {
			t.Errorf("expected 24-char password, got %d", len(pwd))
		}
		if pwds[pwd] {
			t.Error("generated duplicate password")
		}
		pwds[pwd] = true
	}
}

// --- addLayers with CRS layer enabled ---

func TestAddLayers_WithCRSLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.CRS.ParanoiaLevel = 1
	cfg.WAF.CRS.AnomalyThreshold = 5

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("crs")
	if layer == nil {
		t.Error("expected CRS layer to be added")
	}
}

// --- addLayers with VirtualPatch layer enabled ---

func TestAddLayers_WithVirtualPatchLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.VirtualPatch.Enabled = true
	cfg.WAF.VirtualPatch.BlockSeverity = []string{"CRITICAL", "HIGH"}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("virtualpatch")
	if layer == nil {
		t.Error("expected virtual patch layer to be added")
	}
}

// --- addLayers with API Validation layer enabled ---

func TestAddLayers_WithAPIValidationLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation.Enabled = true
	cfg.WAF.APIValidation.ValidateRequest = true
	cfg.WAF.APIValidation.ValidateResponse = false
	cfg.WAF.APIValidation.StrictMode = false
	cfg.WAF.APIValidation.BlockOnViolation = false

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("apivalidation")
	if layer == nil {
		t.Error("expected API validation layer to be added")
	}
}

// --- addLayers with DLP layer enabled ---

func TestAddLayers_WithDLPLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.DLP.ScanRequest = true
	cfg.WAF.DLP.BlockOnMatch = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("dlp")
	if layer == nil {
		t.Error("expected DLP layer to be added")
	}
}

// --- addLayers with Client-Side layer enabled ---

func TestAddLayers_WithClientSideLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ClientSide.Enabled = true
	cfg.WAF.ClientSide.Mode = "enforce"
	cfg.WAF.ClientSide.MagecartDetection.Enabled = true
	cfg.WAF.ClientSide.AgentInjection.Enabled = false
	cfg.WAF.ClientSide.CSP.Enabled = false

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("clientside")
	if layer == nil {
		t.Error("expected client-side layer to be added")
	}
}

// --- addLayers with ATO protection layer ---

func TestAddLayers_WithATOLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ATOProtection.Enabled = true
	cfg.WAF.ATOProtection.BruteForce.Enabled = true
	cfg.WAF.ATOProtection.LoginPaths = []string{"/login"}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("ato_protection")
	if layer == nil {
		t.Error("expected ATO layer to be added")
	}
}

// --- addLayers with API Security layer ---

func TestAddLayers_WithAPISecurityLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APISecurity.Enabled = true
	cfg.WAF.APISecurity.JWT.Enabled = true
	cfg.WAF.APISecurity.JWT.Issuer = "test-issuer"

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("api_security")
	if layer == nil {
		t.Error("expected API security layer to be added")
	}
}

// --- addLayers with CORS layer ---

func TestAddLayers_WithCORSLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CORS.AllowOrigins = []string{"https://example.com"}
	cfg.WAF.CORS.AllowMethods = []string{"GET", "POST"}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("cors")
	if layer == nil {
		t.Error("expected CORS layer to be added")
	}
}

// --- addLayers with Threat Intel layer ---

func TestAddLayers_WithThreatIntelLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.ThreatIntel.Enabled = true
	cfg.WAF.ThreatIntel.IPReputation.Enabled = true
	cfg.WAF.ThreatIntel.DomainRep.Enabled = false

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("threat_intel")
	if layer == nil {
		t.Error("expected threat intel layer to be added")
	}
}

// --- addLayers with Sanitizer layer ---

func TestAddLayers_WithSanitizerLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.MaxURLLength = 2048
	cfg.WAF.Sanitizer.BlockNullBytes = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("sanitizer")
	if layer == nil {
		t.Error("expected sanitizer layer to be added")
	}
}

// --- addLayers with Bot Detection layer ---

func TestAddLayers_WithBotDetectionLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.BotDetection.Enabled = true
	cfg.WAF.BotDetection.Mode = "enforce"
	cfg.WAF.BotDetection.TLSFingerprint.Enabled = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("botdetect")
	if layer == nil {
		t.Error("expected bot detection layer to be added")
	}
}

// --- addLayers with Custom Rules layer ---

func TestAddLayers_WithCustomRulesLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CustomRules.Enabled = true
	cfg.WAF.CustomRules.Rules = []config.CustomRule{
		{
			ID:       "rule-1",
			Name:     "Block Admin",
			Enabled:  true,
			Priority: 10,
			Conditions: []config.RuleCondition{
				{Field: "path", Op: "prefix", Value: "/admin"},
			},
			Action: "block",
			Score:  80,
		},
	}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	layer := eng.FindLayer("rules")
	if layer == nil {
		t.Error("expected rules layer to be added")
	}
}

// --- addLayers with Rate Limit and IP ACL auto-ban ---

func TestAddLayers_RateLimitAutoBan(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"10.0.0.1"}
	cfg.WAF.IPACL.AutoBan.Enabled = true
	cfg.WAF.IPACL.AutoBan.DefaultTTL = 5 * time.Minute
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []config.RateLimitRule{
		{
			ID:     "rl-1",
			Scope:  "ip",
			Paths:  []string{"/api"},
			Limit:  100,
			Window: time.Minute,
			Action: "block",
		},
	}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	addLayers(eng, cfg)
	aclLayer := eng.FindLayer("ipacl")
	rlLayer := eng.FindLayer("ratelimit")
	if aclLayer == nil {
		t.Error("expected IP ACL layer to be added")
	}
	if rlLayer == nil {
		t.Error("expected rate limit layer to be added")
	}
}

// --- startDashboard with compliance enabled ---

func TestStartDashboard_ComplianceEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.Dashboard.APIKey = "test-key-compliance"
	cfg.Compliance.Enabled = true
	cfg.Compliance.Frameworks = []string{"pci_dss", "gdpr"}

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	srv, sse, d := startDashboard(cfg, eng)
	if srv == nil {
		t.Error("expected non-nil server")
	}
	_ = sse
	_ = d
}

// --- startDashboard without API key (triggers generateDashboardPassword) ---

func TestStartDashboard_EmptyAPIKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.Dashboard.APIKey = ""

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	srv, _, _ := startDashboard(cfg, eng)
	if srv == nil {
		t.Error("expected non-nil server")
	}
}

// --- startMCPServer with nil stdin/stdout ---

func TestStartMCPServer_NilIO(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.APIKey = "test-mcp-key"
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	// Use closed pipe for stdin so the MCP server sees EOF and exits
	r, w, _ := os.Pipe()
	w.Close()

	var output strings.Builder
	startMCPServer(eng, cfg, store, nil, r, &output)
	_ = r.Close()
}

// --- startMCPServer with alerting manager ---

func TestStartMCPServer_WithAlertMgr(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	r, w, _ := os.Pipe()
	w.Close()

	var output strings.Builder
	alertMgr := alerting.NewManager(nil)
	startMCPServer(eng, cfg, store, alertMgr, r, &output)
	_ = r.Close()
}

// --- cmdTestAlert no target specified (shows usage) ---

func TestCmdTestAlert_ShowTargets(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-noargs-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configContent := `
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
alerting:
  enabled: true
  webhooks:
    - name: myhook
      url: "https://127.0.0.1/webhook"
      type: slack
      events:
        - block
      min_score: 50
`
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	oldExit := osExit
	exitCode := -1
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldExit }()

	cmdTestAlert([]string{"-config", tmpFile.Name()})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 (no target specified), got %d", exitCode)
	}
}

// --- cmdTestAlert with email targets ---

func TestCmdTestAlert_EmailTarget(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-email-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configContent := `
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
alerting:
  enabled: true
  emails:
    - name: test-email
      smtp_host: "127.0.0.1"
      smtp_port: 25
      username: "test"
      password: "test"
      from: "test@example.com"
      to:
        - "admin@example.com"
      use_tls: false
      events:
        - block
      min_score: 50
`
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	oldExit := osExit
	osExit = func(code int) {}
	defer func() { osExit = oldExit }()

	// Test -all flag with email target
	cmdTestAlert([]string{"-config", tmpFile.Name(), "-all"})
}

// --- isDefaultPath with empty string ---

func TestIsDefaultPath_EmptyString(t *testing.T) {
	if isDefaultPath("") {
		t.Error("expected empty string to not be recognized as default path")
	}
}

// --- MCP adapter: AddRateLimit with actual layer ---

func TestMCPAdapter_AddRateLimit_WithLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	rlLayer := ratelimit.NewLayer(&ratelimit.Config{Enabled: true})
	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})

	a := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}

	err = a.AddRateLimit(map[string]any{
		"id":     "rl-test",
		"scope":  "ip",
		"limit":  100,
		"window": "1m",
		"action": "block",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test invalid window
	err = a.AddRateLimit(map[string]any{
		"id":     "rl-bad",
		"scope":  "ip",
		"limit":  100,
		"window": "invalid",
		"action": "block",
	})
	if err == nil {
		t.Error("expected error for invalid window")
	}

	// Test invalid rule format (string instead of map)
	err = a.AddRateLimit("not-a-map")
	if err == nil {
		t.Error("expected error for invalid rule format")
	}
}

func TestMCPAdapter_RemoveRateLimit_WithLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true

	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	rlLayer := ratelimit.NewLayer(&ratelimit.Config{Enabled: true})
	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})

	a := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}

	err = a.RemoveRateLimit("nonexistent-rule")
	if err == nil {
		t.Error("expected error for nonexistent rule")
	}
}

func TestMCPAdapter_AddRateLimit_NoLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	a := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = a.AddRateLimit(map[string]any{"id": "test"})
	if err == nil {
		t.Error("expected error when no rate limit layer")
	}
}

func TestMCPAdapter_RemoveRateLimit_NoLayer(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	a := &mcpEngineAdapter{engine: eng, cfg: cfg, eventStore: store}
	err = a.RemoveRateLimit("test")
	if err == nil {
		t.Error("expected error when no rate limit layer")
	}
}

// --- tenantManagerAdapter: UpdateTenant with *tenant.TenantUpdate ---

func TestTenantManagerAdapter_UpdateTenant_WithPtr(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	// Create a tenant first
	a.CreateTenant("test-tenant-ptr", "Test Tenant", []string{"example.com"}, nil)

	// Update using *tenant.TenantUpdate
	update := &tenant.TenantUpdate{
		Name:        "Updated Name",
		Description: "Updated Description",
	}
	err := a.UpdateTenant("test-tenant-ptr", update)
	_ = err
}

// --- tenantManagerAdapter: UpdateTenant with domains in map ---

func TestTenantManagerAdapter_UpdateTenant_WithDomains(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	a.CreateTenant("test-tenant-dom", "Test", []string{"example.com"}, nil)

	err := a.UpdateTenant("test-tenant-dom", map[string]any{
		"name":        "Updated",
		"description": "Updated desc",
		"domains":     []string{"new.example.com"},
	})
	_ = err
}

// --- billingManagerAdapter: with tenant that has invoices ---

func TestBillingManagerAdapter_WithInvoices(t *testing.T) {
	mgr := tenant.NewManager(100)
	bm := mgr.BillingManager()
	a := &billingManagerAdapter{bm: bm}

	mgr.CreateTenant("billed-tenant", "Billed", []string{"example.com"}, nil)

	invoices := a.GetAllInvoices()
	_ = invoices

	invoices = a.GetInvoices("billed-tenant")
	_ = invoices
}

// --- alertManagerAdapter: with alerts after creating tenant ---

func TestAlertManagerAdapter_WithTenant(t *testing.T) {
	mgr := tenant.NewManager(100)
	am := mgr.AlertManager()
	a := &alertManagerAdapter{am: am}

	mgr.CreateTenant("alerted-tenant", "Alerted", []string{"example.com"}, nil)

	alerts := a.GetRecentAlerts(time.Hour)
	_ = alerts
}

// --- compliance.NewEngine coverage ---

func TestComplianceEngine_NewEngine(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Compliance.Enabled = true
	cfg.Compliance.Frameworks = []string{"pci_dss", "gdpr"}

	compEngine := compliance.NewEngine(cfg.Compliance)
	if compEngine == nil {
		t.Error("expected non-nil compliance engine")
	}
}

// --- runMain help command paths ---

func TestRunMain_HelpFlag_Long(t *testing.T) {
	code := runMain([]string{"guardianwaf", "--help"})
	if code != 0 {
		t.Errorf("expected 0, got %d", code)
	}
}

func TestRunMain_HelpFlag_Short(t *testing.T) {
	code := runMain([]string{"guardianwaf", "-h"})
	if code != 0 {
		t.Errorf("expected 0, got %d", code)
	}
}

// --- access log text format coverage ---

func TestAccessLog_TextFormatCoverage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Logging.Format = "text"
	cfg.Logging.LogAllowed = true

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "default",
			Targets: []config.TargetConfig{
				{URL: ts.URL},
			},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "default"},
	}

	handler, _ := buildReverseProxy(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- loadConfig with compliance framework in config ---

func TestLoadConfig_ComplianceConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-compliance-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configContent := `
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
`
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	oldExit := osExit
	osExit = func(code int) { t.Fatalf("unexpected os.Exit(%d)", code) }
	defer func() { osExit = oldExit }()

	cfg := loadConfig(tmpFile.Name(), true)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// --- MCP adapter: GetEvents with full query params ---

func TestMCPAdapter_GetEvents_WithQuery(t *testing.T) {
	a := newCovAdapter2Helper(t)
	result, err := a.GetEvents(json.RawMessage(`{"action":"block","limit":10,"offset":0}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = result
}

// --- MCP adapter: TestRequest with custom method ---

func TestMCPAdapter_TestRequest_CustomMethod(t *testing.T) {
	a := newCovAdapter2Helper(t)
	result, err := a.TestRequest("POST", "/api/login", map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = result
}

// --- MCP adapter: GetCRSRules with phase > 0 and severity filter ---

func TestMCPAdapter_GetCRSRules_WithPhaseFilter(t *testing.T) {
	a := newCovAdapter2Helper(t)
	result, err := a.GetCRSRules(1, "critical")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["rules"]; !ok {
		t.Error("expected rules key")
	}
}

// --- helper: create adapter for coverage ---

func newCovAdapter2Helper(t *testing.T) *mcpEngineAdapter {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.VirtualPatch.Enabled = true
	cfg.WAF.APIValidation.Enabled = true
	cfg.WAF.ClientSide.Enabled = true
	cfg.WAF.DLP.Enabled = true
	cfg.TLS.HTTP3.Enabled = true
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}
	return &mcpEngineAdapter{
		engine:     eng,
		cfg:        cfg,
		eventStore: store,
		alertMgr:   nil,
	}
}
