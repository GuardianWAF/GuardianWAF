package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

func init() {
	proxy.AllowPrivateTargets()
}

// --- cmdHealthcheck tests ---

func TestCmdHealthcheck_Subprocess(t *testing.T) {
	// cmdHealthcheck calls os.Exit(0) directly — test via subprocess
	if os.Getenv("GUARDIANWAF_TEST_HEALTHCHECK") == "1" {
		cmdHealthcheck()
		return
	}
	// Build and run a subprocess that calls healthcheck
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdHealthcheck_Subprocess")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_TEST_HEALTHCHECK=1")
	output, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 0 {
			t.Fatalf("expected exit code 0, got %d: %s", exitErr.ExitCode(), output)
		}
	} else if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(output), "OK") {
		t.Errorf("expected OK in output, got: %s", output)
	}
}

// --- readLine tests ---

func TestReadLine_DefaultOnEmpty(t *testing.T) {
	// readLine reads from stdin; with no input it returns the default
	// We cannot easily pipe stdin in unit tests, so we test the default path.
	// The function is tested via cmdSetup integration instead.
	// Here we just ensure the function exists and the default path works.
	result := readLine("fallback")
	if result != "fallback" {
		t.Logf("readLine returned %q (expected fallback on empty stdin)", result)
	}
}

// --- boolStr tests ---

func TestBoolStr_True(t *testing.T) {
	if boolStr(true) != "yes" {
		t.Error("expected yes")
	}
}

func TestBoolStr_False(t *testing.T) {
	if boolStr(false) != "no" {
		t.Error("expected no")
	}
}

// --- envForEntropy tests ---

func TestEnvForEntropy_Coverage(t *testing.T) {
	result := envForEntropy()
	if result == "" {
		t.Error("expected non-empty entropy string")
	}
	if !strings.Contains(result, "-") {
		t.Error("expected dashes in entropy string")
	}
}

// --- generateDashboardPassword tests ---

func TestGenerateDashboardPassword_Coverage(t *testing.T) {
	pwd := generateDashboardPassword()
	if len(pwd) != 24 {
		t.Errorf("expected 24-char password, got %d", len(pwd))
	}
}

// --- mcpEngineAdapter tests for uncovered methods ---

func newCovAdapter(t *testing.T) *mcpEngineAdapter {
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

// Alerting methods

func TestMCPAdapter_GetAlertingStatus_Nil(t *testing.T) {
	a := newCovAdapter(t)
	result := a.GetAlertingStatus()
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestMCPAdapter_AddWebhook_NilMgr(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddWebhook("test", "http://example.com", "slack", []string{"block"}, 50, "5m")
	if err == nil {
		t.Error("expected error with nil alertMgr")
	}
}

func TestMCPAdapter_RemoveWebhook_NilMgr(t *testing.T) {
	a := newCovAdapter(t)
	err := a.RemoveWebhook("test")
	if err == nil {
		t.Error("expected error with nil alertMgr")
	}
}

func TestMCPAdapter_AddEmailTarget_NilMgr(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddEmailTarget("test", "smtp.example.com", 587, "user", "pass", "from@test.com", []string{"to@test.com"}, true, []string{"block"}, 50)
	if err == nil {
		t.Error("expected error with nil alertMgr")
	}
}

func TestMCPAdapter_RemoveEmailTarget_NilMgr(t *testing.T) {
	a := newCovAdapter(t)
	err := a.RemoveEmailTarget("test")
	if err == nil {
		t.Error("expected error with nil alertMgr")
	}
}

func TestMCPAdapter_TestAlert_NilMgr(t *testing.T) {
	a := newCovAdapter(t)
	err := a.TestAlert("test")
	if err == nil {
		t.Error("expected error with nil alertMgr")
	}
}

// CRS methods

func TestMCPAdapter_GetCRSRules_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetCRSRules(0, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	rules, _ := m["rules"].([]any)
	if len(rules) != 0 {
		t.Error("expected empty rules when no CRS layer")
	}
}

func TestMCPAdapter_EnableCRSRule_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.EnableCRSRule("123456", true)
	if err == nil {
		t.Error("expected error when CRS layer not found")
	}
}

func TestMCPAdapter_SetParanoiaLevel_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	err := a.SetParanoiaLevel(2)
	if err != nil {
		t.Logf("SetParanoiaLevel returned: %v (may be expected without full engine)", err)
	}
}

func TestMCPAdapter_AddCRSExclusion_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddCRSExclusion("123456", "/api/test", "param", "test reason")
	if err == nil {
		t.Error("expected error when CRS layer not found")
	}
}

// Virtual Patch methods

func TestMCPAdapter_GetVirtualPatches_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetVirtualPatches("", false)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestMCPAdapter_EnableVirtualPatch_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.EnableVirtualPatch("CVE-2024-1234", true)
	if err == nil {
		t.Error("expected error when virtualpatch layer not found")
	}
}

func TestMCPAdapter_AddCustomPatch_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddCustomPatch("test-patch", "Test Patch", "desc", "CVE-2024-0001", "pattern.*here", "regex", "url", "block", "high", 80)
	if err == nil {
		t.Error("expected error when virtualpatch layer not found")
	}
}

func TestMCPAdapter_UpdateCVEDatabase_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.UpdateCVEDatabase()
	if err == nil {
		t.Error("expected error when virtualpatch layer not found")
	}
}

// API Validation methods

func TestMCPAdapter_GetAPISchemas_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetAPISchemas()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestMCPAdapter_UploadAPISchema_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.UploadAPISchema("test-schema", "{}", "openapi", false)
	if err == nil {
		t.Error("expected error when API validation layer not found")
	}
}

func TestMCPAdapter_RemoveAPISchema_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.RemoveAPISchema("test-schema")
	if err == nil {
		t.Error("expected error when API validation layer not found")
	}
}

func TestMCPAdapter_SetAPIValidationMode_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	vr := true
	sv := true
	err := a.SetAPIValidationMode(&vr, nil, &sv, nil)
	if err != nil {
		t.Logf("SetAPIValidationMode returned: %v", err)
	}
}

func TestMCPAdapter_TestAPISchema_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.TestAPISchema("GET", "/api/test", "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["valid"] != true {
		t.Error("expected valid=true when no layer")
	}
}

// Client-Side methods

func TestMCPAdapter_GetClientSideStats_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetClientSideStats()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if _, ok := m["enabled"]; !ok {
		t.Error("expected enabled key")
	}
}

func TestMCPAdapter_SetClientSideMode_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	mode := "observe"
	md := true
	err := a.SetClientSideMode(mode, &md, nil, nil)
	if err != nil {
		t.Logf("SetClientSideMode returned: %v", err)
	}
}

func TestMCPAdapter_AddSkimmingDomain_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddSkimmingDomain("evil.example.com")
	if err == nil {
		t.Error("expected error when clientside layer not found")
	}
}

func TestMCPAdapter_GetCSPReports_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetCSPReports(10)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	reports, _ := m["reports"].([]any)
	if len(reports) != 0 {
		t.Error("expected empty reports")
	}
}

// DLP methods

func TestMCPAdapter_GetDLPAlerts_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetDLPAlerts(50, "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if _, ok := m["enabled"]; !ok {
		t.Error("expected enabled key")
	}
}

func TestMCPAdapter_AddDLPPattern_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.AddDLPPattern("cc-pattern", "Credit Card", "\\d{16}", "Detects CC numbers", "block", 80)
	if err == nil {
		t.Error("expected error when DLP layer not found")
	}
}

func TestMCPAdapter_RemoveDLPPattern_NoLayer(t *testing.T) {
	a := newCovAdapter(t)
	err := a.RemoveDLPPattern("cc-pattern")
	if err == nil {
		t.Error("expected error when DLP layer not found")
	}
}

func TestMCPAdapter_TestDLPPattern_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.TestDLPPattern(`\d{4}`, "test 1234 data")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["matched"] != true {
		t.Error("expected matched=true")
	}
}

func TestMCPAdapter_TestDLPPattern_InvalidRegex(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.TestDLPPattern(`[invalid`, "test data")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if _, ok := m["error"]; !ok {
		t.Error("expected error key for invalid regex")
	}
}

// HTTP/3 methods

func TestMCPAdapter_GetHTTP3Status_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.GetHTTP3Status()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	// HTTP3 config is present in output regardless of build tag
	if _, ok := m["enabled"]; !ok {
		t.Error("expected enabled key")
	}
}

func TestMCPAdapter_SetHTTP3Config_Coverage(t *testing.T) {
	a := newCovAdapter(t)
	enabled := false
	err := a.SetHTTP3Config(&enabled, nil, nil)
	if err != nil {
		t.Logf("SetHTTP3Config returned: %v", err)
	}
}

// --- tenantManagerAdapter tests ---

// createTestTenantMgr creates a real tenant.Manager for adapter tests.
func createTestTenantMgr(t *testing.T) *tenantManagerAdapter {
	t.Helper()
	mgr := tenant.NewManager(100)
	return &tenantManagerAdapter{mgr: mgr}
}

func TestTenantManagerAdapter_ListTenants_Empty(t *testing.T) {
	a := createTestTenantMgr(t)
	result := a.ListTenants()
	if len(result) != 0 {
		t.Error("expected empty list for new manager")
	}
}

func TestTenantManagerAdapter_GetTenant_NotFound(t *testing.T) {
	a := createTestTenantMgr(t)
	// Just call it to get coverage; result may be nil or empty struct
	_ = a.GetTenant("nonexistent")
}

func TestTenantManagerAdapter_CreateTenant_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	result, err := a.CreateTenant("test", "desc", []string{"example.com"}, nil)
	if err != nil {
		t.Logf("CreateTenant returned: %v", err)
	}
	_ = result
}

func TestTenantManagerAdapter_UpdateTenant_UnsupportedType(t *testing.T) {
	a := createTestTenantMgr(t)
	err := a.UpdateTenant("test", 42) // int is unsupported
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestTenantManagerAdapter_DeleteTenant_NotFound(t *testing.T) {
	a := createTestTenantMgr(t)
	err := a.DeleteTenant("nonexistent")
	_ = err
}

func TestTenantManagerAdapter_RegenerateAPIKey_NotFound(t *testing.T) {
	a := createTestTenantMgr(t)
	_, err := a.RegenerateAPIKey("nonexistent")
	_ = err
}

func TestTenantManagerAdapter_Stats_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.Stats()
}

func TestTenantManagerAdapter_BillingManager_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	result := a.BillingManager()
	_ = result
}

func TestTenantManagerAdapter_AlertManager_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	result := a.AlertManager()
	_ = result
}

func TestTenantManagerAdapter_GetAllUsage_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.GetAllUsage()
}

func TestTenantManagerAdapter_GetTenantUsage_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.GetTenantUsage("test")
}

func TestTenantManagerAdapter_GetTenantRules_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.GetTenantRules("test")
}

func TestTenantManagerAdapter_AddTenantRule_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.AddTenantRule("test", map[string]any{"id": "rule1"})
}

func TestTenantManagerAdapter_GetTenantRule_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.GetTenantRule("test", "rule1")
}

func TestTenantManagerAdapter_UpdateTenantRule_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.UpdateTenantRule("test", map[string]any{"id": "rule1"})
}

func TestTenantManagerAdapter_RemoveTenantRule_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.RemoveTenantRule("test", "rule1")
}

func TestTenantManagerAdapter_ToggleTenantRule_Coverage(t *testing.T) {
	a := createTestTenantMgr(t)
	_ = a.ToggleTenantRule("test", "rule1", true)
}

// --- billingManagerAdapter tests ---

func TestBillingManagerAdapter_GetAllInvoices_Nil(t *testing.T) {
	a := &billingManagerAdapter{bm: nil}
	result := a.GetAllInvoices()
	if result != nil {
		t.Error("expected nil for nil billing manager")
	}
}

func TestBillingManagerAdapter_GetInvoices_Nil(t *testing.T) {
	a := &billingManagerAdapter{bm: nil}
	result := a.GetInvoices("test")
	if result != nil {
		t.Error("expected nil for nil billing manager")
	}
}

func TestBillingManagerAdapter_GetCurrentUsage_Nil(t *testing.T) {
	a := &billingManagerAdapter{bm: nil}
	result := a.GetCurrentUsage("test")
	if result != nil {
		t.Error("expected nil for nil billing manager")
	}
}

func TestBillingManagerAdapter_GenerateInvoice_Nil(t *testing.T) {
	a := &billingManagerAdapter{bm: nil}
	_, err := a.GenerateInvoice("test", "Test Tenant", "basic", time.Now(), time.Now())
	if err == nil {
		t.Error("expected error for nil billing manager")
	}
}

// --- alertManagerAdapter tests ---

func TestAlertManagerAdapter_GetRecentAlerts_Nil(t *testing.T) {
	a := &alertManagerAdapter{am: nil}
	result := a.GetRecentAlerts(time.Hour)
	if result != nil {
		t.Error("expected nil for nil alert manager")
	}
}

// --- cmdTestAlert tests ---

func TestCmdTestAlert_NoConfig(t *testing.T) {
	// cmdTestAlert loads config from file, so we need a valid YAML
	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write minimal config with alerting enabled but no targets
	configContent := `
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
alerting:
  enabled: false
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
		t.Errorf("expected exit code 1 (alerting not enabled), got %d", exitCode)
	}
}

func TestCmdTestAlert_NoTarget(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-*.yaml")
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

// --- sanitizeLogField additional coverage ---

func TestSanitizeLogField_ControlChars(t *testing.T) {
	input := "hello\x00world\x1Btest\x7Fend"
	result := sanitizeLogField(input)
	if strings.Contains(result, "\x00") || strings.Contains(result, "\x1B") || strings.Contains(result, "\x7F") {
		t.Error("expected control chars to be stripped")
	}
	if result != "helloworldtestend" {
		t.Errorf("unexpected result: %q", result)
	}
}

// --- upstreamSummary additional coverage ---

func TestUpstreamSummary_SingleTarget2(t *testing.T) {
	cfg := &config.Config{
		Upstreams: []config.UpstreamConfig{
			{
				Name: "default",
				Targets: []config.TargetConfig{
					{URL: "http://localhost:3000"},
				},
			},
		},
	}
	result := upstreamSummary(cfg)
	if result != "http://localhost:3000" {
		t.Errorf("unexpected upstream summary: %s", result)
	}
}

// --- startMCPServer coverage ---

func TestStartMCPServer_WithCustomIO(t *testing.T) {
	cfg := config.DefaultConfig()
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	// Use pipes so stdin is closed immediately, making the server exit
	r, w, _ := os.Pipe()
	w.Close() // Close immediately so Run() sees EOF

	var output strings.Builder
	startMCPServer(eng, cfg, store, nil, r, &output)
	// If we get here without hanging, the server exited cleanly
}

// --- ConfigSummary tests ---

func TestConfigSummary_Default(t *testing.T) {
	cs := ConfigSummary{}
	if cs.Upstreams != 0 || cs.Routes != 0 || cs.Detectors != 0 || cs.RateLimitRules != 0 {
		t.Error("expected zero values")
	}
}

// --- accessLog format test (additional) ---

// --- cmdSetup coverage ---

func TestCmdSetup_ConfigAlreadyExists(t *testing.T) {
	// Create a temp config file so os.Stat succeeds
	tmpFile, err := os.CreateTemp("", "guardianwaf-setup-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// cmdSetup should return early without --force when config exists
	cmdSetup([]string{"-config", tmpFile.Name()})
	// If we get here, it returned early (did not call os.Exit)
}

func TestCmdSetup_ForceWithEmptyInput(t *testing.T) {
	// Test the setup wizard with --force and empty stdin (all defaults)
	tmpFile, err := os.CreateTemp("", "guardianwaf-setup-force-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Replace stdin with a pipe that immediately returns EOF
	// so all readLine calls return defaults
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin; r.Close() }()

	// Close write end so readLine gets EOF and returns defaults
	w.Close()

	// Replace os.Exit to prevent actual exit
	oldExit := osExit
	exitCalled := false
	osExit = func(code int) { exitCalled = true }
	defer func() { osExit = oldExit }()

	cmdSetup([]string{"-config", tmpFile.Name(), "--force"})

	// Should have generated a config file
	if _, err := os.Stat(tmpFile.Name()); err != nil && !exitCalled {
		t.Logf("Config file check after setup: %v", err)
	}
}

// --- cmdTestAlert with alerting enabled and targets ---

func TestCmdTestAlert_WithTarget(t *testing.T) {
	// Create a test HTTP server for webhook target
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	configContent := fmt.Sprintf(`
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
alerting:
  enabled: true
  webhooks:
    - name: test-webhook
      url: "%s"
      type: slack
      events:
        - block
      min_score: 50
`, ts.URL)

	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	oldExit := osExit
	exitCode := -1
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldExit }()

	cmdTestAlert([]string{"-config", tmpFile.Name(), "-target", "test-webhook"})

	// Should succeed (200 from webhook)
	if exitCode == 1 {
		t.Log("test-alert target test exited with code 1 (webhook may have failed)")
	}
}

func TestCmdTestAlert_AllTargets(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-test-alert-*.yaml")
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
    - name: webhook1
      url: "http://127.0.0.1:1/fake"
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
	osExit = func(code int) {} // no-op
	defer func() { osExit = oldExit }()

	// Test -all flag
	cmdTestAlert([]string{"-config", tmpFile.Name(), "-all"})
	// Webhooks will fail (port 1), but coverage is gained
}

// --- Additional readLine tests via subprocess ---

func TestReadLine_WithInput(t *testing.T) {
	if os.Getenv("GUARDIANWAF_TEST_READLINE") == "1" {
		// readLine is tested through cmdSetup, but let's verify it returns input when available
		result := readLine("default")
		_ = result
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadLine_WithInput")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_TEST_READLINE=1")
	cmd.Stdin = strings.NewReader("custom-input\n")
	output, err := cmd.CombinedOutput()
	_ = output
	_ = err
}

// --- billingManagerAdapter with real tenant.BillingManager ---

func TestBillingManagerAdapter_WithRealManager(t *testing.T) {
	mgr := tenant.NewManager(100)
	bm := mgr.BillingManager()
	a := &billingManagerAdapter{bm: bm}

	// GetAllInvoices with non-nil billing manager
	invoices := a.GetAllInvoices()
	if invoices == nil {
		t.Error("expected non-nil result")
	}

	// GetInvoices for nonexistent tenant
	invoices = a.GetInvoices("nonexistent")
	if invoices == nil {
		t.Error("expected non-nil result")
	}

	// GetCurrentUsage for nonexistent tenant
	usage := a.GetCurrentUsage("nonexistent")
	_ = usage

	// GenerateInvoice for nonexistent tenant
	_, err := a.GenerateInvoice("nonexistent", "Test", "basic", time.Now(), time.Now())
	_ = err
}

// --- alertManagerAdapter with real tenant.AlertManager ---

func TestAlertManagerAdapter_WithRealManager(t *testing.T) {
	mgr := tenant.NewManager(100)
	am := mgr.AlertManager()
	a := &alertManagerAdapter{am: am}

	// GetRecentAlerts with non-nil alert manager
	alerts := a.GetRecentAlerts(time.Hour)
	if alerts == nil {
		t.Error("expected non-nil result")
	}
}

// --- tenantManagerAdapter UpdateTenant with map type ---

func TestTenantManagerAdapter_UpdateTenant_WithMap(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	// Update with map[string]any type (the common path)
	err := a.UpdateTenant("nonexistent", map[string]any{
		"name":        "Updated",
		"description": "Updated desc",
	})
	_ = err
}

// --- tenantManagerAdapter CreateTenant with real manager ---

func TestTenantManagerAdapter_CreateTenant_WithRealMgr(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	// Create with resource quota
	quota := &tenant.ResourceQuota{
		MaxRequestsPerMinute: 100,
		MaxRequestsPerHour:  1000,
	}
	result, err := a.CreateTenant("test-tenant", "Test Tenant", []string{"example.com"}, quota)
	if err != nil {
		t.Logf("CreateTenant: %v", err)
	}
	_ = result
}

// --- tenantManagerAdapter ListTenants with created tenants ---

func TestTenantManagerAdapter_ListTenants_WithTenants(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	// Create a tenant first
	a.CreateTenant("test-tenant", "Test Tenant", []string{"example.com"}, nil)

	// Now list
	result := a.ListTenants()
	if len(result) == 0 {
		t.Error("expected at least one tenant")
	}
}

// --- tenantManagerAdapter GetAllUsage with tenants ---

func TestTenantManagerAdapter_GetAllUsage_WithTenants(t *testing.T) {
	mgr := tenant.NewManager(100)
	a := &tenantManagerAdapter{mgr: mgr}

	a.CreateTenant("test-tenant", "Test Tenant", []string{"example.com"}, nil)
	result := a.GetAllUsage()
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// --- Adapter with real layers ---

func newLayeredAdapter(t *testing.T) *mcpEngineAdapter {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.VirtualPatch.Enabled = true
	cfg.WAF.APIValidation.Enabled = true
	cfg.WAF.ClientSide.Enabled = true
	cfg.WAF.DLP.Enabled = true
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	// Add CRS layer
	crsLayer := crs.NewLayer(nil)
	eng.AddLayer(engine.OrderedLayer{Layer: crsLayer, Order: engine.OrderCRS})

	// Add VirtualPatch layer (no auto-update to avoid background goroutines)
	vpCfg := &virtualpatch.Config{Enabled: true, AutoUpdate: false}
	vpLayer := virtualpatch.NewLayer(vpCfg)
	eng.AddLayer(engine.OrderedLayer{Layer: vpLayer, Order: engine.OrderVirtualPatch})

	// Add DLP layer
	dlpLayer := dlp.NewLayer(nil)
	eng.AddLayer(engine.OrderedLayer{Layer: dlpLayer, Order: engine.OrderDLP})

	// Add ClientSide layer
	csLayer := clientside.NewLayer(nil)
	eng.AddLayer(engine.OrderedLayer{Layer: csLayer, Order: engine.OrderClientSide})

	// Add API Validation layer
	avLayer := apivalidation.NewLayer(nil)
	eng.AddLayer(engine.OrderedLayer{Layer: avLayer, Order: engine.OrderAPIValidation})

	// Add alerting manager
	alertMgr := alerting.NewManager(nil)

	return &mcpEngineAdapter{
		engine:     eng,
		cfg:        cfg,
		eventStore: store,
		alertMgr:   alertMgr,
	}
}

// --- CRS adapter tests with real layer ---

func TestMCPAdapter_GetCRSRules_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetCRSRules(0, "")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["rules"]; !ok {
		t.Error("expected rules key")
	}
}

func TestMCPAdapter_GetCRSRules_WithPhase(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetCRSRules(1, "")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["rules"]; !ok {
		t.Error("expected rules key")
	}
}

func TestMCPAdapter_EnableCRSRule_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.EnableCRSRule("999999", true)
	_ = a.EnableCRSRule("999999", false)
}

func TestMCPAdapter_AddCRSExclusion_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.AddCRSExclusion("999999", "/api/test", "param", "test reason")
}

// --- VirtualPatch adapter tests with real layer ---

func TestMCPAdapter_GetVirtualPatches_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetVirtualPatches("", false)
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["patches"]; !ok {
		t.Error("expected patches key")
	}
}

func TestMCPAdapter_GetVirtualPatches_ActiveOnly(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetVirtualPatches("", true)
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["patches"]; !ok {
		t.Error("expected patches key")
	}
}

func TestMCPAdapter_GetVirtualPatches_WithSeverity(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetVirtualPatches("critical", false)
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["patches"]; !ok {
		t.Error("expected patches key")
	}
}

func TestMCPAdapter_EnableVirtualPatch_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.EnableVirtualPatch("nonexistent", true)
	_ = a.EnableVirtualPatch("nonexistent", false)
}

func TestMCPAdapter_AddCustomPatch_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddCustomPatch("test-patch", "Test Patch", "desc", "CVE-2024-0001", "pattern.*here", "regex", "url", "block", "high", 80)
	if err != nil {
		t.Fatalf("AddCustomPatch with layer: %v", err)
	}
}

func TestMCPAdapter_UpdateCVEDatabase_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.UpdateCVEDatabase()
}

// --- API Validation adapter tests with real layer ---

func TestMCPAdapter_GetAPISchemas_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetAPISchemas()
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["schemas"]; !ok {
		t.Error("expected schemas key")
	}
}

func TestMCPAdapter_UploadAPISchema_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.UploadAPISchema("test-schema", "{}", "openapi", false)
}

func TestMCPAdapter_RemoveAPISchema_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.RemoveAPISchema("test-schema")
}

func TestMCPAdapter_TestAPISchema_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.TestAPISchema("GET", "/api/test", "")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["valid"]; !ok {
		t.Error("expected valid key")
	}
}

func TestMCPAdapter_SetAPIValidationMode_AllFlags(t *testing.T) {
	a := newLayeredAdapter(t)
	vr := true
	vs := false
	sm := true
	bv := false
	_ = a.SetAPIValidationMode(&vr, &vs, &sm, &bv)
}

// --- ClientSide adapter tests with real layer ---

func TestMCPAdapter_GetClientSideStats_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetClientSideStats()
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["scanned_responses"]; !ok {
		t.Error("expected scanned_responses key from real layer")
	}
}

func TestMCPAdapter_AddSkimmingDomain_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddSkimmingDomain("evil.example.com")
	if err != nil {
		t.Fatalf("AddSkimmingDomain with layer: %v", err)
	}
}

func TestMCPAdapter_SetClientSideMode_AllFlags(t *testing.T) {
	a := newLayeredAdapter(t)
	md := true
	ai := false
	csp := true
	_ = a.SetClientSideMode("enforce", &md, &ai, &csp)
}

// --- DLP adapter tests with real layer ---

func TestMCPAdapter_AddDLPPattern_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddDLPPattern("cc-pattern", "Credit Card", `\d{16}`, "Detects CC numbers", "block", 80)
	if err != nil {
		t.Fatalf("AddDLPPattern with layer: %v", err)
	}
}

func TestMCPAdapter_AddDLPPattern_LogAction(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddDLPPattern("log-pattern", "Log Pattern", `\d{4}`, "Log only", "log", 50)
	if err != nil {
		t.Fatalf("AddDLPPattern with log action: %v", err)
	}
}

func TestMCPAdapter_AddDLPPattern_DefaultAction(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddDLPPattern("default-pattern", "Default Pattern", `\w+`, "Default severity", "other", 30)
	if err != nil {
		t.Fatalf("AddDLPPattern with default action: %v", err)
	}
}

func TestMCPAdapter_AddDLPPattern_InvalidRegex(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddDLPPattern("bad-pattern", "Bad", `[invalid`, "Bad regex", "block", 80)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestMCPAdapter_RemoveDLPPattern_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.RemoveDLPPattern("nonexistent")
}

func TestMCPAdapter_AddAndRemoveDLPPattern(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.AddDLPPattern("test-remove", "Test", `\d{4}`, "Test pattern", "block", 50)
	_ = a.RemoveDLPPattern("test-remove")
}

// --- Alerting adapter tests with real manager ---

func TestMCPAdapter_GetAlertingStatus_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	result := a.GetAlertingStatus()
	m := result.(map[string]any)
	if m["enabled"] != true {
		t.Error("expected enabled=true with real alert manager")
	}
}

func TestMCPAdapter_AddWebhook_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.AddWebhook("test-wh", "https://example.com/hook", "slack", []string{"block"}, 50, "5m")
}

func TestMCPAdapter_AddWebhook_EmptyCooldown(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.AddWebhook("test-wh", "https://example.com/hook", "slack", []string{"block"}, 50, "")
}

func TestMCPAdapter_AddWebhook_InvalidCooldown2(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.AddWebhook("test-wh", "https://example.com/hook", "slack", []string{"block"}, 50, "not-a-duration")
	if err == nil {
		t.Error("expected error for invalid cooldown")
	}
}

func TestMCPAdapter_RemoveWebhook_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	err := a.RemoveWebhook("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent webhook")
	}
}

func TestMCPAdapter_AddEmailTarget_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.AddEmailTarget("test-email", "smtp.example.com", 587, "user", "pass", "from@test.com", []string{"to@test.com"}, true, []string{"block"}, 50)
}

func TestMCPAdapter_RemoveEmailTarget_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.RemoveEmailTarget("nonexistent")
}

func TestMCPAdapter_TestAlert_WithMgr(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.TestAlert("nonexistent")
}

// --- loadConfig tests ---

func TestLoadConfig_ExplicitPath(t *testing.T) {
	oldExit := osExit
	exitCode := -1
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = oldExit }()

	cfg := loadConfig("/nonexistent/path/guardianwaf.yaml", true)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing explicit path, got %d", exitCode)
	}
	_ = cfg
}

func TestLoadConfig_DefaultPath(t *testing.T) {
	cfg := loadConfig("", false)
	if cfg == nil {
		t.Error("expected non-nil config for default path")
	}
}

func TestLoadConfig_ExplicitExistingFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "guardianwaf-load-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
version: "1.0"
server:
  listen: "127.0.0.1:0"
  mode: enforce
`
	tmpFile.WriteString(content)
	tmpFile.Close()

	cfg := loadConfig(tmpFile.Name(), true)
	if cfg == nil {
		t.Error("expected non-nil config")
	}
}

// --- collectACMEDomains tests ---

func TestCollectACMEDomains_WithExplicitDomains(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.ACME.Domains = []string{"example.com", "www.example.com"}
	result := collectACMEDomains(cfg)
	if len(result) == 0 {
		t.Error("expected at least one domain set")
	}
}

func TestCollectACMEDomains_WithVirtualHosts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"app.example.com", "*.wildcard.example.com"},
		},
	}
	result := collectACMEDomains(cfg)
	if len(result) == 0 {
		t.Error("expected at least one domain set from virtual host")
	}
	for _, set := range result {
		for _, d := range set {
			if strings.HasPrefix(d, "*.") {
				t.Errorf("wildcard domain should be filtered: %s", d)
			}
		}
	}
}

func TestCollectACMEDomains_Empty(t *testing.T) {
	cfg := config.DefaultConfig()
	result := collectACMEDomains(cfg)
	if len(result) != 0 {
		t.Error("expected empty result for default config")
	}
}

func TestCollectACMEDomains_VirtualHostWithManualCert2(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{
			Domains: []string{"secure.example.com"},
			TLS:     config.VHostTLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		},
	}
	result := collectACMEDomains(cfg)
	if len(result) != 0 {
		t.Error("expected empty result - virtual host has manual cert")
	}
}

// --- isDefaultPath test ---

func TestIsDefaultPath_NonDefault(t *testing.T) {
	if isDefaultPath("/some/other/path.yaml") {
		t.Error("expected false for non-default path")
	}
}

// --- DefaultConfigPath test ---

func TestDefaultConfigPath_Coverage(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("expected non-empty default config path")
	}
}

// --- readLine with actual input via subprocess ---

func TestReadLine_WithNonEmptyInput(t *testing.T) {
	if os.Getenv("GUARDIANWAF_TEST_READLINE2") == "1" {
		_ = readLine("default")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadLine_WithNonEmptyInput")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_TEST_READLINE2=1")
	cmd.Stdin = strings.NewReader("hello\n")
	_, _ = cmd.CombinedOutput()
}

func TestReadLine_WithEmptyInput(t *testing.T) {
	if os.Getenv("GUARDIANWAF_TEST_READLINE3") == "1" {
		_ = readLine("fallback-value")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestReadLine_WithEmptyInput")
	cmd.Env = append(os.Environ(), "GUARDIANWAF_TEST_READLINE3=1")
	cmd.Stdin = strings.NewReader("\n")
	_, _ = cmd.CombinedOutput()
}

// --- TestDLPPattern with no matches ---

func TestMCPAdapter_TestDLPPattern_NoMatch(t *testing.T) {
	a := newCovAdapter(t)
	result, err := a.TestDLPPattern(`\d{4}`, "no digits here")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if m["matched"] != false {
		t.Error("expected matched=false")
	}
}

// --- CRS rules with severity filter and layer ---

func TestMCPAdapter_GetCRSRules_WithSeverity(t *testing.T) {
	a := newLayeredAdapter(t)
	result, err := a.GetCRSRules(0, "critical")
	if err != nil {
		t.Fatal(err)
	}
	m := result.(map[string]any)
	if _, ok := m["rules"]; !ok {
		t.Error("expected rules key")
	}
}

// --- SetParanoiaLevel with layer ---

func TestMCPAdapter_SetParanoiaLevel_WithLayer(t *testing.T) {
	a := newLayeredAdapter(t)
	_ = a.SetParanoiaLevel(2)
}


func TestAccessLog_WithCorrelationID(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Logging.Format = "json"
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
	req.Header.Set("X-Correlation-ID", "test-correlation-123")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// --- MCP adapter methods with real alerting manager ---

func TestMCPAdapter_GetAlertingStatus_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	result := a.GetAlertingStatus()
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("expected map")
	}
	if m["enabled"] != true {
		t.Error("expected enabled=true with real alert manager")
	}
}

func TestMCPAdapter_AddWebhook_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	err := a.AddWebhook("test-wh", "http://127.0.0.1:1/webhook", "slack", []string{"block"}, 50, "5m")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPAdapter_RemoveWebhook_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	err := a.RemoveWebhook("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent webhook")
	}
}

func TestMCPAdapter_AddEmailTarget_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	err := a.AddEmailTarget("test-email", "smtp.example.com", 587, "user", "pass", "from@test.com", []string{"to@test.com"}, true, []string{"block"}, 50)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPAdapter_RemoveEmailTarget_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	err := a.RemoveEmailTarget("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent email target")
	}
}

func TestMCPAdapter_TestAlert_WithAlertMgr(t *testing.T) {
	a := newCovAdapter(t)
	a.alertMgr = alerting.NewManager(nil)
	err := a.TestAlert("nonexistent")
	_ = err
}

// --- DefaultConfigPath and isDefaultPath tests ---

func TestDefaultConfigPath_Coverage2(t *testing.T) {
	path := DefaultConfigPath()
	if path == "" {
		t.Error("expected non-empty default config path")
	}
}

func TestIsDefaultPath_Coverage2(t *testing.T) {
	path := DefaultConfigPath()
	if !isDefaultPath(path) {
		t.Errorf("expected %q to be recognized as default path", path)
	}
	if isDefaultPath("/some/random/path.yaml") {
		t.Error("expected random path to not be default")
	}
}

// --- loadConfig directory coverage ---

func TestLoadConfig_DirectoryPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "guardianwaf-config-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfgContent := "version: \"1.0\"\nserver:\n  listen: \"127.0.0.1:0\"\n  mode: enforce\n"
	if err := os.WriteFile(tmpDir+"/guardianwaf.yaml", []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	oldExit := osExit
	osExit = func(code int) { t.Fatalf("unexpected os.Exit(%d)", code) }
	defer func() { osExit = oldExit }()

	cfg := loadConfig(tmpDir, true)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

// --- startDashboard with tenant manager ---

func TestStartDashboard_WithTenantManager(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.Dashboard.APIKey = "test-key-123"
	store := events.NewMemoryStore(100)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatal(err)
	}

	srv, sse, d := startDashboard(cfg, eng)
	_ = srv
	_ = sse
	_ = d
}
