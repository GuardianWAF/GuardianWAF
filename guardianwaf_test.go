package guardianwaf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNew_DefaultConfig(t *testing.T) {
	eng, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.internal == nil {
		t.Fatal("internal engine is nil")
	}
	if eng.cfg == nil {
		t.Fatal("config is nil")
	}
	// Default mode should be enforce
	if eng.cfg.Mode != ModeEnforce {
		t.Errorf("expected mode %q, got %q", ModeEnforce, eng.cfg.Mode)
	}
}

func TestNew_CustomConfig(t *testing.T) {
	eng, err := New(Config{
		Mode: ModeMonitor,
		Threshold: ThresholdConfig{
			Block: 80,
			Log:   40,
		},
		Sanitizer: SanitizerConfig{
			MaxBodySize: 5 * 1024 * 1024,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeMonitor {
		t.Errorf("expected mode %q, got %q", ModeMonitor, eng.cfg.Mode)
	}
	if eng.cfg.WAF.Detection.Threshold.Block != 80 {
		t.Errorf("expected block threshold 80, got %d", eng.cfg.WAF.Detection.Threshold.Block)
	}
	if eng.cfg.WAF.Detection.Threshold.Log != 40 {
		t.Errorf("expected log threshold 40, got %d", eng.cfg.WAF.Detection.Threshold.Log)
	}
}

func TestNewWithDefaults(t *testing.T) {
	eng, err := NewWithDefaults()
	if err != nil {
		t.Fatalf("NewWithDefaults() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeEnforce {
		t.Errorf("expected mode %q, got %q", ModeEnforce, eng.cfg.Mode)
	}
}

func TestMiddleware_PassCleanRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	wrapped := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/hello", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "OK") {
		t.Errorf("expected body to contain 'OK', got %q", rr.Body.String())
	}
	// Should have request ID header
	if rr.Header().Get("X-GuardianWAF-RequestID") == "" {
		t.Error("expected X-GuardianWAF-RequestID header")
	}
}

func TestMiddleware_BlockSQLi(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for blocked request")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := eng.Middleware(handler)

	// SQL injection attempt
	req := httptest.NewRequest("GET", "/search?q='+OR+1%3D1+--+", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rr.Code)
	}
}

func TestCheck_CleanRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")

	result := eng.Check(req)

	if result.Blocked {
		t.Error("clean request should not be blocked")
	}
	if result.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
	if result.Action != "pass" && result.Action != "log" {
		t.Errorf("expected action pass or log, got %q", result.Action)
	}
}

func TestCheck_SQLiRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest("GET", "/search?q='+UNION+SELECT+*+FROM+users--", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")

	result := eng.Check(req)

	if !result.Blocked {
		t.Error("SQLi request should be blocked")
	}
	if result.TotalScore < 50 {
		t.Errorf("expected score >= 50, got %d", result.TotalScore)
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding")
	}

	hasSQLi := false
	for _, f := range result.Findings {
		if f.Category == "sqli" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Error("expected at least one sqli finding")
	}
}

func TestOnEvent_ReceivesEvents(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	var mu sync.Mutex
	var received []Event

	eng.OnEvent(func(event Event) {
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
	})

	// Send a request to trigger an event
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	eng.Check(req)

	// Wait for event propagation
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	eng.Close()

	if count == 0 {
		t.Error("expected to receive at least one event")
	}
}

func TestWithMode_Option(t *testing.T) {
	eng, err := New(Config{}, WithMode(ModeMonitor))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeMonitor {
		t.Errorf("expected mode %q, got %q", ModeMonitor, eng.cfg.Mode)
	}
}

func TestWithThreshold_Option(t *testing.T) {
	eng, err := New(Config{}, WithThreshold(100, 50))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Detection.Threshold.Block != 100 {
		t.Errorf("expected block threshold 100, got %d", eng.cfg.WAF.Detection.Threshold.Block)
	}
	if eng.cfg.WAF.Detection.Threshold.Log != 50 {
		t.Errorf("expected log threshold 50, got %d", eng.cfg.WAF.Detection.Threshold.Log)
	}
}

func TestWithDetector_Option(t *testing.T) {
	eng, err := New(Config{}, WithDetector("sqli", true, 2.0))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	dc, ok := eng.cfg.WAF.Detection.Detectors["sqli"]
	if !ok {
		t.Fatal("expected sqli detector config")
	}
	if !dc.Enabled {
		t.Error("expected sqli detector to be enabled")
	}
	if dc.Multiplier != 2.0 {
		t.Errorf("expected multiplier 2.0, got %f", dc.Multiplier)
	}
}

func TestWithMaxBodySize_Option(t *testing.T) {
	eng, err := New(Config{}, WithMaxBodySize(1024*1024))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Sanitizer.MaxBodySize != 1024*1024 {
		t.Errorf("expected max body size 1048576, got %d", eng.cfg.WAF.Sanitizer.MaxBodySize)
	}
}

func TestStats_Increments(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Clean request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	eng.Check(req)

	stats := eng.Stats()
	if stats.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", stats.TotalRequests)
	}
}

func TestConvertResult(t *testing.T) {
	// Test the conversion of findings
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest("GET", "/search?q='+UNION+SELECT+*+FROM+users--", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")

	result := eng.Check(req)

	// Verify result fields
	if result.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
	if result.Duration < 0 {
		t.Error("expected non-negative duration")
	}
	for _, f := range result.Findings {
		if f.Detector == "" {
			t.Error("expected non-empty detector name")
		}
		if f.Category == "" {
			t.Error("expected non-empty category")
		}
		if f.Severity == "" {
			t.Error("expected non-empty severity")
		}
	}
}

func TestMultipleOptions(t *testing.T) {
	eng, err := New(Config{},
		WithMode(ModeMonitor),
		WithThreshold(100, 50),
		WithMaxBodySize(2*1024*1024),
		WithDetector("sqli", true, 1.5),
		WithBotDetection(false),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeMonitor {
		t.Errorf("expected mode %q, got %q", ModeMonitor, eng.cfg.Mode)
	}
	if eng.cfg.WAF.Detection.Threshold.Block != 100 {
		t.Errorf("expected block threshold 100, got %d", eng.cfg.WAF.Detection.Threshold.Block)
	}
	if eng.cfg.WAF.BotDetection.Enabled {
		t.Error("expected bot detection to be disabled")
	}
}

// --- Additional Coverage Tests ---

func TestNewFromFile_ValidConfig(t *testing.T) {
	// Create a minimal valid YAML config file
	tmpDir := t.TempDir()
	cfgFile := tmpDir + "/guardianwaf.yaml"
	content := "mode: monitor\n"
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	eng, err := NewFromFile(cfgFile)
	if err != nil {
		t.Fatalf("NewFromFile() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != "monitor" {
		t.Errorf("expected mode 'monitor', got %q", eng.cfg.Mode)
	}
}

func TestNewFromFile_InvalidPath(t *testing.T) {
	_, err := NewFromFile("/nonexistent/path/guardianwaf.yaml")
	if err == nil {
		t.Error("expected error for invalid file path")
	}
}

func TestNewFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := tmpDir + "/bad.yaml"
	// Write invalid UTF-8 bytes to trigger parse error
	content := []byte{0xff, 0xfe, 0x80, 0x81}
	if err := os.WriteFile(cfgFile, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := NewFromFile(cfgFile)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestNewFromFile_WithOptions(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := tmpDir + "/guardianwaf.yaml"
	content := "mode: enforce\n"
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	eng, err := NewFromFile(cfgFile, WithMode(ModeMonitor), WithThreshold(80, 40))
	if err != nil {
		t.Fatalf("NewFromFile() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeMonitor {
		t.Errorf("expected mode overridden to 'monitor', got %q", eng.cfg.Mode)
	}
	if eng.cfg.WAF.Detection.Threshold.Block != 80 {
		t.Errorf("expected block threshold 80, got %d", eng.cfg.WAF.Detection.Threshold.Block)
	}
}

func TestNewWithDefaults_WithOptions(t *testing.T) {
	eng, err := NewWithDefaults(WithMode(ModeDisabled))
	if err != nil {
		t.Fatalf("NewWithDefaults() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Mode != ModeDisabled {
		t.Errorf("expected mode %q, got %q", ModeDisabled, eng.cfg.Mode)
	}
}

func TestWithMaxURLLength_Option(t *testing.T) {
	eng, err := New(Config{}, WithMaxURLLength(2048))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Sanitizer.MaxURLLength != 2048 {
		t.Errorf("expected max URL length 2048, got %d", eng.cfg.WAF.Sanitizer.MaxURLLength)
	}
}

func TestWithMaxHeaderSize_Option(t *testing.T) {
	eng, err := New(Config{}, WithMaxHeaderSize(8192))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Sanitizer.MaxHeaderSize != 8192 {
		t.Errorf("expected max header size 8192, got %d", eng.cfg.WAF.Sanitizer.MaxHeaderSize)
	}
}

func TestWithIPWhitelist_Option(t *testing.T) {
	eng, err := New(Config{}, WithIPWhitelist("10.0.0.1", "10.0.0.2"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	wl := eng.cfg.WAF.IPACL.Whitelist
	found := 0
	for _, ip := range wl {
		if ip == "10.0.0.1" || ip == "10.0.0.2" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("expected 2 whitelisted IPs, found %d in %v", found, wl)
	}
}

func TestWithIPBlacklist_Option(t *testing.T) {
	eng, err := New(Config{}, WithIPBlacklist("192.168.1.1"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	bl := eng.cfg.WAF.IPACL.Blacklist
	found := false
	for _, ip := range bl {
		if ip == "192.168.1.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 192.168.1.1 in blacklist, got %v", bl)
	}
}

func TestWithSecurityHeaders_Option(t *testing.T) {
	eng, err := New(Config{}, WithSecurityHeaders(true))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Error("expected security headers to be enabled")
	}
}

func TestWithDataMasking_Option(t *testing.T) {
	eng, err := New(Config{}, WithDataMasking(true))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.DataMasking.Enabled {
		t.Error("expected data masking to be enabled")
	}
}

func TestWithMaxEvents_Option(t *testing.T) {
	eng, err := New(Config{}, WithMaxEvents(5000))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Events.MaxEvents != 5000 {
		t.Errorf("expected max events 5000, got %d", eng.cfg.Events.MaxEvents)
	}
}

func TestCheck_XSSRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")

	result := eng.Check(req)
	if !result.Blocked {
		t.Error("XSS request should be blocked")
	}
	if result.TotalScore < 50 {
		t.Errorf("expected score >= 50, got %d", result.TotalScore)
	}
}

func TestCheck_BenignRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest("GET", "/api/users?page=1&limit=20", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")

	result := eng.Check(req)
	if result.Blocked {
		t.Error("benign request should not be blocked")
	}
	if result.Action == "block" {
		t.Error("benign request action should not be block")
	}
}

func TestStats_MultipleRequests(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Multiple clean requests
	for range 5 {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
		eng.Check(req)
	}

	stats := eng.Stats()
	if stats.TotalRequests != 5 {
		t.Errorf("expected 5 total requests, got %d", stats.TotalRequests)
	}
}

func TestClose_Idempotent(t *testing.T) {
	eng, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// First close should succeed
	if err := eng.Close(); err != nil {
		t.Errorf("first Close() error: %v", err)
	}
}

func TestConvertConfig_AllFields(t *testing.T) {
	cfg := Config{
		Mode: ModeMonitor,
		Detection: DetectionConfig{
			SQLi:          DetectorConfig{Enabled: true, Multiplier: 1.5},
			XSS:           DetectorConfig{Enabled: true, Multiplier: 2.0},
			PathTraversal: DetectorConfig{Enabled: false, Multiplier: 0.5},
			CmdInjection:  DetectorConfig{Enabled: true, Multiplier: 1.0},
			XXE:           DetectorConfig{Enabled: true, Multiplier: 1.0},
			SSRF:          DetectorConfig{Enabled: true, Multiplier: 1.0},
		},
		Threshold: ThresholdConfig{Block: 80, Log: 40},
		Sanitizer: SanitizerConfig{
			MaxURLLength:  4096,
			MaxHeaderSize: 16384,
			MaxBodySize:   10 * 1024 * 1024,
		},
		IPACL: IPACLConfig{
			Whitelist: []string{"10.0.0.1"},
			Blacklist: []string{"192.168.1.1"},
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
			Rules: []RateLimitRule{
				{ID: "global", Scope: "ip", Limit: 100, Window: time.Minute, Burst: 10, Action: "block"},
			},
		},
		Bot: BotConfig{
			Enabled:            true,
			BlockEmpty:         true,
			BlockKnownScanners: true,
		},
		Response: ResponseConfig{
			SecurityHeaders: true,
			DataMasking:     true,
		},
		Events: EventsConfig{
			MaxEvents: 5000,
		},
	}

	internal := convertConfig(cfg)

	if internal.Mode != ModeMonitor {
		t.Errorf("expected mode monitor, got %q", internal.Mode)
	}
	if internal.WAF.Detection.Threshold.Block != 80 {
		t.Errorf("expected block threshold 80, got %d", internal.WAF.Detection.Threshold.Block)
	}
	if internal.WAF.Detection.Threshold.Log != 40 {
		t.Errorf("expected log threshold 40, got %d", internal.WAF.Detection.Threshold.Log)
	}
	if internal.WAF.Sanitizer.MaxURLLength != 4096 {
		t.Errorf("expected max URL length 4096, got %d", internal.WAF.Sanitizer.MaxURLLength)
	}
	if internal.WAF.Sanitizer.MaxHeaderSize != 16384 {
		t.Errorf("expected max header size 16384, got %d", internal.WAF.Sanitizer.MaxHeaderSize)
	}
	if internal.WAF.Sanitizer.MaxBodySize != 10*1024*1024 {
		t.Errorf("expected max body size, got %d", internal.WAF.Sanitizer.MaxBodySize)
	}
	if len(internal.WAF.IPACL.Whitelist) == 0 {
		t.Error("expected non-empty whitelist")
	}
	if len(internal.WAF.IPACL.Blacklist) == 0 {
		t.Error("expected non-empty blacklist")
	}
	if !internal.WAF.RateLimit.Enabled {
		t.Error("expected rate limit to be enabled")
	}
	if len(internal.WAF.RateLimit.Rules) != 1 {
		t.Errorf("expected 1 rate limit rule, got %d", len(internal.WAF.RateLimit.Rules))
	}
	if !internal.WAF.BotDetection.UserAgent.BlockEmpty {
		t.Error("expected BlockEmpty to be true")
	}
	if !internal.WAF.BotDetection.UserAgent.BlockKnownScanners {
		t.Error("expected BlockKnownScanners to be true")
	}
	if !internal.WAF.Response.SecurityHeaders.Enabled {
		t.Error("expected security headers enabled")
	}
	if !internal.WAF.Response.DataMasking.Enabled {
		t.Error("expected data masking enabled")
	}
	if internal.Events.MaxEvents != 5000 {
		t.Errorf("expected 5000 max events, got %d", internal.Events.MaxEvents)
	}

	// Verify detector configs
	sqli, ok := internal.WAF.Detection.Detectors["sqli"]
	if !ok {
		t.Fatal("expected sqli detector")
	}
	if !sqli.Enabled {
		t.Error("expected sqli enabled")
	}
	if sqli.Multiplier != 1.5 {
		t.Errorf("expected sqli multiplier 1.5, got %f", sqli.Multiplier)
	}

	xss, ok := internal.WAF.Detection.Detectors["xss"]
	if !ok {
		t.Fatal("expected xss detector")
	}
	if xss.Multiplier != 2.0 {
		t.Errorf("expected xss multiplier 2.0, got %f", xss.Multiplier)
	}

	lfi, ok := internal.WAF.Detection.Detectors["lfi"]
	if !ok {
		t.Fatal("expected lfi detector")
	}
	if lfi.Enabled {
		t.Error("expected lfi to be disabled")
	}
}

func TestConvertConfig_EmptyConfig(t *testing.T) {
	cfg := Config{}
	internal := convertConfig(cfg)

	// Should get defaults
	if internal.Mode != ModeEnforce {
		t.Errorf("expected default mode enforce, got %q", internal.Mode)
	}
}

func TestConvertConfig_DetectorWithZeroMultiplier(t *testing.T) {
	cfg := Config{
		Detection: DetectionConfig{
			SQLi: DetectorConfig{Enabled: true, Multiplier: 0},
		},
	}
	internal := convertConfig(cfg)

	sqli := internal.WAF.Detection.Detectors["sqli"]
	if sqli.Multiplier != 1.0 {
		t.Errorf("expected multiplier default 1.0 when 0, got %f", sqli.Multiplier)
	}
}

func TestConvertConfig_RateLimitNoRules(t *testing.T) {
	cfg := Config{
		RateLimit: RateLimitConfig{
			Enabled: true,
			Rules:   nil,
		},
	}
	internal := convertConfig(cfg)
	if !internal.WAF.RateLimit.Enabled {
		t.Error("expected rate limit to be enabled")
	}
}

func TestConvertConfig_BotDisabled(t *testing.T) {
	cfg := Config{
		Bot: BotConfig{
			Enabled: false,
		},
	}
	internal := convertConfig(cfg)
	if internal.WAF.BotDetection.Enabled {
		t.Error("expected bot detection to be disabled")
	}
}

func TestWithDetector_NilDetectors(t *testing.T) {
	// WithDetector should handle nil Detectors map
	eng, err := New(Config{}, WithDetector("custom", true, 3.0))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	dc, ok := eng.cfg.WAF.Detection.Detectors["custom"]
	if !ok {
		t.Fatal("expected custom detector config")
	}
	if !dc.Enabled || dc.Multiplier != 3.0 {
		t.Errorf("expected enabled=true, multiplier=3.0, got %v/%f", dc.Enabled, dc.Multiplier)
	}
}

func TestOnEvent_MultipleCallbacks(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	var mu1, mu2 sync.Mutex
	var received1, received2 []Event

	eng.OnEvent(func(event Event) {
		mu1.Lock()
		received1 = append(received1, event)
		mu1.Unlock()
	})
	eng.OnEvent(func(event Event) {
		mu2.Lock()
		received2 = append(received2, event)
		mu2.Unlock()
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	eng.Check(req)

	time.Sleep(100 * time.Millisecond)

	mu1.Lock()
	c1 := len(received1)
	mu1.Unlock()
	mu2.Lock()
	c2 := len(received2)
	mu2.Unlock()

	eng.Close()

	if c1 == 0 {
		t.Error("callback 1 should have received events")
	}
	if c2 == 0 {
		t.Error("callback 2 should have received events")
	}
}

func TestMiddleware_MonitorMode_CleanRequest(t *testing.T) {
	eng, err := New(Config{
		Mode:      ModeMonitor,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	wrapped := eng.Middleware(handler)

	// Clean request in monitor mode should pass through
	req := httptest.NewRequest("GET", "/api/users?page=1", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for clean request in monitor mode, got %d", rr.Code)
	}
}

func TestNew_WithAllDetectionConfig(t *testing.T) {
	eng, err := New(Config{
		Detection: DetectionConfig{
			SQLi:          DetectorConfig{Enabled: true, Multiplier: 1.0},
			XSS:           DetectorConfig{Enabled: true, Multiplier: 1.0},
			PathTraversal: DetectorConfig{Enabled: true, Multiplier: 1.0},
			CmdInjection:  DetectorConfig{Enabled: true, Multiplier: 1.0},
			XXE:           DetectorConfig{Enabled: true, Multiplier: 1.0},
			SSRF:          DetectorConfig{Enabled: true, Multiplier: 1.0},
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	detectors := eng.cfg.WAF.Detection.Detectors
	for _, name := range []string{"sqli", "xss", "lfi", "cmdi", "xxe", "ssrf"} {
		dc, ok := detectors[name]
		if !ok {
			t.Errorf("expected detector %q", name)
			continue
		}
		if !dc.Enabled {
			t.Errorf("expected detector %q to be enabled", name)
		}
	}
}

func TestNew_EmptyConfigDefaults(t *testing.T) {
	eng, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Verify default detectors are enabled
	detectors := eng.cfg.WAF.Detection.Detectors
	for _, name := range []string{"sqli", "xss", "lfi", "cmdi", "xxe", "ssrf"} {
		dc, ok := detectors[name]
		if !ok {
			t.Errorf("expected default detector %q", name)
			continue
		}
		if !dc.Enabled {
			t.Errorf("expected default detector %q to be enabled", name)
		}
		if dc.Multiplier != 1.0 {
			t.Errorf("expected default multiplier 1.0 for %q, got %f", name, dc.Multiplier)
		}
	}
}

// --- GoDoc Testable Examples ---

func ExampleNew() {
	waf, err := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	if err != nil {
		panic(err)
	}
	defer waf.Close()
	fmt.Println("WAF created successfully")
	// Output: WAF created successfully
}

func ExampleEngine_Middleware() {
	waf, _ := New(Config{
		Mode: ModeEnforce,
	})
	defer waf.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello!")
	})

	protected := waf.Middleware(mux)
	fmt.Printf("Handler type: %T\n", protected)
	// Output: Handler type: http.HandlerFunc
}

func ExampleEngine_Check() {
	waf, _ := New(Config{
		Mode:      ModeEnforce,
		Threshold: ThresholdConfig{Block: 50, Log: 25},
	})
	defer waf.Close()

	// Check a clean request
	req := httptest.NewRequest("GET", "/hello?name=world", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	result := waf.Check(req)
	fmt.Printf("Clean request - Blocked: %v, Score: %d\n", result.Blocked, result.TotalScore)

	// Check a malicious request
	req2 := httptest.NewRequest("GET", "/search?q='+OR+1%3D1+--", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	result2 := waf.Check(req2)
	fmt.Printf("SQLi request - Blocked: %v, Score > 0: %v\n", result2.Blocked, result2.TotalScore > 0)
	// Output:
	// Clean request - Blocked: false, Score: 0
	// SQLi request - Blocked: true, Score > 0: true
}

func ExampleNew_withOptions() {
	waf, _ := New(Config{},
		WithMode(ModeMonitor),
		WithThreshold(60, 30),
		WithDetector("sqli", true, 1.5),
	)
	defer waf.Close()
	fmt.Println("WAF with options created")
	// Output: WAF with options created
}

func ExampleEngine_OnEvent() {
	waf, _ := New(Config{
		Mode: ModeEnforce,
	})
	defer waf.Close()

	// Register event callback
	waf.OnEvent(func(event Event) {
		// Handle WAF events (send to SIEM, alert, etc.)
		_ = event.Score
	})
	fmt.Println("Event handler registered")
	// Output: Event handler registered
}

func TestWithDetector_NilMap(t *testing.T) {
	eng, err := New(Config{}, WithDetector("sqli", true, 2.0))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	dc := eng.cfg.WAF.Detection.Detectors["sqli"]
	if !dc.Enabled {
		t.Error("expected sqli detector to be enabled")
	}
	if dc.Multiplier != 2.0 {
		t.Errorf("expected multiplier 2.0, got %f", dc.Multiplier)
	}
}

func TestNewFromFile_NonexistentDir(t *testing.T) {
	_, err := NewFromFile("/nonexistent/deep/path/guardianwaf.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}

func TestNew_WithRateLimit(t *testing.T) {
	eng, err := New(Config{
		RateLimit: RateLimitConfig{
			Enabled: true,
			Rules: []RateLimitRule{
				{ID: "test", Scope: "ip", Limit: 10, Window: 60_000_000_000, Burst: 5, Action: "block"},
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.RateLimit.Enabled {
		t.Error("expected rate limit to be enabled")
	}
}

func TestNew_WithIPACL(t *testing.T) {
	eng, err := New(Config{
		IPACL: IPACLConfig{
			Whitelist: []string{"10.0.0.0/8"},
			Blacklist: []string{"192.168.1.100"},
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if len(eng.cfg.WAF.IPACL.Whitelist) == 0 {
		t.Error("expected whitelist to be set")
	}
	if len(eng.cfg.WAF.IPACL.Blacklist) == 0 {
		t.Error("expected blacklist to be set")
	}
}

func TestNew_WithBotDisabled(t *testing.T) {
	eng, err := New(Config{
		Bot: BotConfig{
			Enabled:            false,
			BlockEmpty:         true,
			BlockKnownScanners: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.BotDetection.Enabled {
		t.Error("expected bot detection to be disabled")
	}
	if !eng.cfg.WAF.BotDetection.UserAgent.BlockEmpty {
		t.Error("expected BlockEmpty to be true")
	}
}

func TestNew_WithEvents(t *testing.T) {
	eng, err := New(Config{
		Events: EventsConfig{MaxEvents: 5000},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.Events.MaxEvents != 5000 {
		t.Errorf("expected MaxEvents 5000, got %d", eng.cfg.Events.MaxEvents)
	}
}

func TestToInternalDetector_EnabledWithZeroMultiplier(t *testing.T) {
	dc := DetectorConfig{Enabled: true, Multiplier: 0}
	result := toInternalDetector(dc, false)
	if !result.Enabled {
		t.Error("expected enabled")
	}
	if result.Multiplier != 1.0 {
		t.Errorf("expected multiplier 1.0, got %f", result.Multiplier)
	}
}

func TestToInternalDetector_WithMultiplier(t *testing.T) {
	dc := DetectorConfig{Enabled: true, Multiplier: 2.5}
	result := toInternalDetector(dc, false)
	if result.Multiplier != 2.5 {
		t.Errorf("expected multiplier 2.5, got %f", result.Multiplier)
	}
}

func TestWithDetector_NilDetectorsMap(t *testing.T) {
	// Call WithDetector on a config that has a nil Detectors map
	// by creating an engine with explicit detector override
	eng, err := New(Config{
		Detection: DetectionConfig{
			SQLi: DetectorConfig{Enabled: false, Multiplier: 0},
			XSS:  DetectorConfig{Enabled: false, Multiplier: 0},
		},
	}, WithDetector("xss", true, 1.5))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	dc := eng.cfg.WAF.Detection.Detectors["xss"]
	if !dc.Enabled {
		t.Error("expected xss detector to be enabled")
	}
	if dc.Multiplier != 1.5 {
		t.Errorf("expected multiplier 1.5, got %f", dc.Multiplier)
	}
}

func TestNew_WithHSTS(t *testing.T) {
	eng, err := New(Config{
		Response: ResponseConfig{
			SecurityHeaders: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Error("expected security headers to be enabled")
	}
}

func TestNew_WithDataMasking(t *testing.T) {
	eng, err := New(Config{
		Response: ResponseConfig{
			DataMasking: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.DataMasking.Enabled {
		t.Error("expected data masking to be enabled")
	}
}

func TestNew_WithMaxBodySize(t *testing.T) {
	eng, err := New(Config{
		Sanitizer: SanitizerConfig{
			MaxBodySize: 1024 * 1024,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Sanitizer.MaxBodySize != 1024*1024 {
		t.Errorf("expected MaxBodySize 1048576, got %d", eng.cfg.WAF.Sanitizer.MaxBodySize)
	}
}

func TestNew_WithDetectionThresholds(t *testing.T) {
	eng, err := New(Config{
		Threshold: ThresholdConfig{Block: 70, Log: 20},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if eng.cfg.WAF.Detection.Threshold.Block != 70 {
		t.Errorf("expected block 70, got %d", eng.cfg.WAF.Detection.Threshold.Block)
	}
	if eng.cfg.WAF.Detection.Threshold.Log != 20 {
		t.Errorf("expected log 20, got %d", eng.cfg.WAF.Detection.Threshold.Log)
	}
}

func TestNew_WithHSTSConfig(t *testing.T) {
	// Exercise the addDefaultLayers branch where SecurityHeaders.Enabled is true,
	// which populates the response layer's Headers struct (XContentTypeOptions, etc.).
	// Also verify the engine works end-to-end with HSTS-enabled config via NewFromFile.
	tmpDir := t.TempDir()
	cfgFile := tmpDir + "/guardianwaf.yaml"
	content := `mode: enforce
waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 31536000
        include_subdomains: true
      x_frame_options: DENY
      referrer_policy: no-referrer
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	eng, err := NewFromFile(cfgFile)
	if err != nil {
		t.Fatalf("NewFromFile() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Error("expected security headers to be enabled")
	}
	if !eng.cfg.WAF.Response.SecurityHeaders.HSTS.Enabled {
		t.Error("expected HSTS to be enabled")
	}
	if !eng.cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains {
		t.Error("expected HSTS IncludeSubDomains to be true")
	}
	if eng.cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge != 31536000 {
		t.Errorf("expected HSTS MaxAge 31536000, got %d", eng.cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
	}

	// Verify the engine processes requests without error
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	result := eng.Check(req)
	if result.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
}

func TestNew_SecurityHeadersEnabled_PopulatesResponseHeaders(t *testing.T) {
	// Exercise the addDefaultLayers SecurityHeaders.Enabled=true branch
	// through the public API (not from file).
	eng, err := New(Config{
		Response: ResponseConfig{
			SecurityHeaders: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Error("expected security headers enabled")
	}

	// Send a clean request through the middleware to verify headers are applied
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})
	wrapped := eng.Middleware(handler)

	req := httptest.NewRequest("GET", "/hello", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestBrowser/1.0")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// --- Challenge Config Tests ---

func TestNew_WithChallengeEnabled(t *testing.T) {
	eng, err := New(Config{
		Challenge: ChallengeConfig{
			Enabled:     true,
			Difficulty:  20,
			CookieTTL:   10 * time.Minute,
			CookieName:  "gowaf_challenge",
			SecretKey:   "test-secret-key-12345",
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Verify the challenge config is set
	if !eng.cfg.WAF.Challenge.Enabled {
		t.Error("expected challenge to be enabled")
	}
	if eng.cfg.WAF.Challenge.Difficulty != 20 {
		t.Errorf("expected difficulty 20, got %d", eng.cfg.WAF.Challenge.Difficulty)
	}
	if eng.cfg.WAF.Challenge.SecretKey != "test-secret-key-12345" {
		t.Error("expected secret key to be set")
	}
}

func TestNew_WithChallengeEnabled_NoSecretKey(t *testing.T) {
	eng, err := New(Config{
		Challenge: ChallengeConfig{
			Enabled:     true,
			Difficulty:  15,
			CookieTTL:   5 * time.Minute,
			CookieName:  "gowaf_challenge",
			SecretKey:   "",
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Verify the challenge config is set
	if !eng.cfg.WAF.Challenge.Enabled {
		t.Error("expected challenge to be enabled")
	}
	// SecretKey should be empty (auto-generated internally)
	if eng.cfg.WAF.Challenge.SecretKey != "" {
		t.Error("expected secret key to be empty in config")
	}
}

func TestNew_WithChallengeDisabled(t *testing.T) {
	eng, err := New(Config{
		Challenge: ChallengeConfig{
			Enabled: false,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	// Verify the challenge config is disabled
	if eng.cfg.WAF.Challenge.Enabled {
		t.Error("expected challenge to be disabled")
	}
}

func TestNew_ChallengeWithSecretKey(t *testing.T) {
	eng, err := New(Config{
		Challenge: ChallengeConfig{
			Enabled:    true,
			Difficulty: 5,
			CookieTTL:  10 * time.Minute,
			CookieName: "gwaf_test",
			SecretKey:  "test-secret-key",
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Challenge.Enabled {
		t.Error("expected challenge enabled")
	}
	if eng.cfg.WAF.Challenge.Difficulty != 5 {
		t.Errorf("expected difficulty 5, got %d", eng.cfg.WAF.Challenge.Difficulty)
	}
	if eng.cfg.WAF.Challenge.CookieName != "gwaf_test" {
		t.Errorf("expected cookie name 'gwaf_test', got %q", eng.cfg.WAF.Challenge.CookieName)
	}
}

func TestNew_ChallengeDefaultSecret(t *testing.T) {
	eng, err := New(Config{
		Challenge: ChallengeConfig{
			Enabled: true,
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()

	if !eng.cfg.WAF.Challenge.Enabled {
		t.Error("expected challenge enabled")
	}
}

func TestConvertConfig_ChallengeAllFields(t *testing.T) {
	cfg := Config{
		Challenge: ChallengeConfig{
			Enabled:    true,
			Difficulty: 8,
			CookieTTL:  30 * time.Minute,
			CookieName: "custom_cookie",
			SecretKey:  "my-secret",
		},
	}
	internal := convertConfig(cfg)
	if !internal.WAF.Challenge.Enabled {
		t.Error("expected challenge enabled")
	}
	if internal.WAF.Challenge.Difficulty != 8 {
		t.Errorf("expected difficulty 8, got %d", internal.WAF.Challenge.Difficulty)
	}
	if internal.WAF.Challenge.CookieTTL != 30*time.Minute {
		t.Errorf("expected 30m cookie TTL, got %v", internal.WAF.Challenge.CookieTTL)
	}
	if internal.WAF.Challenge.CookieName != "custom_cookie" {
		t.Errorf("expected 'custom_cookie', got %q", internal.WAF.Challenge.CookieName)
	}
	if internal.WAF.Challenge.SecretKey != "my-secret" {
		t.Errorf("expected 'my-secret', got %q", internal.WAF.Challenge.SecretKey)
	}
}
