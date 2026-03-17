package guardianwaf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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
