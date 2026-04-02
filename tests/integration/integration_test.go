package integration

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// setupIntegrationEngine creates a fully-configured Engine with all layers
// for integration testing. Returns the engine and the ipacl layer.
func setupIntegrationEngine(t testing.TB) (*engine.Engine, *ipacl.Layer) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// IP ACL layer
	ipaclLayer, err := ipacl.NewLayer(ipacl.Config{
		Enabled: true,
		AutoBan: ipacl.AutoBanConfig{Enabled: true, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewIPACLLayer: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})

	// Rate limit layer
	rlLayer := ratelimit.NewLayer(ratelimit.Config{
		Enabled: true,
		Rules: []ratelimit.Rule{
			{ID: "global", Scope: "ip", Limit: 100, Window: time.Minute, Burst: 10, Action: "block"},
		},
	})
	eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})

	// Sanitizer layer
	sanLayer := newSanitizer()
	eng.AddLayer(engine.OrderedLayer{Layer: sanLayer, Order: engine.OrderSanitizer})

	// Detection layer (all detectors enabled)
	detLayer := newFullDetection()
	eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: engine.OrderDetection})

	// Bot detection layer (monitor mode)
	bdLayer := botdetect.NewLayer(botdetect.Config{
		Enabled: true,
		Mode:    "monitor",
		UserAgent: botdetect.UAConfig{
			Enabled:            true,
			BlockEmpty:         false,
			BlockKnownScanners: true,
		},
	})
	eng.AddLayer(engine.OrderedLayer{Layer: bdLayer, Order: engine.OrderBotDetect})

	// Response layer
	respLayer := response.NewLayer(response.Config{
		SecurityHeadersEnabled: true,
		ErrorPageMode:          "production",
	})
	eng.AddLayer(engine.OrderedLayer{Layer: respLayer, Order: engine.OrderResponse})

	return eng, ipaclLayer
}

func newSanitizer() *sanitizer.Layer {
	return sanitizer.NewLayer(sanitizer.Config{
		MaxURLLength:   8192,
		MaxHeaderSize:  8192,
		MaxHeaderCount: 100,
		MaxBodySize:    10 * 1024 * 1024,
		MaxCookieSize:  4096,
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
		BlockNullBytes: true,
		StripHopByHop:  true,
	})
}

func newFullDetection() *detection.Layer {
	return detection.NewLayer(detection.Config{
		Enabled: true,
		Detectors: map[string]detection.DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
			"xss":  {Enabled: true, Multiplier: 1.0},
			"lfi":  {Enabled: true, Multiplier: 1.0},
			"cmdi": {Enabled: true, Multiplier: 1.0},
			"xxe":  {Enabled: true, Multiplier: 1.0},
			"ssrf": {Enabled: true, Multiplier: 1.0},
		},
	})
}

// intgRequest creates a test HTTP request with common defaults.
// The target should have query values already URL-encoded via url.QueryEscape().
func intgRequest(method, target string) *http.Request {
	path, query, _ := strings.Cut(target, "?")

	reqURL := &url.URL{
		Scheme:   "http",
		Host:     "localhost",
		Path:     path,
		RawQuery: query,
	}

	req := &http.Request{
		Method:     method,
		URL:        reqURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       "localhost",
		RequestURI: reqURL.RequestURI(),
	}
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req
}

func TestIntegration_BenignRequestPassthrough(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	req := intgRequest("GET", "/hello?name=world")
	event := eng.Check(req)

	if event.Action == engine.ActionBlock {
		t.Errorf("benign request was blocked; score=%d, findings=%d", event.Score, len(event.Findings))
		for _, f := range event.Findings {
			t.Logf("  finding: %s - %s (score=%d)", f.DetectorName, f.Description, f.Score)
		}
	}

	stats := eng.Stats()
	if stats.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", stats.TotalRequests)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("expected 0 blocked requests, got %d", stats.BlockedRequests)
	}
}

func TestIntegration_SQLiBlocked(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	payloads := []string{
		"/search?q=" + url.QueryEscape("' OR 1=1 --"),
		"/search?q=" + url.QueryEscape("' UNION SELECT username,password FROM users --"),
		"/search?q=" + url.QueryEscape("1; DROP TABLE users --"),
	}

	for _, payload := range payloads {
		req := intgRequest("GET", payload)
		event := eng.Check(req)

		if event.Action != engine.ActionBlock {
			t.Errorf("SQLi payload not blocked: %s (action=%s, score=%d)",
				payload, event.Action, event.Score)
		}
	}
}

func TestIntegration_XSSBlocked(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	payloads := []string{
		"/page?q=" + url.QueryEscape("<script>alert(1)</script>"),
		"/page?q=" + url.QueryEscape("<img src=x onerror=alert(1)>"),
		"/page?q=" + url.QueryEscape("<svg onload=alert(1)>"),
	}

	for _, payload := range payloads {
		req := intgRequest("GET", payload)
		event := eng.Check(req)

		if event.Action != engine.ActionBlock {
			t.Errorf("XSS payload not blocked: %s (action=%s, score=%d)",
				payload, event.Action, event.Score)
		}
	}
}

func TestIntegration_LFIBlocked(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	type lfiCase struct {
		path  string
		param string
		value string
	}
	cases := []lfiCase{
		{"/file", "path", "/../../../etc/passwd"},
		{"/download", "file", "/proc/self/environ"},
		{"/page", "file", "/etc/shadow"},
	}

	payloads := make([]string, len(cases))
	for i, c := range cases {
		q := url.Values{}
		q.Set(c.param, c.value)
		payloads[i] = c.path + "?" + q.Encode()
	}

	for _, payload := range payloads {
		req := intgRequest("GET", payload)
		event := eng.Check(req)

		if event.Action != engine.ActionBlock {
			t.Errorf("LFI payload not blocked: %s (action=%s, score=%d)",
				payload, event.Action, event.Score)
		}
	}
}

func TestIntegration_CMDiBlocked(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	payloads := []string{
		"/run?cmd=" + url.QueryEscape(";cat /etc/passwd"),
		"/exec?cmd=" + url.QueryEscape("| whoami"),
		"/api?input=" + url.QueryEscape("$(id)"),
	}

	for _, payload := range payloads {
		req := intgRequest("GET", payload)
		event := eng.Check(req)

		if event.Action != engine.ActionBlock {
			t.Errorf("CMDi payload not blocked: %s (action=%s, score=%d)",
				payload, event.Action, event.Score)
		}
	}
}

func TestIntegration_BlacklistBlocked(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	ipaclLayer, err := ipacl.NewLayer(ipacl.Config{
		Enabled:   true,
		Blacklist: []string{"6.6.6.6"},
	})
	if err != nil {
		t.Fatalf("NewIPACLLayer: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})

	req := intgRequest("GET", "/hello")
	req.RemoteAddr = "6.6.6.6:12345"
	event := eng.Check(req)

	if event.Action != engine.ActionBlock {
		t.Errorf("blacklisted IP was not blocked; action=%s, score=%d", event.Action, event.Score)
	}
	if event.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", event.StatusCode)
	}
}

func TestIntegration_WhitelistBypass(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	ipaclLayer, err := ipacl.NewLayer(ipacl.Config{
		Enabled:   true,
		Whitelist: []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("NewIPACLLayer: %v", err)
	}
	eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})
	eng.AddLayer(engine.OrderedLayer{Layer: newSanitizer(), Order: engine.OrderSanitizer})
	eng.AddLayer(engine.OrderedLayer{Layer: newFullDetection(), Order: engine.OrderDetection})

	// Request from whitelisted IP with attack payload
	req := intgRequest("GET", "/search?q="+url.QueryEscape("' OR 1=1 --"))
	req.RemoteAddr = "10.0.0.1:12345"

	event := eng.Check(req)

	// Verify IP ACL did not block (no ipacl finding with blacklist description)
	for _, f := range event.Findings {
		if f.DetectorName == "ipacl" && f.Description == "IP is blacklisted" {
			t.Error("whitelisted IP was blocked by IP ACL")
		}
	}
}

func TestIntegration_ScoreAccumulation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000
	cfg.WAF.Detection.Threshold.Block = 80
	cfg.WAF.Detection.Threshold.Log = 20

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	eng.AddLayer(engine.OrderedLayer{Layer: newSanitizer(), Order: engine.OrderSanitizer})
	eng.AddLayer(engine.OrderedLayer{
		Layer: detection.NewLayer(detection.Config{
			Enabled: true,
			Detectors: map[string]detection.DetectorConfig{
				"sqli": {Enabled: true, Multiplier: 1.0},
				"xss":  {Enabled: true, Multiplier: 1.0},
				"cmdi": {Enabled: true, Multiplier: 1.0},
			},
		}),
		Order: engine.OrderDetection,
	})

	// Combined payload triggers multiple detectors; scores accumulate
	q := url.Values{}
	q.Set("a", "' OR 1=1 --")
	q.Set("b", "<script>alert(1)</script>")
	q.Set("c", ";cat /etc/passwd")
	req := intgRequest("GET", "/page?"+q.Encode())

	event := eng.Check(req)

	if event.Score == 0 {
		t.Error("expected accumulated score > 0 for combined attack payload")
	}
	if len(event.Findings) < 2 {
		t.Errorf("expected findings from multiple detectors, got %d", len(event.Findings))
	}
}

func TestIntegration_PathExclusion(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	cfg.Events.MaxEvents = 1000
	cfg.WAF.Detection.Exclusions = []config.ExclusionConfig{
		{Path: "/api/webhook", Detectors: []string{"sqli", "xss"}, Reason: "webhook payloads"},
	}

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	eng.AddLayer(engine.OrderedLayer{Layer: newSanitizer(), Order: engine.OrderSanitizer})
	eng.AddLayer(engine.OrderedLayer{
		Layer: detection.NewLayer(detection.Config{
			Enabled: true,
			Detectors: map[string]detection.DetectorConfig{
				"sqli": {Enabled: true, Multiplier: 1.0},
				"xss":  {Enabled: true, Multiplier: 1.0},
			},
			Exclusions: []detection.Exclusion{
				{PathPrefix: "/api/webhook", Detectors: []string{"sqli", "xss"}},
			},
		}),
		Order: engine.OrderDetection,
	})

	q := url.Values{}
	q.Set("q", "' OR 1=1 --")
	req := intgRequest("GET", "/api/webhook?"+q.Encode())
	event := eng.Check(req)

	for _, f := range event.Findings {
		if f.DetectorName == "sqli" || f.DetectorName == "xss" {
			t.Errorf("excluded path should not have %s findings", f.DetectorName)
		}
	}
}

func TestIntegration_ConcurrentRequests(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	paths := []string{
		"/hello?name=world",
		"/search?q=golang",
		"/page?id=42",
		"/search?q=" + url.QueryEscape("' OR 1=1 --"),
		"/page?q=" + url.QueryEscape("<script>alert(1)</script>"),
		"/api/data?format=json",
		"/download?file=report.pdf",
		"/run?cmd=" + url.QueryEscape(";cat /etc/passwd"),
		"/hello",
		"/about",
	}

	errCh := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			path := paths[idx%len(paths)]
			req := intgRequest("GET", path)
			event := eng.Check(req)
			if event == nil {
				errCh <- "got nil event"
				return
			}
			if event.RequestID == "" {
				errCh <- "got empty request ID"
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for errMsg := range errCh {
		t.Error(errMsg)
	}

	stats := eng.Stats()
	if stats.TotalRequests != int64(numGoroutines) {
		t.Errorf("expected %d total requests, got %d", numGoroutines, stats.TotalRequests)
	}
}

func TestIntegration_MiddlewareBenignPassthrough(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	backendCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	handler := eng.Middleware(backend)
	rec := httptest.NewRecorder()
	req := intgRequest("GET", "/hello?name=world")

	handler.ServeHTTP(rec, req)

	if !backendCalled {
		t.Error("backend was not called for benign request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestIntegration_MiddlewareAttackBlocked(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	backendCalled := false
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := eng.Middleware(backend)
	rec := httptest.NewRecorder()
	req := intgRequest("GET", "/search?q="+url.QueryEscape("' UNION SELECT username,password FROM users --"))

	handler.ServeHTTP(rec, req)

	if backendCalled {
		t.Error("backend was called for attack request - should have been blocked")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Request Blocked") {
		t.Error("expected block response body")
	}
}

func TestIntegration_EventSubscription(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	eventCh := make(chan engine.Event, 10)
	eng.EventBus().Subscribe(eventCh)

	req := intgRequest("GET", "/hello?name=test")
	eng.Check(req)

	select {
	case ev := <-eventCh:
		if ev.Method != "GET" {
			t.Errorf("expected method GET, got %s", ev.Method)
		}
		if ev.Path != "/hello" {
			t.Errorf("expected path /hello, got %s", ev.Path)
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for event")
	}
}

func TestIntegration_StatsTracking(t *testing.T) {
	eng, _ := setupIntegrationEngine(t)
	defer eng.Close()

	for i := 0; i < 5; i++ {
		req := intgRequest("GET", "/hello")
		eng.Check(req)
	}

	for i := 0; i < 3; i++ {
		req := intgRequest("GET", "/search?q="+url.QueryEscape("' OR 1=1 --"))
		eng.Check(req)
	}

	stats := eng.Stats()
	if stats.TotalRequests != 8 {
		t.Errorf("expected 8 total requests, got %d", stats.TotalRequests)
	}
	if stats.BlockedRequests == 0 {
		t.Error("expected some blocked requests")
	}
	if stats.BlockedRequests+stats.PassedRequests+stats.LoggedRequests != stats.TotalRequests {
		t.Errorf("stats don't add up: blocked=%d + passed=%d + logged=%d != total=%d",
			stats.BlockedRequests, stats.PassedRequests, stats.LoggedRequests, stats.TotalRequests)
	}
}
