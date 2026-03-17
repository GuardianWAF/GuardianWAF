package botdetect

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// newTestContext creates a minimal RequestContext for testing.
func newTestContext(ua string, clientIP string) *engine.RequestContext {
	headers := make(map[string][]string)
	if ua != "" {
		headers["User-Agent"] = []string{ua}
	}

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/test"},
			Header: http.Header{"User-Agent": {ua}},
		},
		Method:      "GET",
		Path:        "/test",
		URI:         "/test",
		Headers:     headers,
		QueryParams: make(map[string][]string),
		Cookies:     make(map[string]string),
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
		StartTime:   time.Now(),
	}

	if clientIP != "" {
		ctx.ClientIP = net.ParseIP(clientIP)
	}

	return ctx
}

// --- Fingerprint Lookup Tests ---

func TestLookupFingerprint_Known(t *testing.T) {
	info := LookupFingerprint("e7d705a3286e19ea42f587b344ee6865")
	if info.Category != FingerprintGood {
		t.Errorf("expected FingerprintGood, got %v", info.Category)
	}
	if info.Score != 0 {
		t.Errorf("expected score 0 for good fingerprint, got %d", info.Score)
	}
}

func TestLookupFingerprint_Bad(t *testing.T) {
	info := LookupFingerprint("e35df3e00ca4ef31d42b34bebaa2f86e")
	if info.Category != FingerprintBad {
		t.Errorf("expected FingerprintBad, got %v", info.Category)
	}
	if info.Score != 80 {
		t.Errorf("expected score 80, got %d", info.Score)
	}
}

func TestLookupFingerprint_Suspicious(t *testing.T) {
	info := LookupFingerprint("a0e9f5d64349fb13191bc781f81f42e1")
	if info.Category != FingerprintSuspicious {
		t.Errorf("expected FingerprintSuspicious, got %v", info.Category)
	}
	if info.Score != 40 {
		t.Errorf("expected score 40, got %d", info.Score)
	}
}

func TestLookupFingerprint_Unknown(t *testing.T) {
	info := LookupFingerprint("0000000000000000000000000000000")
	if info.Category != FingerprintUnknown {
		t.Errorf("expected FingerprintUnknown, got %v", info.Category)
	}
}

// --- User-Agent Analysis Tests ---

func TestAnalyzeUserAgent_Empty(t *testing.T) {
	score, desc := AnalyzeUserAgent("")
	if score != 40 {
		t.Errorf("expected score 40 for empty UA, got %d", score)
	}
	if desc == "" {
		t.Error("expected non-empty description")
	}
}

func TestAnalyzeUserAgent_KnownScanner(t *testing.T) {
	scanners := []string{
		"sqlmap/1.5#stable",
		"Nikto/2.1.6",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)",
		"nuclei - Open-source project",
	}

	for _, ua := range scanners {
		score, _ := AnalyzeUserAgent(ua)
		if score != 85 {
			t.Errorf("expected score 85 for scanner UA %q, got %d", ua, score)
		}
	}
}

func TestAnalyzeUserAgent_GoodBot(t *testing.T) {
	bots := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
	}

	for _, ua := range bots {
		score, _ := AnalyzeUserAgent(ua)
		if score != 0 {
			t.Errorf("expected score 0 for good bot UA %q, got %d", ua, score)
		}
	}
}

func TestAnalyzeUserAgent_UnknownBot(t *testing.T) {
	score, _ := AnalyzeUserAgent("MyCustomBot/1.0")
	if score != 30 {
		t.Errorf("expected score 30 for unknown bot, got %d", score)
	}
}

func TestAnalyzeUserAgent_NormalBrowser(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	score, _ := AnalyzeUserAgent(ua)
	if score != 0 {
		t.Errorf("expected score 0 for normal browser, got %d", score)
	}
}

func TestAnalyzeUserAgent_OutdatedBrowser(t *testing.T) {
	ua := "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
	score, _ := AnalyzeUserAgent(ua)
	if score != 25 {
		t.Errorf("expected score 25 for outdated browser, got %d", score)
	}
}

func TestAnalyzeUserAgent_LongUA(t *testing.T) {
	// Build a UA longer than 512 chars that does not match other patterns
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	for len(ua) < 520 {
		ua += " extension"
	}
	score, _ := AnalyzeUserAgent(ua)
	if score != 20 {
		t.Errorf("expected score 20 for excessively long UA, got %d", score)
	}
}

func TestAnalyzeUserAgent_CLI(t *testing.T) {
	score, _ := AnalyzeUserAgent("curl/7.68.0")
	if score != 15 {
		t.Errorf("expected score 15 for curl, got %d", score)
	}
}

// --- Behavioral Analysis Tests ---

func TestBehaviorManager_HighRPS(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       2,
		UniquePathsPerMin:  100,
		ErrorRateThreshold: 50,
		TimingStdDevMs:     1,
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.1"
	// Generate many requests in quick succession
	for i := 0; i < 50; i++ {
		bm.Record(ip, "/test", false, 100*time.Millisecond)
	}

	score, findings := bm.Analyze(ip)
	if score == 0 {
		t.Error("expected non-zero score for high RPS")
	}

	hasRPSFinding := false
	for _, f := range findings {
		if f == "high request rate detected" {
			hasRPSFinding = true
			break
		}
	}
	if !hasRPSFinding {
		t.Error("expected 'high request rate detected' finding")
	}
}

func TestBehaviorManager_HighErrorRate(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       1000,
		UniquePathsPerMin:  1000,
		ErrorRateThreshold: 30,
		TimingStdDevMs:     0, // disable timing check
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.2"
	// Generate requests with high error rate
	for i := 0; i < 10; i++ {
		isError := i < 8 // 80% error rate
		bm.Record(ip, "/test", isError, time.Duration(50+i)*time.Millisecond)
	}

	score, findings := bm.Analyze(ip)
	if score == 0 {
		t.Error("expected non-zero score for high error rate")
	}

	hasErrorFinding := false
	for _, f := range findings {
		if f == "high error rate detected" {
			hasErrorFinding = true
			break
		}
	}
	if !hasErrorFinding {
		t.Errorf("expected 'high error rate detected' finding, got %v", findings)
	}
}

func TestBehaviorManager_NoActivity(t *testing.T) {
	cfg := DefaultBehaviorConfig()
	bm := NewBehaviorManager(cfg)

	score, findings := bm.Analyze("10.0.0.99")
	if score != 0 {
		t.Errorf("expected score 0 for unknown IP, got %d", score)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unknown IP, got %v", findings)
	}
}

func TestBehaviorManager_Cleanup(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             1 * time.Second,
		RPSThreshold:       100,
		UniquePathsPerMin:  100,
		ErrorRateThreshold: 50,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	bm.Record("10.0.0.1", "/test", false, time.Millisecond)
	if bm.TrackerCount() != 1 {
		t.Errorf("expected 1 tracker, got %d", bm.TrackerCount())
	}

	// Note: in a real test we would advance time; here we just verify cleanup runs without error
	bm.Cleanup()
}

// --- Layer Integration Tests ---

func TestLayer_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	layer := NewLayer(cfg)

	ctx := newTestContext("sqlmap/1.0", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when layer disabled, got %v", result.Action)
	}
}

func TestLayer_KnownScanner(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false // Disable TLS for this test
	cfg.Behavior.Enabled = false
	layer := NewLayer(cfg)

	ctx := newTestContext("sqlmap/1.5#stable", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score for known scanner")
	}
	if result.Action == engine.ActionPass {
		t.Error("expected non-pass action for known scanner")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for known scanner")
	}
}

func TestLayer_NormalBrowser(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(cfg)

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	ctx := newTestContext(ua, "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for normal browser, got %v", result.Action)
	}
}

func TestLayer_EmptyUA(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.UserAgent.BlockEmpty = true
	layer := NewLayer(cfg)

	ctx := newTestContext("", "10.0.0.1")
	// Remove User-Agent from headers for empty test
	delete(ctx.Headers, "User-Agent")
	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score for empty UA")
	}
}

func TestLayer_MonitorMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "monitor"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(cfg)

	ctx := newTestContext("sqlmap/1.5", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog in monitor mode, got %v", result.Action)
	}
}

func TestLayer_Name(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	if layer.Name() != "botdetect" {
		t.Errorf("expected layer name 'botdetect', got %q", layer.Name())
	}
}

func TestFingerprintCategory_String(t *testing.T) {
	tests := []struct {
		cat      FingerprintCategory
		expected string
	}{
		{FingerprintGood, "good"},
		{FingerprintBad, "bad"},
		{FingerprintSuspicious, "suspicious"},
		{FingerprintUnknown, "unknown"},
	}

	for _, tc := range tests {
		if tc.cat.String() != tc.expected {
			t.Errorf("FingerprintCategory(%d).String() = %q, want %q", tc.cat, tc.cat.String(), tc.expected)
		}
	}
}

func TestAddRemoveFingerprint(t *testing.T) {
	hash := "test_hash_for_add_remove"
	AddFingerprint(hash, FingerprintInfo{Name: "test", Category: FingerprintBad, Score: 90})

	info := LookupFingerprint(hash)
	if info.Category != FingerprintBad {
		t.Errorf("expected FingerprintBad after add, got %v", info.Category)
	}

	RemoveFingerprint(hash)
	info = LookupFingerprint(hash)
	if info.Category != FingerprintUnknown {
		t.Errorf("expected FingerprintUnknown after remove, got %v", info.Category)
	}
}
