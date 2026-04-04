package botdetect

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

	ctx := newTestContext("sqlmap/1.5", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog in monitor mode, got %v", result.Action)
	}
}

func TestLayer_Name(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)
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

// --- Additional tests for uncovered code paths ---

func TestScoreToBehaviorSeverity(t *testing.T) {
	tests := []struct {
		score    int
		expected engine.Severity
	}{
		{100, engine.SeverityHigh},
		{80, engine.SeverityHigh},
		{60, engine.SeverityMedium},
		{40, engine.SeverityMedium},
		{30, engine.SeverityLow},
		{20, engine.SeverityLow},
		{10, engine.SeverityInfo},
		{0, engine.SeverityInfo},
	}
	for _, tt := range tests {
		got := scoreToBehaviorSeverity(tt.score)
		if got != tt.expected {
			t.Errorf("scoreToBehaviorSeverity(%d) = %v, want %v", tt.score, got, tt.expected)
		}
	}
}

func TestLayer_BehaviorMgr(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Behavior.Enabled = true
	layer := NewLayer(&cfg)

	bm := layer.BehaviorMgr()
	if bm == nil {
		t.Fatal("expected non-nil BehaviorManager when behavior enabled")
	}

	// Test with behavior disabled
	cfg2 := DefaultConfig()
	cfg2.Behavior.Enabled = false
	layer2 := NewLayer(&cfg2)
	bm2 := layer2.BehaviorMgr()
	if bm2 != nil {
		t.Fatal("expected nil BehaviorManager when behavior disabled")
	}
}

func TestTruncateUA(t *testing.T) {
	tests := []struct {
		ua     string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"abcde", 5, "abcde"},
		{"abcdefghij", 5, "ab..."},
		{"abcdefghij", 3, "abc"},
		{"abcdefghij", 2, "ab"},
		{"abcdefghij", 1, "a"},
	}
	for _, tt := range tests {
		got := truncateUA(tt.ua, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateUA(%q, %d) = %q, want %q", tt.ua, tt.maxLen, got, tt.want)
		}
	}
}

func TestLayer_ProcessWithBehavior(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = true
	cfg.Behavior.RPSThreshold = 1 // very low threshold
	cfg.Behavior.Window = 5 * time.Second
	layer := NewLayer(&cfg)

	// Simulate many requests to trigger behavior detection
	for i := 0; i < 50; i++ {
		ctx := newTestContext("Mozilla/5.0 Chrome", "192.168.1.1")
		layer.Process(ctx)
	}

	// The next request should detect high RPS
	ctx := newTestContext("Mozilla/5.0 Chrome", "192.168.1.1")
	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score from behavior analysis")
	}
}

func TestLayer_ProcessWithNilClientIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = true
	layer := NewLayer(&cfg)

	ctx := newTestContext("Mozilla/5.0 Chrome", "")
	// ctx.ClientIP is nil
	result := layer.Process(ctx)
	// Should still work, just skip behavior analysis
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for normal browser with no IP, got %v", result.Action)
	}
}

func TestLayer_ProcessEnforceHighScore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	// Known scanner gets score 85 -> should block in enforce mode
	ctx := newTestContext("sqlmap/1.5", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("expected ActionBlock for high score scanner in enforce mode, got %v", result.Action)
	}
}

func TestLayer_ProcessEnforceMediumScore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	// Empty UA gets score 40 -> should challenge in enforce mode
	ctx := newTestContext("", "10.0.0.1")
	delete(ctx.Headers, "User-Agent")
	result := layer.Process(ctx)

	if result.Action != engine.ActionChallenge {
		t.Errorf("expected ActionChallenge for medium score in enforce mode, got %v", result.Action)
	}
}

func TestLayer_ProcessEnforceLowScore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	// CLI tool gets score 15 -> should log in enforce mode
	ctx := newTestContext("curl/7.68.0", "10.0.0.1")
	result := layer.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog for low score in enforce mode, got %v", result.Action)
	}
}

func TestLayer_EmptyUABlockDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.UserAgent.BlockEmpty = false
	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	delete(ctx.Headers, "User-Agent")
	result := layer.Process(ctx)

	// With BlockEmpty=false, empty UA should pass
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass with BlockEmpty=false, got %v", result.Action)
	}
}

func TestLayer_ProcessWithTLSFingerprint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = 771
	ctx.TLSCipherSuite = 49195
	result := layer.Process(ctx)

	// Unknown fingerprints return score 0, so action should be pass
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for unknown TLS fingerprint, got %v", result.Action)
	}
}

func TestLayer_AnalyzeTLSFingerprint_KnownBad(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false

	// Add a fingerprint that will match our test TLS params
	testFP := ComputeJA3(771, []uint16{49195}, nil, nil, nil)
	AddFingerprint(testFP.Hash, FingerprintInfo{Name: "test-bad", Category: FingerprintBad, Score: 80})
	defer RemoveFingerprint(testFP.Hash)

	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = 771
	ctx.TLSCipherSuite = 49195
	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score for known bad TLS fingerprint")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for known bad TLS fingerprint")
	}
}

func TestLayer_AnalyzeTLSFingerprint_KnownSuspicious(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false

	testFP := ComputeJA3(772, []uint16{49196}, nil, nil, nil)
	AddFingerprint(testFP.Hash, FingerprintInfo{Name: "test-sus", Category: FingerprintSuspicious, Score: 40})
	defer RemoveFingerprint(testFP.Hash)

	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = 772
	ctx.TLSCipherSuite = 49196
	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score for suspicious TLS fingerprint")
	}
}

func TestLayer_AnalyzeTLSFingerprint_KnownGood(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false

	testFP := ComputeJA3(773, []uint16{49197}, nil, nil, nil)
	AddFingerprint(testFP.Hash, FingerprintInfo{Name: "test-good", Category: FingerprintGood, Score: 0})
	defer RemoveFingerprint(testFP.Hash)

	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = 773
	ctx.TLSCipherSuite = 49197
	result := layer.Process(ctx)

	// Good fingerprint with score 0 should pass
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for known good TLS fingerprint, got %v", result.Action)
	}
}

func TestBehaviorTracker_AdvanceLargeElapsed(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       100,
		UniquePathsPerMin:  100,
		ErrorRateThreshold: 50,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.50"
	bm.Record(ip, "/test", false, time.Millisecond)

	// Force a large time advance by sleeping briefly and then recording again
	// The advance function should handle ticks > size correctly
	tracker := bm.getOrCreate(ip)
	tracker.mu.Lock()
	// Simulate large time jump
	tracker.lastTick = time.Now().Add(-10 * time.Second)
	tracker.mu.Unlock()

	bm.Record(ip, "/test2", false, time.Millisecond)
	// Should not panic
}

func TestBehaviorManager_CleanupRemovesOld(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             1 * time.Millisecond,
		RPSThreshold:       100,
		UniquePathsPerMin:  100,
		ErrorRateThreshold: 50,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	bm.Record("10.0.0.1", "/test", false, time.Millisecond)
	if bm.TrackerCount() != 1 {
		t.Fatalf("expected 1 tracker, got %d", bm.TrackerCount())
	}

	// Manually set lastTick to the past to simulate old tracker
	tracker := bm.getOrCreate("10.0.0.1")
	tracker.mu.Lock()
	tracker.lastTick = time.Now().Add(-10 * time.Second)
	tracker.mu.Unlock()

	bm.Cleanup()

	if bm.TrackerCount() != 0 {
		t.Fatalf("expected 0 trackers after cleanup, got %d", bm.TrackerCount())
	}
}

func TestBehaviorManager_ConcurrentAccess(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       100,
		UniquePathsPerMin:  100,
		ErrorRateThreshold: 50,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	done := make(chan struct{})
	// Concurrent recording from multiple goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			ip := "10.0.0.1"
			for j := 0; j < 100; j++ {
				bm.Record(ip, "/path", false, time.Millisecond)
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not panic and should have recorded
	score, _ := bm.Analyze("10.0.0.1")
	_ = score // just verify no panic
}

func TestBehaviorManager_TimingStdDevLow(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       1000,
		UniquePathsPerMin:  1000,
		ErrorRateThreshold: 100,
		TimingStdDevMs:     100, // Very high threshold to ensure machine-like detection
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.5"
	// Record many requests with very consistent timing (low stddev)
	for i := 0; i < 20; i++ {
		bm.Record(ip, "/test", false, 50*time.Millisecond)
	}

	score, findings := bm.Analyze(ip)
	hasTimingFinding := false
	for _, f := range findings {
		if f == "machine-like request timing detected" {
			hasTimingFinding = true
			break
		}
	}
	if !hasTimingFinding {
		t.Errorf("expected 'machine-like request timing detected', got score=%d findings=%v", score, findings)
	}
}

func TestTimingStdDev_Empty(t *testing.T) {
	result := timingStdDev(nil)
	if result != 0 {
		t.Fatalf("expected 0 for empty timings, got %f", result)
	}
}

func TestTimingStdDev_SingleValue(t *testing.T) {
	result := timingStdDev([]time.Duration{100 * time.Millisecond})
	if result != 0 {
		t.Fatalf("expected 0 for single timing, got %f", result)
	}
}

func TestAnalyzeUserAgent_Wget(t *testing.T) {
	score, _ := AnalyzeUserAgent("wget/1.21")
	if score != 15 {
		t.Errorf("expected score 15 for wget, got %d", score)
	}
}

func TestAnalyzeUserAgent_LibwwwPerl(t *testing.T) {
	score, _ := AnalyzeUserAgent("libwww-perl/6.67")
	if score != 15 {
		t.Errorf("expected score 15 for libwww-perl, got %d", score)
	}
}

func TestAnalyzeUserAgent_Spider(t *testing.T) {
	score, _ := AnalyzeUserAgent("MySpider/1.0")
	if score != 30 {
		t.Errorf("expected score 30 for unknown spider, got %d", score)
	}
}

func TestAnalyzeUserAgent_Crawler(t *testing.T) {
	score, _ := AnalyzeUserAgent("MyCrawler/1.0")
	if score != 30 {
		t.Errorf("expected score 30 for unknown crawler, got %d", score)
	}
}

func TestLayer_UAHighScore_Severity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	// Scanner gets score 85 => SeverityHigh
	ctx := newTestContext("sqlmap/1.5", "10.0.0.1")
	result := layer.Process(ctx)

	found := false
	for _, f := range result.Findings {
		if f.DetectorName == "botdetect-ua" && f.Severity == engine.SeverityHigh {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SeverityHigh finding for scanner UA")
	}
}

func TestLayer_UAMediumScore_Severity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	// Empty UA gets score 40 => SeverityMedium
	ctx := newTestContext("", "10.0.0.1")
	delete(ctx.Headers, "User-Agent")
	result := layer.Process(ctx)

	found := false
	for _, f := range result.Findings {
		if f.DetectorName == "botdetect-ua" && f.Severity == engine.SeverityMedium {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SeverityMedium finding for empty UA")
	}
}

// --- Coverage gap tests for behavior.go ---

func TestBehaviorTracker_AnalyzeWindowLessThanOneSecond(t *testing.T) {
	// Covers the windowSecs < 1 branch in analyze.
	cfg := BehaviorConfig{
		Window:             500 * time.Millisecond, // less than 1 second
		RPSThreshold:       1,
		UniquePathsPerMin:  1000,
		ErrorRateThreshold: 0,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.100"
	for i := 0; i < 10; i++ {
		bm.Record(ip, "/test", false, time.Millisecond)
	}

	score, findings := bm.Analyze(ip)
	// With windowSecs clamped to 1, RPS = 10/1 = 10, threshold is 1 => should trigger
	if score == 0 {
		t.Errorf("expected non-zero score for sub-second window with high RPS, got %d", score)
	}
	hasRPS := false
	for _, f := range findings {
		if f == "high request rate detected" {
			hasRPS = true
			break
		}
	}
	if !hasRPS {
		t.Errorf("expected 'high request rate detected' finding, got %v", findings)
	}
}

func TestBehaviorTracker_AnalyzeHighErrorRateWithThreshold(t *testing.T) {
	// Covers the totalRequests > 0 && cfg.ErrorRateThreshold > 0 branch
	// with an error rate that exceeds the threshold.
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       0, // disable RPS check
		UniquePathsPerMin:  0, // disable path check
		ErrorRateThreshold: 20,
		TimingStdDevMs:     0, // disable timing check
	}
	bm := NewBehaviorManager(cfg)

	ip := "10.0.0.101"
	// 9 out of 10 requests are errors => 90% error rate
	for i := 0; i < 10; i++ {
		bm.Record(ip, "/test", i < 9, time.Millisecond)
	}

	score, findings := bm.Analyze(ip)
	if score == 0 {
		t.Errorf("expected non-zero score for high error rate, got %d", score)
	}
	hasError := false
	for _, f := range findings {
		if f == "high error rate detected" {
			hasError = true
			break
		}
	}
	if !hasError {
		t.Errorf("expected 'high error rate detected' finding, got %v", findings)
	}
}

func TestBehaviorManager_GetOrCreate_ConcurrentSameIP(t *testing.T) {
	// Hammers getOrCreate from multiple goroutines for the same IP
	// to increase probability of hitting the double-check path (line 218).
	cfg := BehaviorConfig{
		Window:             5 * time.Second,
		RPSThreshold:       1000,
		UniquePathsPerMin:  1000,
		ErrorRateThreshold: 100,
		TimingStdDevMs:     0,
	}
	bm := NewBehaviorManager(cfg)

	const goroutines = 50
	const ip = "10.0.0.200"

	start := make(chan struct{})
	done := make(chan *BehaviorTracker, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			<-start // wait for all goroutines to be ready
			tracker := bm.getOrCreate(ip)
			done <- tracker
		}()
	}

	// Release all goroutines at once to maximize contention
	close(start)

	var trackers []*BehaviorTracker
	for i := 0; i < goroutines; i++ {
		trackers = append(trackers, <-done)
	}

	// All goroutines should have gotten the same tracker instance
	for i := 1; i < len(trackers); i++ {
		if trackers[i] != trackers[0] {
			t.Fatal("expected all goroutines to return the same tracker instance")
		}
	}

	if bm.TrackerCount() != 1 {
		t.Errorf("expected exactly 1 tracker, got %d", bm.TrackerCount())
	}
}

// --- JA4 Fingerprint Tests ---

func TestLookupJA4Fingerprint_KnownGood(t *testing.T) {
	info := LookupJA4Fingerprint("t13d1516h2_8daaf6152771_e5627efa2ab1")
	if info.Category != FingerprintGood {
		t.Errorf("expected FingerprintGood, got %v", info.Category)
	}
	if info.Score != 0 {
		t.Errorf("expected score 0 for good JA4 fingerprint, got %d", info.Score)
	}
	if info.Name != "Chrome/Edge 120" {
		t.Errorf("expected Name 'Chrome/Edge 120', got %q", info.Name)
	}
}

func TestLookupJA4Fingerprint_KnownBad(t *testing.T) {
	info := LookupJA4Fingerprint("t12d0500_123456789abc_def456789abc")
	if info.Category != FingerprintBad {
		t.Errorf("expected FingerprintBad, got %v", info.Category)
	}
	if info.Score != 80 {
		t.Errorf("expected score 80 for bad JA4 fingerprint, got %d", info.Score)
	}
	if info.Name != "Python requests" {
		t.Errorf("expected Name 'Python requests', got %q", info.Name)
	}
}

func TestLookupJA4Fingerprint_Unknown(t *testing.T) {
	info := LookupJA4Fingerprint("t99d0000_unknown_unknown")
	if info.Category != FingerprintUnknown {
		t.Errorf("expected FingerprintUnknown, got %v", info.Category)
	}
	if info.Score != 0 {
		t.Errorf("expected score 0 for unknown JA4 fingerprint, got %d", info.Score)
	}
	if info.Name != "unknown" {
		t.Errorf("expected Name 'unknown', got %q", info.Name)
	}
}

func TestAddJA4Fingerprint(t *testing.T) {
	key := "test_ja4_custom_add"
	info := FingerprintInfo{
		Name:     "Test Custom Bot",
		Category: FingerprintBad,
		Score:    99,
	}

	AddJA4Fingerprint(key, info)
	defer RemoveJA4Fingerprint(key)

	got := LookupJA4Fingerprint(key)
	if got.Category != FingerprintBad {
		t.Errorf("expected FingerprintBad after add, got %v", got.Category)
	}
	if got.Score != 99 {
		t.Errorf("expected score 99 after add, got %d", got.Score)
	}
	if got.Name != "Test Custom Bot" {
		t.Errorf("expected Name 'Test Custom Bot' after add, got %q", got.Name)
	}
}

func TestRemoveJA4Fingerprint(t *testing.T) {
	key := "test_ja4_custom_remove"
	info := FingerprintInfo{
		Name:     "Test Remove",
		Category: FingerprintBad,
		Score:    75,
	}

	AddJA4Fingerprint(key, info)
	// Verify it was added
	got := LookupJA4Fingerprint(key)
	if got.Category != FingerprintBad {
		t.Fatalf("expected FingerprintBad after add, got %v", got.Category)
	}

	RemoveJA4Fingerprint(key)

	got = LookupJA4Fingerprint(key)
	if got.Category != FingerprintUnknown {
		t.Errorf("expected FingerprintUnknown after remove, got %v", got.Category)
	}
}

func TestAnalyzeTLSFingerprint_JA4Bad(t *testing.T) {
	// Compute a JA4 hash from known params, register it as bad, then verify Process() detects it.
	params := JA4Params{
		Protocol:     "t",
		TLSVersion:   0x0303,
		SNI:          false,
		CipherSuites: []uint16{0x002f, 0x0035},
		Extensions:   []uint16{0x0000, 0x0010, 0x0017},
		ALPN:         "h2",
	}
	ja4fp := ComputeJA4(params)

	AddJA4Fingerprint(ja4fp.Full, FingerprintInfo{
		Name:     "Test JA4 Bad Bot",
		Category: FingerprintBad,
		Score:    80,
	})
	defer RemoveJA4Fingerprint(ja4fp.Full)

	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = params.TLSVersion
	ctx.JA4Ciphers = params.CipherSuites
	ctx.JA4Exts = params.Extensions
	ctx.JA4ALPN = params.ALPN
	ctx.JA4Protocol = params.Protocol
	ctx.JA4SNI = params.SNI

	result := layer.Process(ctx)

	if result.Score == 0 {
		t.Error("expected non-zero score for known bad JA4 fingerprint")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for known bad JA4 fingerprint")
	}

	found := false
	for _, f := range result.Findings {
		if f.DetectorName == "botdetect-ja4" {
			found = true
			if f.Severity != engine.SeverityHigh {
				t.Errorf("expected SeverityHigh for bad JA4, got %v", f.Severity)
			}
			if f.Score != 80 {
				t.Errorf("expected finding score 80, got %d", f.Score)
			}
		}
	}
	if !found {
		t.Error("expected a botdetect-ja4 finding")
	}
}

func TestAnalyzeTLSFingerprint_JA4Good(t *testing.T) {
	// Compute a JA4 hash, register it as good (score 0), verify Process() passes.
	params := JA4Params{
		Protocol:     "t",
		TLSVersion:   0x0304,
		SNI:          true,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303},
		Extensions:   []uint16{0x0000, 0x0010, 0x0033},
		ALPN:         "h2",
	}
	ja4fp := ComputeJA4(params)

	AddJA4Fingerprint(ja4fp.Full, FingerprintInfo{
		Name:     "Test JA4 Good Browser",
		Category: FingerprintGood,
		Score:    0,
	})
	defer RemoveJA4Fingerprint(ja4fp.Full)

	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = params.TLSVersion
	ctx.JA4Ciphers = params.CipherSuites
	ctx.JA4Exts = params.Extensions
	ctx.JA4ALPN = params.ALPN
	ctx.JA4Protocol = params.Protocol
	ctx.JA4SNI = params.SNI

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for known good JA4 fingerprint, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 for known good JA4 fingerprint, got %d", result.Score)
	}
}

func TestAnalyzeTLSFingerprint_JA4Unknown(t *testing.T) {
	// JA4 that is not in the DB should fall through to the JA3 path.
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = true
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	layer := NewLayer(&cfg)

	ctx := newTestContext("", "10.0.0.1")
	ctx.TLSVersion = 0x0303
	ctx.TLSCipherSuite = 49199
	// Set JA4 ciphers to trigger JA4 path, but with values that won't match any DB entry
	ctx.JA4Ciphers = []uint16{0x00ff}
	ctx.JA4Exts = []uint16{0x00fe}
	ctx.JA4ALPN = "h2"
	ctx.JA4Protocol = "t"
	ctx.JA4SNI = false

	result := layer.Process(ctx)

	// Unknown JA4 falls through to JA3; JA3 hash for (0x0303, [49199]) is also unknown
	// so the result should be pass with score 0
	if result.Score != 0 {
		t.Errorf("expected score 0 for unknown JA4 that falls through to unknown JA3, got %d", result.Score)
	}
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for unknown JA4, got %v", result.Action)
	}
}
