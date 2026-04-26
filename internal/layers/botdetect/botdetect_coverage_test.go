package botdetect

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect/biometric"
)

// --- EnhancedLayer tests ---

func TestCoverage_EnhancedLayer_Name(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	l := NewEnhancedLayer(&cfg)
	if l.Name() != "botdetect-enhanced" {
		t.Errorf("Name() = %q, want %q", l.Name(), "botdetect-enhanced")
	}
}

func TestCoverage_EnhancedLayer_SnapshotConfig(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Mode = "monitor"
	l := NewEnhancedLayer(&cfg)
	snap := l.snapshotConfig()
	if snap.Mode != "monitor" {
		t.Errorf("snapshotConfig().Mode = %q, want %q", snap.Mode, "monitor")
	}
	if !snap.Enabled {
		t.Error("snapshotConfig().Enabled should be true")
	}
}

func TestCoverage_EnhancedLayer_Process_Disabled(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Enabled = false
	l := NewEnhancedLayer(&cfg)
	ctx := &engine.RequestContext{
		Headers: map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Process(disabled) action = %v, want Pass", result.Action)
	}
}

func TestCoverage_EnhancedLayer_Process_UAAnalysis(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	// Test with a known scanner User-Agent
	ctx := &engine.RequestContext{
		Headers: map[string][]string{
			"User-Agent": {"sqlmap/1.0"},
		},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	if result.Score == 0 {
		t.Error("Process(sqlmap UA) should produce non-zero score")
	}
	if len(result.Findings) == 0 {
		t.Error("Process(sqlmap UA) should produce findings")
	}
}

func TestCoverage_EnhancedLayer_Process_EmptyUA(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	ctx := &engine.RequestContext{
		Headers: map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	// Empty UA with BlockEmpty=true gives score 40, which in enforce mode results in Log
	if result.Score != 40 {
		t.Errorf("Process(empty UA) score = %d, want 40", result.Score)
	}
}

func TestCoverage_EnhancedLayer_Process_EnforceBlock(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	// Test with a known scanner User-Agent (high score)
	ctx := &engine.RequestContext{
		Headers: map[string][]string{
			"User-Agent": {"sqlmap/1.5"},
		},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Process(enforce+high score) action = %v, want Block", result.Action)
	}
}

func TestCoverage_EnhancedLayer_Process_EnforceChallenge(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Mode = "enforce"
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	cfg.Challenge.SiteKey = "test-site-key"
	cfg.Challenge.SecretKey = "test-secret-key"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	// Use an empty UA which gives score 40 (BlockEmpty=true) — in enforce mode
	// with challenge enabled, score >= 50 triggers challenge. With score 40,
	// the action should be Log (default for scores below 50).
	ctx := &engine.RequestContext{
		Headers: map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	// Empty UA should produce a score of 40
	if result.Score != 40 {
		t.Errorf("Process(empty UA) score = %d, want 40", result.Score)
	}
	if result.Action != engine.ActionLog {
		t.Errorf("Process(empty UA, enforce, score 40) action = %v, want Log", result.Action)
	}
}

func TestCoverage_EnhancedLayer_Process_MonitorMode(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Mode = "monitor"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	ctx := &engine.RequestContext{
		Headers: map[string][]string{
			"User-Agent": {"sqlmap/1.0"},
		},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	// Monitor mode should only log
	if result.Action != engine.ActionLog {
		t.Errorf("Process(monitor+scanner) action = %v, want Log", result.Action)
	}
}

func TestCoverage_EnhancedLayer_Process_TLSFingerprint(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	ctx := &engine.RequestContext{
		TLSVersion: tlsVersion12,
		Headers:    map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	// Should pass (analyzeTLSFingerprint returns 0, nil)
	if result.Action != engine.ActionPass {
		t.Errorf("Process(TLS fp) action = %v, want Pass", result.Action)
	}
}

func TestCoverage_EnhancedLayer_Process_Biometric(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.TLSFingerprint.Enabled = false
	cfg.UserAgent.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = true
	cfg.Biometric.MinEvents = 2
	l := NewEnhancedLayer(&cfg)

	// Create a session with enough events
	sessionID := "test-session-bio"
	session := &biometric.Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
	}
	session.MouseEvents = make([]biometric.MouseEvent, cfg.Biometric.MinEvents)
	l.sessions[sessionID] = session

	req := &http.Request{
		Header: http.Header{},
	}
	req.Header.Set("X-Session-ID", sessionID)

	ctx := &engine.RequestContext{
		Request:    req,
		Headers:    map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	result := l.Process(ctx)
	// Should run biometric analysis
	_ = result
}

func TestCoverage_EnhancedLayer_GetSession(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	l := NewEnhancedLayer(&cfg)

	// Test non-existent session
	s := l.getSession("nonexistent")
	if s != nil {
		t.Error("getSession(nonexistent) should return nil")
	}

	// Test valid session
	sessionID := "valid-session"
	session := &biometric.Session{
		ID:        sessionID,
		CreatedAt: time.Now(),
	}
	l.sessions[sessionID] = session
	s = l.getSession(sessionID)
	if s == nil {
		t.Error("getSession(valid) should return session")
	}

	// Test expired session
	expiredID := "expired-session"
	expiredSession := &biometric.Session{
		ID:        expiredID,
		CreatedAt: time.Now().Add(-time.Hour),
	}
	l.sessionTTL = 1 * time.Minute
	l.sessions[expiredID] = expiredSession
	s = l.getSession(expiredID)
	if s != nil {
		t.Error("getSession(expired) should return nil")
	}
}

func TestCoverage_EnhancedLayer_CleanupSessions(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	l := NewEnhancedLayer(&cfg)
	l.sessionTTL = 1 * time.Minute

	// Add a valid session
	l.sessions["valid"] = &biometric.Session{
		ID:        "valid",
		CreatedAt: time.Now(),
	}

	// Add an expired session
	l.sessions["expired"] = &biometric.Session{
		ID:        "expired",
		CreatedAt: time.Now().Add(-time.Hour),
	}

	l.CleanupSessions()

	if _, ok := l.sessions["valid"]; !ok {
		t.Error("valid session should still exist")
	}
	if _, ok := l.sessions["expired"]; ok {
		t.Error("expired session should be cleaned up")
	}
}

func TestCoverage_EnhancedLayer_VerifyCaptcha(t *testing.T) {
	// Test without challenge provider
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = false
	l := NewEnhancedLayer(&cfg)

	result, err := l.VerifyCaptcha("token", "1.2.3.4")
	if err != nil {
		t.Errorf("VerifyCaptcha(no provider) error = %v", err)
	}
	if result != nil {
		t.Error("VerifyCaptcha(no provider) should return nil result")
	}
}

func TestCoverage_EnhancedLayer_analyzeTLSFingerprint(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	l := NewEnhancedLayer(&cfg)
	ctx := &engine.RequestContext{
		Headers: map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	score, findings := l.analyzeTLSFingerprint(ctx)
	if score != 0 {
		t.Errorf("analyzeTLSFingerprint() score = %d, want 0", score)
	}
	if findings != nil {
		t.Errorf("analyzeTLSFingerprint() findings = %v, want nil", findings)
	}
}

func TestCoverage_EnhancedLayer_analyzeUA(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	l := NewEnhancedLayer(&cfg)

	tests := []struct {
		name       string
		ua         string
		wantScore  bool
	}{
		{"normal browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"scanner", "Nikto", true},
		{"empty", "", true}, // BlockEmpty=true in default config
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &engine.RequestContext{
				Headers: map[string][]string{},
				Accumulator: &engine.ScoreAccumulator{},
			}
			if tt.ua != "" {
				ctx.Headers["User-Agent"] = []string{tt.ua}
			}
			score, findings := l.analyzeUA(ctx)
			if (score > 0) != tt.wantScore {
				t.Errorf("analyzeUA(%s) score=%d, wantScore=%v", tt.name, score, tt.wantScore)
			}
			if score > 0 && len(findings) == 0 {
				t.Error("non-zero score should have findings")
			}
		})
	}
}

func TestCoverage_EnhancedLayer_analyzeBehavior(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Behavior.Enabled = true
	l := NewEnhancedLayer(&cfg)

	// Test without ClientIP
	ctx := &engine.RequestContext{
		Headers:    map[string][]string{},
		Accumulator: &engine.ScoreAccumulator{},
	}
	score, findings := l.analyzeBehavior(ctx)
	if score != 0 {
		t.Error("analyzeBehavior(no IP) should return 0")
	}
	if findings != nil {
		t.Error("analyzeBehavior(no IP) should return nil findings")
	}
}

func TestCoverage_ScoreToSeverity(t *testing.T) {
	tests := []struct {
		score    int
		expected engine.Severity
	}{
		{100, engine.SeverityHigh},
		{80, engine.SeverityHigh},
		{60, engine.SeverityMedium},
		{40, engine.SeverityMedium},
		{25, engine.SeverityLow},
		{10, engine.SeverityInfo},
		{0, engine.SeverityInfo},
	}
	for _, tt := range tests {
		result := scoreToSeverity(tt.score)
		if result != tt.expected {
			t.Errorf("scoreToSeverity(%d) = %v, want %v", tt.score, result, tt.expected)
		}
	}
}

// --- Challenge token tests ---

func TestCoverage_SignChallengeToken(t *testing.T) {
	// The token format uses "." as separator, so use an IP without dots for
	// predictable splitN behavior. The real code strips port brackets before signing.
	token := signChallengeToken("::1", time.Now().Add(time.Hour).Unix())
	if token == "" {
		t.Error("signChallengeToken returned empty string")
	}
}

func TestCoverage_VerifyChallengeToken(t *testing.T) {
	// Use simple IP without dots since the token format is "ip.expiry.hmac"
	// and SplitN(token, ".", 3) is used for parsing.
	ip := "::1"
	expiry := time.Now().Add(time.Hour).Unix()
	token := signChallengeToken(ip, expiry)

	// Valid token
	if !VerifyChallengeToken(token, ip) {
		t.Error("VerifyChallengeToken(valid) should return true")
	}

	// Wrong IP
	if VerifyChallengeToken(token, "::2") {
		t.Error("VerifyChallengeToken(wrong IP) should return false")
	}

	// Expired token
	expiredToken := signChallengeToken(ip, time.Now().Add(-time.Hour).Unix())
	if VerifyChallengeToken(expiredToken, ip) {
		t.Error("VerifyChallengeToken(expired) should return false")
	}

	// Malformed token (only 2 parts)
	if VerifyChallengeToken("not.valid", ip) {
		t.Error("VerifyChallengeToken(malformed) should return false")
	}

	// Empty token
	if VerifyChallengeToken("", ip) {
		t.Error("VerifyChallengeToken(empty) should return false")
	}

	// Non-numeric expiry
	if VerifyChallengeToken("ip.abc.def", ip) {
		t.Error("VerifyChallengeToken(non-numeric expiry) should return false")
	}

	// Wrong HMAC
	wrongHMAC := ip + "." + "9999999999" + ".deadbeef"
	if VerifyChallengeToken(wrongHMAC, ip) {
		t.Error("VerifyChallengeToken(wrong HMAC) should return false")
	}
}

// --- Collector handler coverage tests ---

func TestCoverage_ProcessMouseEvent_DefaultSubtype(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	// Test with unknown subtype (should return without recording)
	event := BiometricEvent{
		Type:    "mouse",
		Subtype: "unknown",
		X:       100,
		Y:       200,
	}
	collector.processMouseEvent("test-session", event)
	// Should not panic, no event recorded for unknown subtype
}

func TestCoverage_ProcessMouseEvent_AllSubtypes(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	subtypes := []string{"move", "click", "down", "up"}
	for _, subtype := range subtypes {
		event := BiometricEvent{
			Type:      "mouse",
			Subtype:   subtype,
			X:         100,
			Y:         200,
			Button:    0,
			Timestamp: time.Now(),
		}
		collector.processMouseEvent("session-"+subtype, event)
	}
}

func TestCoverage_ProcessKeyboardEvent_AllSubtypes(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	subtypes := []string{"down", "up", "press"}
	for _, subtype := range subtypes {
		event := BiometricEvent{
			Type:      "keyboard",
			Subtype:   subtype,
			Key:       "Shift",
			Code:      "ShiftLeft",
			Timestamp: time.Now(),
		}
		collector.processKeyboardEvent("session-"+subtype, event)
	}

	// Unknown subtype should be ignored
	event := BiometricEvent{
		Type:    "keyboard",
		Subtype: "unknown",
	}
	collector.processKeyboardEvent("session-unknown", event)
}

func TestCoverage_ProcessTouchEvent_AllSubtypes(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	subtypes := []string{"start", "move", "end"}
	for _, subtype := range subtypes {
		event := BiometricEvent{
			Type:      "touch",
			Subtype:   subtype,
			X:         100,
			Y:         200,
			Timestamp: time.Now(),
		}
		collector.processTouchEvent("session-"+subtype, event)
	}

	// Unknown subtype should be ignored
	event := BiometricEvent{
		Type:    "touch",
		Subtype: "unknown",
	}
	collector.processTouchEvent("session-unknown", event)
}

func TestCoverage_SanitizeKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Shift", "Shift"},
		{"Control", "Control"},
		{"Alt", "Alt"},
		{"Backspace", "Backspace"},
		{"Enter", "Enter"},
		{"Escape", "Escape"},
		{"Tab", "Tab"},
		{"F1", "F1"},
		{"F12", "F12"},
		{"ArrowUp", "ArrowUp"},
		{"a", "*"},
		{"A", "*"},
		{"0", "*"},
		{"", "*"},
		{"SomeRandomKey", "*"},
	}
	for _, tt := range tests {
		result := sanitizeKey(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeKey(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCoverage_HandleChallengeVerify_MissingToken(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	cfg.Challenge.SiteKey = "test-key"
	cfg.Challenge.SecretKey = "test-secret"
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	req := httptest.NewRequest(http.MethodPost, "/gwaf/challenge/verify", nil)
	w := httptest.NewRecorder()
	collector.HandleChallengeVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("HandleChallengeVerify(no token) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCoverage_HandleChallengeVerify_WrongMethod(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	req := httptest.NewRequest(http.MethodGet, "/gwaf/challenge/verify", nil)
	w := httptest.NewRecorder()
	collector.HandleChallengeVerify(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HandleChallengeVerify(GET) status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestCoverage_HandleChallengeVerify_WithToken(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	cfg.Challenge.SecretKey = "test-secret"
	cfg.Challenge.SiteKey = "test-site"
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	form := url.Values{}
	form.Set("token", "test-token-value")
	req := httptest.NewRequest(http.MethodPost, "/gwaf/challenge/verify", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Manually set form
	req.PostForm = form
	req.Form = form
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	collector.HandleChallengeVerify(w, req)

	// Should get a response (success or failure from verification)
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("HandleChallengeVerify(with token) status = %d", w.Code)
	}
}

// --- Behavior analysis edge cases ---

func TestCoverage_BehaviorManager_Record(t *testing.T) {
	bm := NewBehaviorManager(BehaviorConfig{
		Window:             60 * time.Second,
		RPSThreshold:       10,
		UniquePathsPerMin:  50,
		ErrorRateThreshold: 30,
		TimingStdDevMs:     10,
	})

	// Record events
	for i := range 20 {
		bm.Record("10.0.0.1", "/api/test", i%3 == 0, time.Duration(i*10)*time.Millisecond)
	}

	score, descs := bm.Analyze("10.0.0.1")
	_ = score
	_ = descs
}

func TestCoverage_BehaviorManager_GetOrCreate(t *testing.T) {
	bm := NewBehaviorManager(BehaviorConfig{
		Window: 60 * time.Second,
	})

	// First access creates the tracker
	tracker := bm.getOrCreate("192.168.1.1")
	if tracker == nil {
		t.Error("getOrCreate should create tracker")
	}

	// Second access returns existing
	tracker2 := bm.getOrCreate("192.168.1.1")
	if tracker != tracker2 {
		t.Error("getOrCreate should return same tracker")
	}
}

// --- Process scroll event ---

func TestCoverage_ProcessScrollEvent(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	event := BiometricEvent{
		Type:      "scroll",
		X:         0,
		Y:         100,
		DeltaX:    10,
		DeltaY:    20,
		Timestamp: time.Now(),
	}
	collector.processScrollEvent("scroll-session", event)
}

// --- HandleChallengePage coverage ---

func TestCoverage_HandleChallengePage_WrongMethod(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Challenge.Enabled = true
	cfg.Challenge.Provider = "hcaptcha"
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	req := httptest.NewRequest(http.MethodPost, "/gwaf/challenge", nil)
	w := httptest.NewRecorder()
	collector.HandleChallengePage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("HandleChallengePage(POST) status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- Process event dispatch ---

func TestCoverage_ProcessEvent_AllTypes(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	types := []string{"mouse", "keyboard", "scroll", "touch"}
	for _, typ := range types {
		event := BiometricEvent{
			Type:      typ,
			Subtype:   "move",
			X:         100,
			Y:         200,
			Timestamp: time.Now(),
		}
		collector.processEvent("session-"+typ, event)
	}

	// Unknown type should be silently ignored
	event := BiometricEvent{Type: "unknown"}
	collector.processEvent("session-unknown", event)
}

// --- HandleCollect edge cases ---

func TestCoverage_HandleCollect_SessionIDTooLong(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	// Create request with session ID > 128 chars
	longID := ""
	for i := 0; i < 200; i++ {
		longID += "x"
	}

	events := EventRequest{
		Events: []BiometricEvent{
			{Type: "mouse", Subtype: "move", X: 100, Y: 200, Timestamp: time.Now()},
		},
	}
	body, _ := json.Marshal(events)

	req := httptest.NewRequest(http.MethodPost, "/gwaf/collect", nil)
	req.Header.Set("X-Session-ID", longID)
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), nil, 1<<20)
	req.Body = &readCloser{data: body}
	w := httptest.NewRecorder()

	collector.HandleCollect(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("HandleCollect(long session ID) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCoverage_HandleCollect_InvalidJSON(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Biometric.Enabled = true
	l := NewEnhancedLayer(&cfg)
	collector := NewBiometricCollector(l)

	req := httptest.NewRequest(http.MethodPost, "/gwaf/collect", nil)
	req.Header.Set("X-Session-ID", "valid-session")
	req.Body = &readCloser{data: []byte("not json")}
	w := httptest.NewRecorder()

	collector.HandleCollect(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("HandleCollect(invalid JSON) status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// --- TLS fingerprint config constants ---

const tlsVersion12 = 0x0303

// --- Helper for splitting dot-separated tokens ---

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// --- readCloser wraps a byte slice as io.ReadCloser ---

type readCloser struct {
	data   []byte
	offset int
}

func (r *readCloser) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *readCloser) Close() error { return nil }

// --- Tenant WAF config integration ---

func TestCoverage_EnhancedLayer_Process_WithTenantConfig(t *testing.T) {
	cfg := DefaultEnhancedConfig()
	cfg.Mode = "enforce"
	cfg.TLSFingerprint.Enabled = false
	cfg.Behavior.Enabled = false
	cfg.BrowserFingerprint.Enabled = false
	cfg.Biometric.Enabled = false
	l := NewEnhancedLayer(&cfg)

	// Test with tenant WAF config
	tenantConfig := &config.WAFConfig{}
	ctx := &engine.RequestContext{
		Headers: map[string][]string{
			"User-Agent": {"sqlmap/1.0"},
		},
		Accumulator:     &engine.ScoreAccumulator{},
		TenantWAFConfig: tenantConfig,
	}
	result := l.Process(ctx)
	_ = result
}
