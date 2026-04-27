package challenge

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Layer coverage (currently 0%) ---

func TestNewLayer_Cov(t *testing.T) {
	l, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil) failed: %v", err)
	}
	if l == nil {
		t.Fatal("expected layer, got nil")
	}
	// nil config => defaults to disabled
	if l.config.Enabled {
		t.Error("expected disabled with nil config")
	}
}

func TestNewLayer_WithConfig_Cov(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Difficulty: 8,
		CookieTTL:  3600000000000, // 1 hour
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		CookieName: "__gwaf_test",
	}
	l, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	if !l.config.Enabled {
		t.Error("expected enabled")
	}
}

func TestLayer_Name_Cov(t *testing.T) {
	l, _ := NewLayer(nil)
	if l.Name() != "js-challenge" {
		t.Errorf("Name() = %q, want %q", l.Name(), "js-challenge")
	}
}

func TestLayer_Order_Cov(t *testing.T) {
	l, _ := NewLayer(nil)
	if l.Order() != 430 {
		t.Errorf("Order() = %d, want 430", l.Order())
	}
}

func TestLayer_Process_Disabled_Cov(t *testing.T) {
	l, _ := NewLayer(nil)
	ctx := &engine.RequestContext{
		Request:  httptest.NewRequest("GET", "/", nil),
		ClientIP: net.ParseIP("127.0.0.1"),
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for disabled layer, got %v", result.Action)
	}
}

func TestLayer_Process_NilRequest_Cov(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		CookieName: "__gwaf_test",
	}
	l, _ := NewLayer(cfg)
	ctx := &engine.RequestContext{
		Request:  nil,
		ClientIP: net.ParseIP("127.0.0.1"),
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for nil request, got %v", result.Action)
	}
}

func TestLayer_Process_NoCookie_Cov(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		CookieName: "__gwaf_test",
	}
	l, _ := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Request:  httptest.NewRequest("GET", "/protected", nil),
		ClientIP: net.ParseIP("127.0.0.1"),
	}

	result := l.Process(ctx)
	if result.Action != engine.ActionChallenge {
		t.Errorf("expected challenge when no cookie, got %v", result.Action)
	}
	if result.Score != 40 {
		t.Errorf("expected score 40, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}
	if result.Findings[0].DetectorName != "js-challenge" {
		t.Errorf("detector = %q, want js-challenge", result.Findings[0].DetectorName)
	}
}

func TestLayer_Process_ValidCookie_Cov(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		CookieName: "__gwaf_test",
		CookieTTL:  3600000000000,
	}
	l, _ := NewLayer(cfg)

	ip := net.ParseIP("127.0.0.1")
	token := l.svc.generateToken(ip)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "__gwaf_test", Value: token})

	ctx := &engine.RequestContext{
		Request:  req,
		ClientIP: ip,
	}

	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with valid cookie, got %v", result.Action)
	}
}

func TestLayer_Service_Cov(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
	}
	l, _ := NewLayer(cfg)
	svc := l.Service()
	if svc == nil {
		t.Error("expected non-nil service")
	}
}

// --- DefaultConfigE coverage ---

func TestDefaultConfigE_Cov(t *testing.T) {
	cfg, err := DefaultConfigE()
	if err != nil {
		t.Fatalf("DefaultConfigE failed: %v", err)
	}
	if cfg.Difficulty != 20 {
		t.Errorf("expected difficulty 20, got %d", cfg.Difficulty)
	}
	if cfg.CookieName != "__gwaf_challenge" {
		t.Errorf("expected cookie name __gwaf_challenge, got %s", cfg.CookieName)
	}
}

// --- generateChallenge coverage ---

func TestGenerateChallenge_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey: []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
	})

	ch1, err := svc.generateChallenge()
	if err != nil {
		t.Fatalf("generateChallenge failed: %v", err)
	}
	if len(ch1) != 32 { // 16 bytes => 32 hex chars
		t.Errorf("expected 32-char challenge, got %d", len(ch1))
	}

	ch2, _ := svc.generateChallenge()
	if ch1 == ch2 {
		t.Error("challenges should be unique")
	}
}

// --- ServeChallengePage with challenge header ---

func TestServeChallengePage_Headers_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 16,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/some/path", nil)
	svc.ServeChallengePage(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-GuardianWAF-Challenge") != "1" {
		t.Error("expected X-GuardianWAF-Challenge header")
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("expected no-store cache control, got %s", cc)
	}
}

// --- hasLeadingZeroBits additional edge cases ---

func TestHasLeadingZeroBits_MoreEdgeCases_Cov(t *testing.T) {
	tests := []struct {
		hash     []byte
		bits     int
		expected bool
	}{
		{[]byte{0x00}, 8, true},
		{[]byte{0x80}, 1, false},
		{[]byte{0x40}, 2, false},
		{[]byte{0x7F}, 1, true},
		{[]byte{0x3F}, 2, true},
		{[]byte{0x00, 0x00, 0x01}, 23, true},
		{[]byte{}, 0, true},
	}

	for _, tt := range tests {
		got := hasLeadingZeroBits(tt.hash, tt.bits)
		if got != tt.expected {
			t.Errorf("hasLeadingZeroBits(%x, %d) = %v, want %v", tt.hash, tt.bits, got, tt.expected)
		}
	}
}

// --- VerifyHandler: redirect with @ sign sanitized ---

func TestVerifyHandler_RedirectWithAt_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 4,
		CookieName: "__gwaf_test",
	})

	handler := svc.VerifyHandler()

	challenge := "aabbccddaabbccddaabbccddaabbccdd"
	var validNonce string
	for i := range 1 << 20 {
		digit := i
		nonce := ""
		for digit > 0 {
			nonce = string(rune('a'+digit%26)) + nonce
			digit /= 26
		}
		if nonce == "" {
			nonce = "a"
		}
		if verifyPoW(challenge, nonce, 4) {
			validNonce = nonce
			break
		}
	}
	if validNonce == "" {
		t.Fatal("could not find valid nonce")
	}

	form := url.Values{
		"challenge": {challenge},
		"nonce":     {validNonce},
		"redirect":  {"/path@evil"},
	}
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	loc := resp.Header.Get("Location")
	if loc != "/" {
		t.Errorf("redirect with @ should be sanitized to /, got %s", loc)
	}
}

// --- VerifyHandler: protocol-relative redirect sanitized ---

func TestVerifyHandler_ProtocolRelativeRedirect_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 4,
		CookieName: "__gwaf_test",
	})

	handler := svc.VerifyHandler()

	challenge := "aabbccddaabbccddaabbccddaabbccdd"
	var validNonce string
	for i := range 1 << 20 {
		digit := i
		nonce := ""
		for digit > 0 {
			nonce = string(rune('a'+digit%26)) + nonce
			digit /= 26
		}
		if nonce == "" {
			nonce = "a"
		}
		if verifyPoW(challenge, nonce, 4) {
			validNonce = nonce
			break
		}
	}
	if validNonce == "" {
		t.Fatal("could not find valid nonce")
	}

	form := url.Values{
		"challenge": {challenge},
		"nonce":     {validNonce},
		"redirect":  {"//evil.com"},
	}
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	loc := resp.Header.Get("Location")
	if loc != "/" {
		t.Errorf("protocol-relative redirect should be sanitized to /, got %s", loc)
	}
}

// --- VerifyHandler: redirect with backslash sanitized ---

func TestVerifyHandler_RedirectBackslash_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 4,
		CookieName: "__gwaf_test",
	})

	handler := svc.VerifyHandler()

	challenge := "aabbccddaabbccddaabbccddaabbccdd"
	var validNonce string
	for i := range 1 << 20 {
		digit := i
		nonce := ""
		for digit > 0 {
			nonce = string(rune('a'+digit%26)) + nonce
			digit /= 26
		}
		if nonce == "" {
			nonce = "a"
		}
		if verifyPoW(challenge, nonce, 4) {
			validNonce = nonce
			break
		}
	}
	if validNonce == "" {
		t.Fatal("could not find valid nonce")
	}

	form := url.Values{
		"challenge": {challenge},
		"nonce":     {validNonce},
		"redirect":  {"\\evil"},
	}
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	loc := resp.Header.Get("Location")
	if loc != "/" {
		t.Errorf("redirect with backslash should be sanitized to /, got %s", loc)
	}
}

// --- VerifyPath constant ---

func TestVerifyPath_Cov(t *testing.T) {
	if VerifyPath != "/__guardianwaf/challenge/verify" {
		t.Errorf("VerifyPath = %q, want /__guardianwaf/challenge/verify", VerifyPath)
	}
}

// --- VerifyHandler with ClientIPExtractor ---

func TestVerifyHandler_ClientIPExtractor_Cov(t *testing.T) {
	svc, _ := NewService(Config{
		SecretKey:  []byte("test-key-32-bytes-long-aaaaaaaaaaa!"),
		Difficulty: 4,
		CookieName: "__gwaf_test",
		CookieTTL:  3600000000000,
		ClientIPExtractor: func(r *http.Request) net.IP {
			return net.ParseIP("10.0.0.1")
		},
	})

	handler := svc.VerifyHandler()

	challenge := "aabbccddaabbccddaabbccddaabbccdd"
	var validNonce string
	for i := range 1 << 20 {
		digit := i
		nonce := ""
		for digit > 0 {
			nonce = string(rune('a'+digit%26)) + nonce
			digit /= 26
		}
		if nonce == "" {
			nonce = "a"
		}
		if verifyPoW(challenge, nonce, 4) {
			validNonce = nonce
			break
		}
	}
	if validNonce == "" {
		t.Fatal("could not find valid nonce")
	}

	form := url.Values{
		"challenge": {challenge},
		"nonce":     {validNonce},
		"redirect":  {"/valid/path"},
	}
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.1:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", resp.StatusCode)
	}

	// Cookie should be set using the ClientIPExtractor's IP
	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "__gwaf_test" {
			found = true
		}
	}
	if !found {
		t.Error("expected cookie to be set")
	}
}
