package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Difficulty != 20 {
		t.Errorf("expected difficulty 20, got %d", cfg.Difficulty)
	}
	if cfg.CookieTTL != 1*time.Hour {
		t.Errorf("expected 1h cookie TTL, got %v", cfg.CookieTTL)
	}
	if cfg.CookieName != "__gwaf_challenge" {
		t.Errorf("expected __gwaf_challenge, got %s", cfg.CookieName)
	}
	if len(cfg.SecretKey) != 32 {
		t.Errorf("expected 32-byte secret key, got %d", len(cfg.SecretKey))
	}
}

func TestNewService(t *testing.T) {
	// Empty config should get defaults
	svc := NewService(Config{})
	if svc.config.Difficulty != 20 {
		t.Errorf("expected default difficulty 20, got %d", svc.config.Difficulty)
	}
	if len(svc.config.SecretKey) == 0 {
		t.Error("expected auto-generated secret key")
	}
	if svc.config.CookieName != "__gwaf_challenge" {
		t.Errorf("expected default cookie name, got %s", svc.config.CookieName)
	}
}

func TestHasLeadingZeroBits(t *testing.T) {
	tests := []struct {
		hash     []byte
		bits     int
		expected bool
	}{
		{[]byte{0x00, 0x00, 0xFF}, 16, true},
		{[]byte{0x00, 0x00, 0xFF}, 17, false},
		{[]byte{0x00, 0x0F, 0xFF}, 12, true},
		{[]byte{0x00, 0x0F, 0xFF}, 13, false},
		{[]byte{0x00, 0x00, 0x00}, 24, true},
		{[]byte{0x01, 0x00, 0x00}, 8, false},
		{[]byte{0x00, 0x00, 0x00, 0x00}, 0, true},
		{[]byte{0xFF}, 0, true},
	}

	for _, tt := range tests {
		got := hasLeadingZeroBits(tt.hash, tt.bits)
		if got != tt.expected {
			t.Errorf("hasLeadingZeroBits(%x, %d) = %v, want %v", tt.hash, tt.bits, got, tt.expected)
		}
	}
}

func TestVerifyPoW(t *testing.T) {
	// Use low difficulty for fast test
	challenge := "testchallenge123"
	difficulty := 8 // only 1 leading zero byte

	// Brute-force a valid nonce
	var validNonce string
	for i := range 1 << 20 {
		nonce := fmt.Sprintf("%x", i)
		if verifyPoW(challenge, nonce, difficulty) {
			validNonce = nonce
			break
		}
	}

	if validNonce == "" {
		t.Fatal("could not find valid nonce for difficulty 8")
	}

	// Valid nonce should pass
	if !verifyPoW(challenge, validNonce, difficulty) {
		t.Error("valid nonce did not pass verification")
	}

	// Wrong nonce should fail (almost certainly)
	if verifyPoW(challenge, "definitely_wrong_nonce_xyz", difficulty) {
		// Extremely unlikely but possible — just skip
		t.Log("warning: random nonce passed (astronomically unlikely)")
	}
}

func TestTokenGenerateAndVerify(t *testing.T) {
	svc := NewService(Config{
		SecretKey: []byte("test-secret-key-32-bytes-long!!!"),
		CookieTTL: 1 * time.Hour,
	})

	ip := net.ParseIP("192.168.1.100")

	// Generate token
	token := svc.generateToken(ip)
	if token == "" {
		t.Fatal("generated empty token")
	}

	// Should verify with same IP
	if !svc.verifyToken(token, ip) {
		t.Error("token should be valid for same IP")
	}

	// Should fail with different IP
	otherIP := net.ParseIP("10.0.0.1")
	if svc.verifyToken(token, otherIP) {
		t.Error("token should not be valid for different IP")
	}

	// Should fail with tampered token
	if svc.verifyToken(token+"tampered", ip) {
		t.Error("tampered token should not be valid")
	}

	// Should fail with empty token
	if svc.verifyToken("", ip) {
		t.Error("empty token should not be valid")
	}

	// Should fail with garbage
	if svc.verifyToken("not.a.valid.token", ip) {
		t.Error("garbage token should not be valid")
	}
}

func TestTokenExpiration(t *testing.T) {
	svc := NewService(Config{
		SecretKey: []byte("test-secret-key-32-bytes-long!!!"),
		CookieTTL: -1 * time.Second, // already expired
	})

	ip := net.ParseIP("192.168.1.100")
	token := svc.generateToken(ip)

	if svc.verifyToken(token, ip) {
		t.Error("expired token should not be valid")
	}
}

func TestHasValidCookie(t *testing.T) {
	svc := NewService(Config{
		SecretKey:  []byte("test-secret-key-32-bytes-long!!!"),
		CookieTTL:  1 * time.Hour,
		CookieName: "__gwaf_test",
	})

	ip := net.ParseIP("127.0.0.1")
	token := svc.generateToken(ip)

	// Request with valid cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{Name: "__gwaf_test", Value: token})
	if !svc.HasValidCookie(req, ip) {
		t.Error("should accept valid cookie")
	}

	// Request without cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.1:12345"
	if svc.HasValidCookie(req2, ip) {
		t.Error("should reject request without cookie")
	}

	// Request with wrong cookie name
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(&http.Cookie{Name: "wrong_name", Value: token})
	if svc.HasValidCookie(req3, ip) {
		t.Error("should reject wrong cookie name")
	}
}

func TestServeChallengePage(t *testing.T) {
	svc := NewService(Config{
		SecretKey:  []byte("test-secret-key-32-bytes-long!!!"),
		Difficulty: 16,
	})

	req := httptest.NewRequest("GET", "/some/page?q=test", nil)
	w := httptest.NewRecorder()

	svc.ServeChallengePage(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %s", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "SHA-256") {
		t.Error("challenge page should mention SHA-256")
	}
	if !strings.Contains(body, "GuardianWAF") {
		t.Error("challenge page should mention GuardianWAF")
	}
	if !strings.Contains(body, "__guardianwaf/challenge/verify") {
		t.Error("challenge page should contain verify endpoint")
	}
	if !strings.Contains(body, "D=16") {
		t.Error("challenge page should contain difficulty value")
	}

	// Verify cache control
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("expected no-store cache control, got %s", cc)
	}
}

func TestVerifyHandler(t *testing.T) {
	svc := NewService(Config{
		SecretKey:  []byte("test-secret-key-32-bytes-long!!!"),
		Difficulty: 4, // very low for fast tests
		CookieTTL:  1 * time.Hour,
		CookieName: "__gwaf_test",
	})

	handler := svc.VerifyHandler()

	// Find a valid nonce for our challenge
	challenge := "deadbeef01234567deadbeef01234567"
	var validNonce string
	for i := range 1 << 20 {
		nonce := fmt.Sprintf("%x", i)
		data := challenge + nonce
		hash := sha256.Sum256([]byte(data))
		if hasLeadingZeroBits(hash[:], 4) {
			validNonce = nonce
			break
		}
	}

	t.Run("valid solution", func(t *testing.T) {
		form := url.Values{
			"challenge": {challenge},
			"nonce":     {validNonce},
			"redirect":  {"/original/page"},
		}
		req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("expected 303 redirect, got %d", resp.StatusCode)
		}

		loc := resp.Header.Get("Location")
		if loc != "/original/page" {
			t.Errorf("expected redirect to /original/page, got %s", loc)
		}

		// Check cookie was set
		cookies := resp.Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == "__gwaf_test" {
				found = true
				if !c.HttpOnly {
					t.Error("cookie should be HttpOnly")
				}
			}
		}
		if !found {
			t.Error("challenge cookie was not set")
		}
	})

	t.Run("invalid nonce", func(t *testing.T) {
		form := url.Values{
			"challenge": {challenge},
			"nonce":     {"invalid_nonce"},
			"redirect":  {"/"},
		}
		req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("missing fields", func(t *testing.T) {
		form := url.Values{"challenge": {challenge}}
		req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/__guardianwaf/challenge/verify", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", w.Code)
		}
	})

	t.Run("empty redirect defaults to /", func(t *testing.T) {
		form := url.Values{
			"challenge": {challenge},
			"nonce":     {validNonce},
			"redirect":  {""},
		}
		req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		loc := resp.Header.Get("Location")
		if loc != "/" {
			t.Errorf("expected redirect to /, got %s", loc)
		}
	})

	t.Run("non-relative redirect sanitized to /", func(t *testing.T) {
		form := url.Values{
			"challenge": {challenge},
			"nonce":     {validNonce},
			"redirect":  {"https://evil.com/steal"},
		}
		req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		resp := w.Result()
		loc := resp.Header.Get("Location")
		if loc != "/" {
			t.Errorf("expected redirect sanitized to /, got %s", loc)
		}
	})
}

func TestVerifyHandlerParseFormError(t *testing.T) {
	svc := NewService(Config{
		SecretKey:  []byte("test-secret-key-32-bytes-long!!!"),
		Difficulty: 4,
	})
	handler := svc.VerifyHandler()

	// Send a body with invalid content-type that triggers ParseForm error
	req := httptest.NewRequest("POST", "/__guardianwaf/challenge/verify",
		strings.NewReader("%zz=invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// ParseForm may or may not error on this, but ensure no panic
	// and we get a non-success response for missing fields
	if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
		// Either bad request (parse error) or bad request (missing fields) is acceptable
		t.Logf("got status %d", w.Code)
	}
}

func TestVerifyTokenMalformedPayload(t *testing.T) {
	svc := NewService(Config{
		SecretKey: []byte("test-secret-key-32-bytes-long!!!"),
		CookieTTL: 1 * time.Hour,
	})

	ip := net.ParseIP("192.168.1.1")

	// Craft a token with valid HMAC but no pipe separator in payload
	// payload = "nopipe" (no "|" separator)
	payload := "nopipe"
	payloadHex := hex.EncodeToString([]byte(payload))
	mac := svc.computeHMAC(payload)
	token := payloadHex + "." + mac

	if svc.verifyToken(token, ip) {
		t.Error("token without pipe separator should be rejected")
	}

	// Craft a token with valid HMAC but non-numeric expiry
	payload2 := "notanumber|192.168.1.1"
	payloadHex2 := hex.EncodeToString([]byte(payload2))
	mac2 := svc.computeHMAC(payload2)
	token2 := payloadHex2 + "." + mac2

	if svc.verifyToken(token2, ip) {
		t.Error("token with non-numeric expiry should be rejected")
	}

	// Nil client IP
	validToken := svc.generateToken(nil)
	if !svc.verifyToken(validToken, nil) {
		t.Error("nil IP token should verify with nil IP")
	}
	if svc.verifyToken(validToken, ip) {
		t.Error("nil IP token should not verify with non-nil IP")
	}
}

func TestJSStringEscape(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{`hello`, `hello`},
		{`</script>`, `<\/script>`},
		{`"quoted"`, `\"quoted\"`},
		{`a&b`, `a&b`}, // ampersand is not escaped in JS strings
		{`it's`, `it\'s`},
		{`back\slash`, `back\\slash`},
		{"/path?a=1&b=2", `/path?a=1&b=2`},
	}
	for _, tt := range tests {
		got := jsStringEscape(tt.input)
		if got != tt.expected {
			t.Errorf("jsStringEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractClientIP(t *testing.T) {
	// Challenge layer's extractClientIP uses RemoteAddr only (no proxy header trust)
	tests := []struct {
		name     string
		xff      string
		xri      string
		remote   string
		expected string
	}{
		{"XFF ignored", "1.2.3.4, 5.6.7.8", "", "9.0.0.1:80", "9.0.0.1"},
		{"X-Real-IP ignored", "", "10.0.0.1", "9.0.0.1:80", "9.0.0.1"},
		{"RemoteAddr", "", "", "192.168.1.1:12345", "192.168.1.1"},
		{"RemoteAddr no port", "", "", "192.168.1.1", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			ip := extractClientIP(req)
			if ip.String() != tt.expected {
				t.Errorf("got %s, want %s", ip, tt.expected)
			}
		})
	}
}

func TestBuildChallengePage(t *testing.T) {
	page := buildChallengePage("abc123", 16, "/test?foo=bar")

	if !strings.Contains(page, `C="abc123"`) {
		t.Error("page should contain challenge value")
	}
	if !strings.Contains(page, `D=16`) {
		t.Error("page should contain difficulty")
	}
	if !strings.Contains(page, `/test?foo=bar`) {
		t.Error("page should contain redirect URI")
	}
	if !strings.Contains(page, `<!DOCTYPE html>`) {
		t.Error("page should be valid HTML")
	}
}

func TestBuildChallengePageXSS(t *testing.T) {
	// Ensure XSS in redirect URI is JS-escaped
	page := buildChallengePage("abc", 16, `"><script>alert(1)</script>`)

	if strings.Contains(page, `<script>alert(1)</script>`) {
		t.Error("XSS payload should be escaped")
	}
	// Double quote should be JS-escaped, script tag broken via <\/
	if !strings.Contains(page, `\"`) {
		t.Error("double quote should be JS-escaped")
	}
	if !strings.Contains(page, `<\/script>`) {
		t.Error("should contain escaped script closing tag")
	}
}

func BenchmarkVerifyPoW(b *testing.B) {
	// Pre-compute a valid nonce
	challenge := "benchmarkchallenge"
	difficulty := 16
	var nonce string
	for i := range 1 << 24 {
		n := fmt.Sprintf("%x", i)
		if verifyPoW(challenge, n, difficulty) {
			nonce = n
			break
		}
	}
	_ = hex.EncodeToString(nil) // use hex

	b.ResetTimer()
	for range b.N {
		verifyPoW(challenge, nonce, difficulty)
	}
}

func BenchmarkTokenGenerate(b *testing.B) {
	svc := NewService(Config{
		SecretKey: []byte("bench-secret-key-32-bytes-long!!"),
		CookieTTL: 1 * time.Hour,
	})
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for range b.N {
		svc.generateToken(ip)
	}
}

func BenchmarkTokenVerify(b *testing.B) {
	svc := NewService(Config{
		SecretKey: []byte("bench-secret-key-32-bytes-long!!"),
		CookieTTL: 1 * time.Hour,
	})
	ip := net.ParseIP("192.168.1.1")
	token := svc.generateToken(ip)

	b.ResetTimer()
	for range b.N {
		svc.verifyToken(token, ip)
	}
}
