package response

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// --- Security Headers Tests ---

func TestSecurityHeaders_Apply(t *testing.T) {
	sh := DefaultSecurityHeaders()
	w := httptest.NewRecorder()
	sh.Apply(w)

	checks := []struct {
		header string
		want   string
	}{
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "SAMEORIGIN"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
		{"Content-Security-Policy", "default-src 'self'"},
		{"X-XSS-Protection", "0"},
	}

	for _, c := range checks {
		got := w.Header().Get(c.header)
		if got != c.want {
			t.Errorf("header %q = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestSecurityHeaders_Empty(t *testing.T) {
	sh := SecurityHeaders{} // all empty
	w := httptest.NewRecorder()
	sh.Apply(w)

	// No headers should be set
	if len(w.Header()) != 0 {
		t.Errorf("expected no headers set for empty config, got %d", len(w.Header()))
	}
}

func TestSecurityHeaders_Partial(t *testing.T) {
	sh := SecurityHeaders{
		HSTS:              "max-age=3600",
		XContentTypeOptions: "nosniff",
	}
	w := httptest.NewRecorder()
	sh.Apply(w)

	if w.Header().Get("Strict-Transport-Security") != "max-age=3600" {
		t.Error("expected HSTS header")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "" {
		t.Error("expected no X-Frame-Options header when not configured")
	}
}

// --- Credit Card Masking Tests ---

func TestMaskCreditCards_Visa(t *testing.T) {
	// Visa test number: 4111111111111111
	input := "Card: 4111111111111111 is valid"
	result := MaskCreditCards(input)
	if strings.Contains(result, "4111111111111111") {
		t.Error("credit card number should be masked")
	}
	// Last 4 should be preserved
	if !strings.Contains(result, "1111") {
		t.Error("last 4 digits should be preserved")
	}
	// Should contain mask characters
	if !strings.Contains(result, "****") {
		t.Error("should contain mask characters")
	}
}

func TestMaskCreditCards_Mastercard(t *testing.T) {
	// Mastercard test number: 5500000000000004
	input := "MC: 5500000000000004"
	result := MaskCreditCards(input)
	if strings.Contains(result, "5500000000000004") {
		t.Error("Mastercard number should be masked")
	}
	if !strings.Contains(result, "0004") {
		t.Error("last 4 digits should be preserved")
	}
}

func TestMaskCreditCards_Amex(t *testing.T) {
	// Amex test number: 378282246310005
	input := "Amex: 378282246310005"
	result := MaskCreditCards(input)
	if strings.Contains(result, "378282246310005") {
		t.Error("Amex number should be masked")
	}
	if !strings.Contains(result, "0005") {
		t.Error("last 4 digits should be preserved")
	}
}

func TestMaskCreditCards_WithDashes(t *testing.T) {
	// Visa with dashes: 4111-1111-1111-1111
	input := "Card: 4111-1111-1111-1111"
	result := MaskCreditCards(input)
	if strings.Contains(result, "4111-1111-1111") {
		t.Error("dashed credit card number should be masked")
	}
	if !strings.Contains(result, "1111") {
		t.Error("last 4 digits should be preserved")
	}
}

func TestMaskCreditCards_WithSpaces(t *testing.T) {
	// Visa with spaces: 4111 1111 1111 1111
	input := "Card: 4111 1111 1111 1111"
	result := MaskCreditCards(input)
	if !strings.Contains(result, "1111") {
		t.Error("last 4 digits should be preserved")
	}
}

func TestMaskCreditCards_InvalidLuhn(t *testing.T) {
	// Invalid Luhn: 4111111111111112 (fails check)
	input := "Card: 4111111111111112"
	result := MaskCreditCards(input)
	if !strings.Contains(result, "4111111111111112") {
		t.Error("invalid Luhn number should NOT be masked")
	}
}

func TestMaskCreditCards_TooShort(t *testing.T) {
	input := "Short: 123456789012"
	result := MaskCreditCards(input)
	// 12 digits - too short for a credit card
	if result != input {
		t.Error("short number should not be masked")
	}
}

func TestMaskCreditCards_NoNumbers(t *testing.T) {
	input := "No numbers here"
	result := MaskCreditCards(input)
	if result != input {
		t.Error("text without numbers should be unchanged")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		digits string
		valid  bool
	}{
		{"4111111111111111", true},
		{"5500000000000004", true},
		{"378282246310005", true},
		{"4111111111111112", false},
		{"0000000000000000", true}, // technically valid Luhn
		{"1", false},               // too short
	}

	for _, tc := range tests {
		got := luhnCheck([]byte(tc.digits))
		if got != tc.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tc.digits, got, tc.valid)
		}
	}
}

// --- SSN Masking Tests ---

func TestMaskSSN_Valid(t *testing.T) {
	input := "SSN: 123-45-6789 is here"
	result := MaskSSN(input)
	if strings.Contains(result, "123-45") {
		t.Error("SSN should be masked")
	}
	if !strings.Contains(result, "***-**-6789") {
		t.Errorf("expected ***-**-6789, got %q", result)
	}
}

func TestMaskSSN_InvalidGroup(t *testing.T) {
	// Area number 000 is invalid
	input := "SSN: 000-45-6789"
	result := MaskSSN(input)
	if result != input {
		t.Error("invalid SSN (000 area) should not be masked")
	}
}

func TestMaskSSN_666Area(t *testing.T) {
	// Area number 666 is invalid
	input := "SSN: 666-45-6789"
	result := MaskSSN(input)
	if result != input {
		t.Error("invalid SSN (666 area) should not be masked")
	}
}

func TestMaskSSN_900Area(t *testing.T) {
	// Area numbers 900-999 are invalid
	input := "SSN: 900-45-6789"
	result := MaskSSN(input)
	if result != input {
		t.Error("invalid SSN (9xx area) should not be masked")
	}
}

func TestMaskSSN_NoMatch(t *testing.T) {
	input := "No SSN here"
	result := MaskSSN(input)
	if result != input {
		t.Error("text without SSN pattern should be unchanged")
	}
}

func TestMaskSSN_Multiple(t *testing.T) {
	input := "First: 123-45-6789 Second: 234-56-7890"
	result := MaskSSN(input)
	if strings.Contains(result, "123-45") {
		t.Error("first SSN should be masked")
	}
	if strings.Contains(result, "234-56") {
		t.Error("second SSN should be masked")
	}
}

// --- API Key Masking Tests ---

func TestMaskAPIKeys_Basic(t *testing.T) {
	input := `api_key=abcd1234567890efghij1234567890ab`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("API key should be masked")
	}
	if !strings.Contains(result, "****") {
		t.Error("should contain mask characters")
	}
}

func TestMaskAPIKeys_WithQuotes(t *testing.T) {
	input := `"token": "abcdef1234567890abcdef1234567890"`
	result := MaskAPIKeys(input)
	if strings.Contains(result, "abcdef1234567890abcdef1234567890") {
		t.Error("token should be masked")
	}
}

func TestMaskAPIKeys_Secret(t *testing.T) {
	input := `secret=MyVeryLongSecretKeyValue12345`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("secret should be masked")
	}
}

func TestMaskAPIKeys_Short(t *testing.T) {
	// Short keys (< 16 chars) should not be masked
	input := `key=shortval`
	result := MaskAPIKeys(input)
	if result != input {
		t.Error("short key values should not be masked")
	}
}

func TestMaskAPIKeys_NoKeyword(t *testing.T) {
	input := `data=abcdef1234567890abcdef1234567890`
	result := MaskAPIKeys(input)
	if result != input {
		t.Error("values without key/token/secret keyword should not be masked")
	}
}

// --- Stack Trace Stripping Tests ---

func TestStripStackTraces_Go(t *testing.T) {
	input := `Some normal text
goroutine 1 [running]:
main.handler()
	/app/main.go:42 +0x1a3
More normal text`

	result := StripStackTraces(input)
	if strings.Contains(result, "goroutine") {
		t.Error("Go stack trace should be stripped")
	}
	if strings.Contains(result, "main.go:42") {
		t.Error("Go stack frame should be stripped")
	}
	if !strings.Contains(result, "Some normal text") {
		t.Error("normal text should be preserved")
	}
	if !strings.Contains(result, "More normal text") {
		t.Error("trailing normal text should be preserved")
	}
}

func TestStripStackTraces_Java(t *testing.T) {
	input := `Error occurred
java.lang.NullPointerException: something
	at com.example.App.handle(App.java:42)
	at com.example.App.main(App.java:10)
Done`

	result := StripStackTraces(input)
	if strings.Contains(result, "NullPointerException") {
		t.Error("Java exception should be stripped")
	}
	if strings.Contains(result, "App.java:42") {
		t.Error("Java stack frame should be stripped")
	}
	if !strings.Contains(result, "Error occurred") {
		t.Error("preceding text should be preserved")
	}
}

func TestStripStackTraces_Python(t *testing.T) {
	input := `Request failed
Traceback (most recent call last):
  File "/app/handler.py", line 42, in handle
ValueError: invalid input
End`

	result := StripStackTraces(input)
	if strings.Contains(result, "Traceback") {
		t.Error("Python traceback should be stripped")
	}
	if strings.Contains(result, "handler.py") {
		t.Error("Python stack frame should be stripped")
	}
	if !strings.Contains(result, "Request failed") {
		t.Error("preceding text should be preserved")
	}
}

func TestStripStackTraces_NodeJS(t *testing.T) {
	input := `Something broke
Error: connection refused
    at Socket.connect (net.js:1023:14)
    at handler (/app/server.js:42:5)
Recovered`

	result := StripStackTraces(input)
	if strings.Contains(result, "net.js:1023") {
		t.Error("Node.js stack frame should be stripped")
	}
	if strings.Contains(result, "server.js:42") {
		t.Error("Node.js stack frame should be stripped")
	}
	if !strings.Contains(result, "Something broke") {
		t.Error("preceding text should be preserved")
	}
}

func TestStripStackTraces_NoTrace(t *testing.T) {
	input := "Normal text with no stack traces"
	result := StripStackTraces(input)
	if result != input {
		t.Error("text without stack traces should be unchanged")
	}
}

// --- Error Page Tests ---

func TestErrorPage_Production(t *testing.T) {
	page := ErrorPage(403, "production")

	if !strings.Contains(page, "403") {
		t.Error("production page should contain status code")
	}
	if !strings.Contains(page, "Forbidden") {
		t.Error("production page should contain status text")
	}
	if !strings.Contains(page, "GuardianWAF") {
		t.Error("production page should contain branding")
	}
	if strings.Contains(page, "development") {
		t.Error("production page should not contain development indicators")
	}
}

func TestErrorPage_Development(t *testing.T) {
	page := ErrorPage(500, "development")

	if !strings.Contains(page, "500") {
		t.Error("development page should contain status code")
	}
	if !strings.Contains(page, "Development") {
		t.Error("development page should indicate development mode")
	}
	if !strings.Contains(page, "Do not expose in production") {
		t.Error("development page should contain production warning")
	}
}

func TestErrorPageWithDetails(t *testing.T) {
	page := ErrorPageWithDetails(500, "development", "database connection failed")

	if !strings.Contains(page, "database connection failed") {
		t.Error("development page should contain details")
	}
}

func TestErrorPageWithDetails_Production(t *testing.T) {
	page := ErrorPageWithDetails(500, "production", "database connection failed")

	if strings.Contains(page, "database connection failed") {
		t.Error("production page should NOT contain details")
	}
}

func TestErrorPage_HTMLEscaping(t *testing.T) {
	page := ErrorPageWithDetails(500, "development", "<script>alert('xss')</script>")

	if strings.Contains(page, "<script>") {
		t.Error("error page should escape HTML in details")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("error page should contain escaped HTML")
	}
}

func TestErrorPage_VariousCodes(t *testing.T) {
	codes := []int{400, 403, 404, 405, 429, 500, 502, 503}
	for _, code := range codes {
		page := ErrorPage(code, "production")
		if page == "" {
			t.Errorf("error page for %d should not be empty", code)
		}
		if !strings.Contains(page, "<!DOCTYPE html>") {
			t.Errorf("error page for %d should be valid HTML", code)
		}
	}
}

// --- Layer Integration Tests ---

func TestLayer_Name(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	if layer.Name() != "response" {
		t.Errorf("expected layer name 'response', got %q", layer.Name())
	}
}

func TestLayer_Process(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/test"},
		},
		Method:      "GET",
		Path:        "/test",
		Accumulator: engine.NewScoreAccumulator(2),
		Metadata:    make(map[string]any),
		StartTime:   time.Now(),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass, got %v", result.Action)
	}

	// Config should be stored in metadata
	if _, ok := ctx.Metadata["response_config"]; !ok {
		t.Error("expected response_config in metadata")
	}
}

func TestLayer_ApplyToResponse(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	body := "Card: 4111111111111111 SSN: 123-45-6789"
	result := layer.ApplyToResponse(body)

	if strings.Contains(result, "4111111111111111") {
		t.Error("credit card should be masked in response")
	}
	if strings.Contains(result, "123-45") {
		t.Error("SSN should be masked in response")
	}
}

func TestLayer_ApplyToResponse_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataMaskingEnabled = false
	layer := NewLayer(cfg)

	body := "Card: 4111111111111111"
	result := layer.ApplyToResponse(body)

	if result != body {
		t.Error("masking should be disabled when DataMaskingEnabled is false")
	}
}

func TestLayer_ApplyToResponse_SelectiveMasking(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaskCreditCards = false
	cfg.MaskSSN = true
	layer := NewLayer(cfg)

	body := "Card: 4111111111111111 SSN: 123-45-6789"
	result := layer.ApplyToResponse(body)

	// CC should NOT be masked
	if !strings.Contains(result, "4111111111111111") {
		t.Error("credit card should NOT be masked when MaskCreditCards is false")
	}
	// SSN should be masked
	if strings.Contains(result, "123-45-6789") {
		t.Error("SSN should be masked when MaskSSN is true")
	}
}
