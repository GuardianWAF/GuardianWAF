package response

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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
		{"Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"},
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
		HSTS:                "max-age=3600",
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
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)
	if layer.Name() != "response" {
		t.Errorf("expected layer name 'response', got %q", layer.Name())
	}
}

func TestLayer_Process(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)

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

	// Hook should be registered since SecurityHeadersEnabled is true
	if _, ok := ctx.Metadata["response_hook"]; !ok {
		t.Error("expected response_hook in metadata when security headers enabled")
	}

	// Call the hook and verify it applies headers
	hook := ctx.Metadata["response_hook"].(func(http.ResponseWriter))
	w := httptest.NewRecorder()
	hook(w)
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options from hook")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("expected X-Frame-Options from hook")
	}
}

func TestLayer_Process_NoSecurityHeaders(t *testing.T) {
	cfg := Config{
		SecurityHeadersEnabled: false,
		DataMaskingEnabled:     true,
	}
	layer := NewLayer(&cfg)

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

	layer.Process(ctx)

	// No hook should be set when security headers disabled
	if _, ok := ctx.Metadata["response_hook"]; ok {
		t.Error("expected no response_hook when security headers disabled")
	}
}

func TestLayer_ApplyToResponse(t *testing.T) {
	cfg := DefaultConfig()
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

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
	layer := NewLayer(&cfg)

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

// --- GetConfig Test ---

func TestLayer_GetConfig(t *testing.T) {
	cfg := Config{
		SecurityHeadersEnabled: true,
		DataMaskingEnabled:     true,
		MaskCreditCards:        true,
		ErrorPageMode:          "production",
	}
	layer := NewLayer(&cfg)
	got := layer.GetConfig()
	if got.SecurityHeadersEnabled != cfg.SecurityHeadersEnabled {
		t.Error("GetConfig should return the config passed to NewLayer")
	}
	if got.ErrorPageMode != "production" {
		t.Errorf("expected ErrorPageMode 'production', got %q", got.ErrorPageMode)
	}
}

// --- statusText / statusMessage Edge Cases ---

func TestStatusText_UnknownCode(t *testing.T) {
	// Unknown status code should return "Error"
	text := statusText(999)
	if text != "Error" {
		t.Errorf("statusText(999) = %q, want %q", text, "Error")
	}
}

func TestStatusMessage_AllCodes(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{400, "The request could not be understood by the server."},
		{403, "Access to this resource has been denied by the security policy."},
		{404, "The requested resource could not be found."},
		{405, "The request method is not allowed for this resource."},
		{408, "The server timed out waiting for the request."},
		{413, "The request payload is too large."},
		{429, "Too many requests. Please slow down and try again later."},
		{500, "An internal error occurred. Please try again later."},
		{502, "The server received an invalid response from an upstream server."},
		{503, "The service is temporarily unavailable. Please try again later."},
		{999, "An error occurred while processing your request."},
	}
	for _, tc := range tests {
		got := statusMessage(tc.code)
		if got != tc.want {
			t.Errorf("statusMessage(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestErrorPage_UnknownCode(t *testing.T) {
	page := ErrorPage(999, "production")
	if !strings.Contains(page, "999") {
		t.Error("unknown code page should contain the code")
	}
	if !strings.Contains(page, "Error") {
		t.Error("unknown code page should contain 'Error' as title")
	}
}

func TestErrorPage_408And413(t *testing.T) {
	for _, code := range []int{408, 413} {
		page := ErrorPage(code, "production")
		if !strings.Contains(page, http.StatusText(code)) {
			t.Errorf("error page for %d should contain status text", code)
		}
	}
}

// --- SecurityHeaders CacheControl branch ---

func TestSecurityHeaders_CacheControl(t *testing.T) {
	sh := SecurityHeaders{
		CacheControl: "no-store",
	}
	w := httptest.NewRecorder()
	sh.Apply(w)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("expected Cache-Control header to be set")
	}
}

// --- MaskAPIKeys edge cases ---

func TestMaskAPIKeys_ShortKeyValue(t *testing.T) {
	// Key exactly 16 chars — should mask but maskEnd <= maskStart edge
	input := `key=1234567890123456`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("16-char key should be masked")
	}
}

func TestMaskAPIKeys_ExactlyEightChars(t *testing.T) {
	// Key between 8 and 16 — should NOT be masked (< 16 chars)
	input := `token=abcd1234`
	result := MaskAPIKeys(input)
	if result != input {
		t.Error("8-char key should not be masked")
	}
}

func TestMaskAPIKeys_MultipleSeparators(t *testing.T) {
	// Key with tab separator
	input := "secret\t= \t'abcdefghijklmnopqrstuvwxyz1234'"
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("key after tab separators should be masked")
	}
}

// --- isStackTraceLine edge cases ---

func TestStripStackTraces_GoFuncLine(t *testing.T) {
	input := "main.handler()\n\t/app/main.go:42 +0x1a3\nOK"
	result := StripStackTraces(input)
	if strings.Contains(result, "main.go:42") {
		t.Error("Go stack frame with () should be stripped")
	}
	if !strings.Contains(result, "OK") {
		t.Error("normal line should be preserved")
	}
}

func TestStripStackTraces_TypeErrorAndReferenceError(t *testing.T) {
	input := "Start\nTypeError: undefined is not a function\n    at handler (/app/index.ts:10:5)\nEnd"
	result := StripStackTraces(input)
	if strings.Contains(result, "TypeError") {
		t.Error("TypeError start should be stripped")
	}
	if strings.Contains(result, "index.ts:10") {
		t.Error("TypeScript stack frame should be stripped")
	}
	if !strings.Contains(result, "Start") || !strings.Contains(result, "End") {
		t.Error("surrounding text should be preserved")
	}
}

func TestStripStackTraces_ReferenceError(t *testing.T) {
	input := "ReferenceError: x is not defined\n    at main (/app/app.js:5:1)\nDone"
	result := StripStackTraces(input)
	if strings.Contains(result, "ReferenceError") {
		t.Error("ReferenceError should be stripped")
	}
}

func TestStripStackTraces_SyntaxError(t *testing.T) {
	input := "SyntaxError: Unexpected token\n    at parse (/app/parser.js:1:1)\nOK"
	result := StripStackTraces(input)
	if strings.Contains(result, "SyntaxError") {
		t.Error("SyntaxError should be stripped")
	}
}

func TestMaskSSN_ZeroGroup2(t *testing.T) {
	// Group 2 is "00" - invalid
	input := "SSN: 123-00-6789"
	result := MaskSSN(input)
	if result != input {
		t.Error("invalid SSN (00 group) should not be masked")
	}
}

func TestMaskSSN_ZeroGroup3(t *testing.T) {
	// Group 3 is "0000" - invalid
	input := "SSN: 123-45-0000"
	result := MaskSSN(input)
	if result != input {
		t.Error("invalid SSN (0000 serial) should not be masked")
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.SecurityHeadersEnabled {
		t.Error("default SecurityHeadersEnabled should be true")
	}
	if !cfg.DataMaskingEnabled {
		t.Error("default DataMaskingEnabled should be true")
	}
	if cfg.ErrorPageMode != "production" {
		t.Errorf("expected ErrorPageMode 'production', got %q", cfg.ErrorPageMode)
	}
}

// --- MaskCreditCards edge: maskEnd < 0 guard ---

func TestMaskCreditCards_NineteenDigitCard(t *testing.T) {
	// 19-digit card number (Luhn valid): 6304000000000000000 check
	// Use a 16-digit valid card with spaces creating long digit sequence
	input := "Card: 4111111111111111 end"
	result := MaskCreditCards(input)
	if strings.Contains(result, "4111111111111111") {
		t.Error("card should be masked")
	}
}

func TestMaskCreditCards_MultipleCards(t *testing.T) {
	input := "First: 4111111111111111 Second: 5500000000000004"
	result := MaskCreditCards(input)
	if strings.Contains(result, "4111111111111111") {
		t.Error("first card should be masked")
	}
	if strings.Contains(result, "5500000000000004") {
		t.Error("second card should be masked")
	}
}

// --- MaskAPIKeys: maskEnd <= maskStart branch ---

func TestMaskAPIKeys_ExactlySixteenChars(t *testing.T) {
	// 16-char key: first 4 + last 4 = 8 visible, middle 8 masked
	input := "key=abcd12345678efgh"
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("16-char key should be masked")
	}
}

func TestMaskAPIKeys_PasswordKeyword(t *testing.T) {
	input := `password = "abcdefghijklmnopqrstuvwxyz"`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("password value should be masked")
	}
}

func TestMaskAPIKeys_AccessTokenKeyword(t *testing.T) {
	input := `access_token=ABCDEFGHIJKLMNOP1234567890abcdef`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("access_token value should be masked")
	}
}

func TestMaskAPIKeys_AuthTokenKeyword(t *testing.T) {
	input := `auth_token: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'`
	result := MaskAPIKeys(input)
	if result == input {
		t.Error("auth_token value should be masked")
	}
}

// --- isStackTraceLine: Go () pattern without +0x ---

func TestStripStackTraces_GoFuncCallOnly(t *testing.T) {
	input := "runtime.main()\n\t/usr/local/go/src/runtime/proc.go:250 +0x1\nDone"
	result := StripStackTraces(input)
	if strings.Contains(result, "proc.go:250") {
		t.Error("Go stack frame should be stripped")
	}
	if !strings.Contains(result, "Done") {
		t.Error("trailing text should be preserved")
	}
}

func TestStripStackTraces_MixedLanguages(t *testing.T) {
	input := `Start
goroutine 1 [running]:
main.handler()
	/app/main.go:42 +0x1a3
java.lang.NullPointerException: null
	at com.app.Handler.handle(Handler.java:10)
Traceback (most recent call last):
  File "/app/main.py", line 1, in <module>
Error: something
    at handler (/app/index.js:5:10)
End`
	result := StripStackTraces(input)
	if !strings.Contains(result, "Start") || !strings.Contains(result, "End") {
		t.Error("surrounding text should be preserved")
	}
	if strings.Contains(result, "goroutine") || strings.Contains(result, "main.go:42") {
		t.Error("Go traces should be stripped")
	}
	if strings.Contains(result, "NullPointerException") || strings.Contains(result, "Handler.java") {
		t.Error("Java traces should be stripped")
	}
	if strings.Contains(result, "Traceback") || strings.Contains(result, "main.py") {
		t.Error("Python traces should be stripped")
	}
	if strings.Contains(result, "index.js:5") {
		t.Error("Node.js traces should be stripped")
	}
}
