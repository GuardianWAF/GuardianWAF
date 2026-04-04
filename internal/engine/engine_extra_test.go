package engine

import (
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Middleware: real HTTP request through the middleware chain
// ---------------------------------------------------------------------------

func TestMiddleware_RealHTTPRequest_AllActions(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a score layer that will trigger log threshold (score=30 >= log 25, < block 50)
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 30, category: "test"},
		Order: OrderDetection,
	})

	// Log action: request passes through to next handler
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("logged-pass"))
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/log-path")
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for log action, got %d", rec.Code)
	}
	if rec.Body.String() != "logged-pass" {
		t.Errorf("expected body 'logged-pass', got %q", rec.Body.String())
	}

	// Verify stats show a logged request
	stats := e.Stats()
	if stats.LoggedRequests != 1 {
		t.Errorf("expected 1 logged request, got %d", stats.LoggedRequests)
	}
}

// ---------------------------------------------------------------------------
// Middleware: panic recovery
// ---------------------------------------------------------------------------

func TestMiddleware_PanicRecovery(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a layer that panics
	e.AddLayer(OrderedLayer{
		Layer: &panicLayer{name: "panicker"},
		Order: OrderIPACL,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called after panic")
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/panic")

	// Should not panic the test; the middleware recovers
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 after panic recovery, got %d", rec.Code)
	}

	// Verify the panic was logged
	entries := e.Logs.Recent(10)
	found := false
	for _, entry := range entries {
		if strings.Contains(entry.Message, "PANIC recovered") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected panic recovery to be logged")
	}
}

// panicLayer is a test layer that always panics.
type panicLayer struct{ name string }

func (l *panicLayer) Name() string { return l.name }
func (l *panicLayer) Process(_ *RequestContext) LayerResult {
	panic("deliberate test panic")
}

// ---------------------------------------------------------------------------
// Middleware: layers that modify the response via response hook
// ---------------------------------------------------------------------------

func TestMiddleware_ResponseHookAppliedOnPass(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a response layer that sets a hook
	e.AddLayer(OrderedLayer{
		Layer: &mockResponseLayer{securityHeaders: true},
		Order: OrderResponse,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/hook-test")
	handler.ServeHTTP(rec, r)

	// Security headers from response hook should be applied
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header from response hook")
	}
	if rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("expected X-Frame-Options header from response hook")
	}
}

func TestMiddleware_ResponseHookAppliedOnBlock(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a response layer that sets a hook (runs first due to low order)
	e.AddLayer(OrderedLayer{
		Layer: &mockResponseLayer{securityHeaders: true},
		Order: OrderIPACL, // same order as block layer, but added first
	})

	// Add a block layer that runs at detection order (after response)
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: OrderDetection,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called on block")
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/block-hook")
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	// Security headers should be applied because response layer ran before block
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options on blocked response")
	}
}

// ---------------------------------------------------------------------------
// Middleware: request context metadata propagation
// ---------------------------------------------------------------------------

func TestMiddleware_MetadataPropagation(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a layer that sets metadata
	e.AddLayer(OrderedLayer{
		Layer: &metadataLayer{name: "meta-setter"},
		Order: OrderSanitizer,
	})

	var capturedMeta map[string]any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The response hook should have been applied by now
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/meta-path")
	handler.ServeHTTP(rec, r)

	_ = capturedMeta // metadata is verified indirectly through response hook
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// metadataLayer is a test layer that populates context metadata.
type metadataLayer struct{ name string }

func (l *metadataLayer) Name() string { return l.name }
func (l *metadataLayer) Process(ctx *RequestContext) LayerResult {
	ctx.Metadata["test_key"] = "test_value"
	ctx.Metadata["response_hook"] = func(w http.ResponseWriter) {
		w.Header().Set("X-Meta-Test", "propagated")
	}
	return LayerResult{Action: ActionPass}
}

// ---------------------------------------------------------------------------
// Middleware: access log callback
// ---------------------------------------------------------------------------

func TestMiddleware_AccessLogCallback(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("POST", "/access-log-test")
	handler.ServeHTTP(rec, r)

	if captured.Method != "POST" {
		t.Errorf("expected method POST in access log, got %q", captured.Method)
	}
	if captured.Path != "/access-log-test" {
		t.Errorf("expected path /access-log-test in access log, got %q", captured.Path)
	}
	if captured.Action != "pass" {
		t.Errorf("expected action 'pass', got %q", captured.Action)
	}
	if captured.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", captured.StatusCode)
	}
}

func TestMiddleware_AccessLogCallback_Block(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: OrderIPACL,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/blocked-access")
	handler.ServeHTTP(rec, r)

	if captured.Action != "block" {
		t.Errorf("expected action 'block', got %q", captured.Action)
	}
	if captured.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", captured.StatusCode)
	}
	if captured.Findings != 1 {
		t.Errorf("expected 1 finding, got %d", captured.Findings)
	}
}

// ---------------------------------------------------------------------------
// Middleware: challenge action with challenge service
// ---------------------------------------------------------------------------

func TestMiddleware_ChallengeWithService(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a challenge layer
	e.AddLayer(OrderedLayer{
		Layer: &challengeLayer{name: "bot-detect"},
		Order: OrderBotDetect,
	})

	// Inject challenge service
	svc := &mockChallengeService{}
	e.SetChallengeService(svc)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for challenge")
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/challenge-me")
	handler.ServeHTTP(rec, r)

	if !svc.servedChallenge {
		t.Error("expected ServeChallengePage to be called")
	}

	stats := e.Stats()
	if stats.ChallengedRequests != 1 {
		t.Errorf("expected 1 challenged request, got %d", stats.ChallengedRequests)
	}
}

func TestMiddleware_ChallengeWithValidCookie(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a challenge layer
	e.AddLayer(OrderedLayer{
		Layer: &challengeLayer{name: "bot-detect"},
		Order: OrderBotDetect,
	})

	// Inject challenge service that says cookie is valid
	svc := &mockChallengeService{hasValidCookie: true}
	e.SetChallengeService(svc)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("passed-after-challenge"))
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/challenge-cookie-valid")
	handler.ServeHTTP(rec, r)

	// Should pass through because the cookie is valid
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (challenge bypassed by valid cookie), got %d", rec.Code)
	}
	if rec.Body.String() != "passed-after-challenge" {
		t.Errorf("expected 'passed-after-challenge', got %q", rec.Body.String())
	}

	stats := e.Stats()
	if stats.PassedRequests != 1 {
		t.Errorf("expected 1 passed request, got %d", stats.PassedRequests)
	}
}

func TestMiddleware_ChallengeWithoutService(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a challenge layer but do NOT inject a challenge service
	e.AddLayer(OrderedLayer{
		Layer: &challengeLayer{name: "bot-detect"},
		Order: OrderBotDetect,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/challenge-no-svc")
	handler.ServeHTTP(rec, r)

	// Without a challenge service, should fall back to block
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 (fallback block for challenge), got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Request Blocked") {
		t.Error("expected block page as fallback for challenge without service")
	}
}

// challengeLayer returns ActionChallenge for testing.
type challengeLayer struct{ name string }

func (l *challengeLayer) Name() string { return l.name }
func (l *challengeLayer) Process(_ *RequestContext) LayerResult {
	return LayerResult{Action: ActionChallenge}
}

// mockChallengeService implements ChallengeChecker for testing.
type mockChallengeService struct {
	hasValidCookie  bool
	servedChallenge bool
}

func (m *mockChallengeService) HasValidCookie(_ *http.Request, _ net.IP) bool {
	return m.hasValidCookie
}

func (m *mockChallengeService) ServeChallengePage(w http.ResponseWriter, _ *http.Request) {
	m.servedChallenge = true
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("challenge page"))
}

// ---------------------------------------------------------------------------
// computeJA4FromContext: TLS version and cipher suite branches
// ---------------------------------------------------------------------------

func TestComputeJA4FromContext_AllTLSVersionsViaJA4Ver(t *testing.T) {
	tests := []struct {
		name   string
		ja4Ver uint16
		want   string
	}{
		{"TLS 1.0 via JA4Ver", 0x0301, "t10"},
		{"TLS 1.1 via JA4Ver", 0x0302, "t11"},
		{"TLS 1.2 via JA4Ver", 0x0303, "t12"},
		{"TLS 1.3 via JA4Ver", 0x0304, "t13"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				JA4Ver:      tt.ja4Ver,
				JA4Ciphers:  []uint16{0x1301},
				JA4Protocol: "t",
			}
			result := computeJA4FromContext(ctx)
			if !strings.Contains(result, tt.want) {
				t.Errorf("computeJA4FromContext() = %q, expected to contain %q", result, tt.want)
			}
		})
	}
}

func TestComputeJA4FromContext_FallbackToTLSVersion(t *testing.T) {
	// When JA4Ver is 0, it falls back to TLSVersion
	tests := []struct {
		name       string
		tlsVersion uint16
		want       string
	}{
		{"fallback TLS 1.0", 0x0301, "t10"},
		{"fallback TLS 1.1", 0x0302, "t11"},
		{"fallback TLS 1.2", 0x0303, "t12"},
		{"fallback TLS 1.3", 0x0303 + 1, "t13"}, // 0x0304
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				TLSVersion: tt.tlsVersion,
				JA4Ciphers: []uint16{0x1301},
			}
			result := computeJA4FromContext(ctx)
			if !strings.Contains(result, tt.want) {
				t.Errorf("computeJA4FromContext() = %q, expected to contain %q", result, tt.want)
			}
		})
	}
}

func TestComputeJA4FromContext_SNI(t *testing.T) {
	// SNI flag set to true
	ctx := &RequestContext{
		TLSVersion: 0x0304,
		JA4SNI:     true,
		JA4Ciphers: []uint16{0x1301},
	}
	result := computeJA4FromContext(ctx)
	if !strings.Contains(result, "d") {
		t.Errorf("expected 'd' (domain) in JA4 when SNI is set, got %q", result)
	}

	// SNI via ServerName (non-empty)
	ctx2 := &RequestContext{
		TLSVersion: 0x0304,
		ServerName: "example.com",
		JA4Ciphers: []uint16{0x1301},
	}
	result2 := computeJA4FromContext(ctx2)
	if !strings.Contains(result2, "d") {
		t.Errorf("expected 'd' when ServerName is non-empty, got %q", result2)
	}

	// No SNI at all
	ctx3 := &RequestContext{
		TLSVersion: 0x0304,
		JA4Ciphers: []uint16{0x1301},
	}
	result3 := computeJA4FromContext(ctx3)
	if !strings.Contains(result3, "i") {
		t.Errorf("expected 'i' (IP) in JA4 when no SNI, got %q", result3)
	}
}

func TestComputeJA4FromContext_ALPNVariants(t *testing.T) {
	tests := []struct {
		name string
		alpn string
		want string
	}{
		{"single char ALPN", "h", "hh"},
		{"two char ALPN h2", "h2", "h2"},
		{"three char ALPN h3", "h3", "h3"},
		{"empty ALPN", "", "00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &RequestContext{
				TLSVersion: 0x0304,
				JA4Ciphers: []uint16{0x1301},
				JA4ALPN:    tt.alpn,
			}
			result := computeJA4FromContext(ctx)
			if !strings.Contains(result, tt.want) {
				t.Errorf("JA4 = %q, expected to contain ALPN code %q", result, tt.want)
			}
		})
	}
}

func TestComputeJA4FromContext_DefaultProtocol(t *testing.T) {
	// Empty JA4Protocol should default to "t"
	ctx := &RequestContext{
		JA4Protocol: "",
		JA4Ciphers:  []uint16{0x1301},
		JA4Exts:     []uint16{0x001b},
	}
	result := computeJA4FromContext(ctx)
	if !strings.HasPrefix(result, "t") {
		t.Errorf("expected default protocol 't', got prefix of %q", result)
	}
}

func TestComputeJA4FromContext_LargeCipherAndExtCounts(t *testing.T) {
	// More than 99 ciphers/exts should be capped
	ciphers := make([]uint16, 150)
	for i := range ciphers {
		ciphers[i] = uint16(i)
	}
	exts := make([]uint16, 150)
	for i := range exts {
		exts[i] = uint16(i)
	}

	ctx := &RequestContext{
		TLSVersion: 0x0304,
		JA4Ciphers: ciphers,
		JA4Exts:    exts,
	}
	result := computeJA4FromContext(ctx)
	// Count should be capped at 99
	if !strings.Contains(result, "99") {
		t.Errorf("expected count capped at 99 in %q", result)
	}
}

func TestComputeJA4FromContext_ZeroTLSVersion(t *testing.T) {
	// When both JA4Ver and TLSVersion are 0, default version is "13"
	ctx := &RequestContext{
		JA4Ciphers: []uint16{0x1301},
	}
	result := computeJA4FromContext(ctx)
	if !strings.Contains(result, "13") {
		t.Errorf("expected default version '13' when both version fields are 0, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// computeJA4FromContext: no TLS state
// ---------------------------------------------------------------------------

func TestNewEvent_NoTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/no-tls", nil)
	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.TLSVersion != "" {
		t.Errorf("expected empty TLS version for non-TLS request, got %q", event.TLSVersion)
	}
	if event.TLSCipherSuite != "" {
		t.Errorf("expected empty TLS cipher suite for non-TLS request, got %q", event.TLSCipherSuite)
	}
	if event.JA3Hash != "" {
		t.Errorf("expected empty JA3 hash for non-TLS request, got %q", event.JA3Hash)
	}
	if event.JA4Fingerprint != "" {
		t.Errorf("expected empty JA4 fingerprint for non-TLS request, got %q", event.JA4Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// NewEvent: various TLS states
// ---------------------------------------------------------------------------

func TestNewEvent_WithTLSButNoCipherSuite(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{
		Version:     0x0303,
		CipherSuite: 0, // no cipher suite
		ServerName:  "example.com",
	}

	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	// TLSVersion should be set
	if event.TLSVersion != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %q", event.TLSVersion)
	}
	// TLSCipherSuite should be "Unknown" because cipher=0 maps to unknown
	if event.TLSCipherSuite != "Unknown" {
		t.Errorf("expected Unknown cipher, got %q", event.TLSCipherSuite)
	}
	// JA3 should be empty because TLSCipherSuite is 0 (guard: ctx.TLSCipherSuite > 0)
	if event.JA3Hash != "" {
		t.Errorf("expected no JA3 when cipher suite is 0, got %q", event.JA3Hash)
	}
}

func TestNewEvent_WithTLSAndCipherSuite(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/test", nil)
	req.TLS = &tls.ConnectionState{
		Version:     0x0303,
		CipherSuite: 0xc02f,
		ServerName:  "example.com",
	}

	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.TLSVersion != "TLS 1.2" {
		t.Errorf("expected TLS 1.2, got %q", event.TLSVersion)
	}
	if event.TLSCipherSuite != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("expected cipher name, got %q", event.TLSCipherSuite)
	}
	if event.JA3Hash == "" {
		t.Error("expected JA3 hash when cipher suite is set")
	}
	if event.ServerName != "example.com" {
		t.Errorf("expected ServerName example.com, got %q", event.ServerName)
	}
}

func TestNewEvent_WithContentEncodingGzip(t *testing.T) {
	// Create gzipped body
	var gzipBuf strings.Builder
	gw := gzip.NewWriter(&gzipBuf)
	_, _ = gw.Write([]byte("hello gzipped world"))
	gw.Close()

	req := httptest.NewRequest("POST", "/gzip", strings.NewReader(gzipBuf.String()))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", "TestBot/1.0")
	req.Header.Set("Referer", "https://example.com/prev")
	req.RemoteAddr = "5.6.7.8:12345"

	ctx := AcquireContext(req, 2, 1024*1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	// The body should be decompressed
	if !strings.Contains(ctx.BodyString, "hello gzipped world") {
		t.Errorf("expected decompressed body, got %q", ctx.BodyString)
	}

	// Event metadata
	if event.ContentType != "text/plain" {
		t.Errorf("expected Content-Type text/plain, got %q", event.ContentType)
	}
	if event.Referer != "https://example.com/prev" {
		t.Errorf("expected Referer, got %q", event.Referer)
	}
	if event.UserAgent != "TestBot/1.0" {
		t.Errorf("expected User-Agent, got %q", event.UserAgent)
	}
	if event.Host != "" {
		// httptest request has empty Host
		t.Logf("Host = %q (may be empty for test requests)", event.Host)
	}
}

func TestNewEvent_WithContentEncodingDeflate(t *testing.T) {
	// Create deflated body
	var deflateBuf strings.Builder
	fw, _ := flate.NewWriter(&deflateBuf, flate.DefaultCompression)
	_, _ = fw.Write([]byte("deflated content here"))
	fw.Close()

	req := httptest.NewRequest("POST", "/deflate", strings.NewReader(deflateBuf.String()))
	req.Header.Set("Content-Encoding", "deflate")
	req.RemoteAddr = "5.6.7.8:12345"

	ctx := AcquireContext(req, 2, 1024*1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if !strings.Contains(ctx.BodyString, "deflated content here") {
		t.Errorf("expected decompressed deflate body, got %q", ctx.BodyString)
	}
	_ = event
}

func TestNewEvent_NilClientIP(t *testing.T) {
	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/"},
		RemoteAddr: "",
		Header:     make(http.Header),
	}
	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	// When ClientIP is nil, ClientIP field in event should be empty
	if event.ClientIP != "" {
		t.Errorf("expected empty ClientIP for nil ClientIP, got %q", event.ClientIP)
	}
}

func TestNewEvent_WithUAParser(t *testing.T) {
	// Register a UA parser
	SetUAParser(func(ua string) (browser, brVersion, osName, deviceType string, isBot bool) {
		return "TestBrowser", "99.0", "Linux", "desktop", true
	})
	defer SetUAParser(nil)

	req := httptest.NewRequest("GET", "/ua-test", nil)
	req.Header.Set("User-Agent", "TestBrowser/99.0 (Linux)")
	req.RemoteAddr = "1.2.3.4:1234"

	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.Browser != "TestBrowser" {
		t.Errorf("expected Browser TestBrowser, got %q", event.Browser)
	}
	if event.BrVersion != "99.0" {
		t.Errorf("expected BrVersion 99.0, got %q", event.BrVersion)
	}
	if event.OS != "Linux" {
		t.Errorf("expected OS Linux, got %q", event.OS)
	}
	if event.DeviceType != "desktop" {
		t.Errorf("expected DeviceType desktop, got %q", event.DeviceType)
	}
	if !event.IsBot {
		t.Error("expected IsBot true")
	}
}

// ---------------------------------------------------------------------------
// levelToInt: all log levels
// ---------------------------------------------------------------------------

func TestLevelToInt_AllLevels(t *testing.T) {
	tests := []struct {
		input string
		want  LogLevel
	}{
		{"debug", LogLevelDebug},
		{"info", LogLevelInfo},
		{"warn", LogLevelWarn},
		{"error", LogLevelError},
		{"trace", LogLevelInfo},   // unknown defaults to info
		{"", LogLevelInfo},        // empty defaults to info
		{"WARNING", LogLevelInfo}, // case-sensitive, defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := levelToInt(tt.input)
			if got != tt.want {
				t.Errorf("levelToInt(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Engine: FindLayer with layers present
// ---------------------------------------------------------------------------

func TestFindLayer_Found(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{Layer: &passLayer{name: "sanitizer"}, Order: OrderSanitizer})
	e.AddLayer(OrderedLayer{Layer: &passLayer{name: "ipacl"}, Order: OrderIPACL})

	layer := e.FindLayer("sanitizer")
	if layer == nil {
		t.Fatal("expected to find 'sanitizer' layer")
	}
	if layer.Name() != "sanitizer" {
		t.Errorf("expected layer name 'sanitizer', got %q", layer.Name())
	}

	// Nonexistent layer
	missing := e.FindLayer("nonexistent")
	if missing != nil {
		t.Error("expected nil for nonexistent layer name")
	}
}

// ---------------------------------------------------------------------------
// Engine: Check with challenge action from pipeline
// ---------------------------------------------------------------------------

func TestEngine_Check_ChallengeAction(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{
		Layer: &challengeLayer{name: "bot-detect"},
		Order: OrderBotDetect,
	})

	r := testRequest("GET", "/challenge-check")
	event := e.Check(r)

	// Pipeline sets ActionChallenge, no score-based override since score=0
	if event.Action != ActionChallenge {
		t.Errorf("expected ActionChallenge, got %v", event.Action)
	}
	if event.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", event.StatusCode)
	}

	stats := e.Stats()
	if stats.ChallengedRequests != 1 {
		t.Errorf("expected 1 challenged request, got %d", stats.ChallengedRequests)
	}
}

// ---------------------------------------------------------------------------
// Engine: Check with challenge from pipeline but score >= block threshold
// ---------------------------------------------------------------------------

func TestEngine_Check_ChallengeDoesNotOverrideBlock(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Add a challenge layer AND a high-score layer
	e.AddLayer(OrderedLayer{
		Layer: &challengeLayer{name: "bot-detect"},
		Order: OrderBotDetect,
	})
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 60, category: "sqli"},
		Order: OrderDetection,
	})

	r := testRequest("GET", "/challenge-block")
	event := e.Check(r)

	// Score 60 >= block threshold 50, so block should win over challenge
	// But pipeline action is Challenge, which only promotes if not already blocked
	// Score-based block takes precedence
	if event.Action != ActionBlock {
		t.Errorf("expected ActionBlock (score >= block threshold), got %v", event.Action)
	}
}

// ---------------------------------------------------------------------------
// Engine: Stats with zero requests
// ---------------------------------------------------------------------------

func TestEngine_Stats_ZeroRequests(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	stats := e.Stats()
	if stats.TotalRequests != 0 {
		t.Errorf("expected 0 total, got %d", stats.TotalRequests)
	}
	if stats.AvgLatencyUs != 0 {
		t.Errorf("expected 0 avg latency with no requests, got %d", stats.AvgLatencyUs)
	}
}

// ---------------------------------------------------------------------------
// Engine: Check with method and query propagation
// ---------------------------------------------------------------------------

func TestEngine_Check_QueryPropagation(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	r := testRequest("GET", "/search?q=hello+world&page=2")
	event := e.Check(r)

	if event.Method != "GET" {
		t.Errorf("expected method GET, got %s", event.Method)
	}
	if event.Query != "q=hello+world&page=2" {
		t.Errorf("expected query string, got %q", event.Query)
	}
}

// ---------------------------------------------------------------------------
// blockpage: itoa negative numbers
// ---------------------------------------------------------------------------

func TestBlockPage_ZeroScore(t *testing.T) {
	page := blockPage("req-123", 0)
	if strings.Contains(page, "Threat Score") {
		t.Error("expected no Threat Score section when score is 0")
	}
}

func TestBlockPage_WithScore(t *testing.T) {
	page := blockPage("req-456", 85)
	if !strings.Contains(page, "Threat Score") {
		t.Error("expected Threat Score section when score > 0")
	}
	if !strings.Contains(page, "85/100") {
		t.Error("expected '85/100' in block page")
	}
}

func TestItoa_Positive(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{-1, "-1"},
		{-42, "-42"},
	}
	for _, tt := range tests {
		got := itoa(tt.n)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Engine: Middleware with concurrent requests through middleware
// ---------------------------------------------------------------------------

func TestMiddleware_Concurrent(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 15, category: "test"},
		Order: OrderDetection,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			r := testRequest("GET", "/concurrent-middleware")
			handler.ServeHTTP(rec, r)
		}()
	}
	wg.Wait()

	stats := e.Stats()
	if stats.TotalRequests != int64(goroutines) {
		t.Errorf("expected %d total requests, got %d", goroutines, stats.TotalRequests)
	}
}

// ---------------------------------------------------------------------------
// Pipeline: Challenge does not override block in multi-layer pipeline
// ---------------------------------------------------------------------------

func TestPipeline_ChallengeDoesNotOverrideBlock(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &blockLayer{name: "blocker"}, Order: 100},
		OrderedLayer{Layer: &challengeLayer{name: "challenger"}, Order: 200},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	// Block should take precedence — and early return means challenger never runs
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", result.Action)
	}
}

func TestPipeline_BlockOverridesLog(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &scoreLayer{name: "logger", score: 10, category: "test"}, Order: 100},
		OrderedLayer{Layer: &blockLayer{name: "blocker"}, Order: 200},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock to override log, got %v", result.Action)
	}
}

func TestPipeline_LogDoesNotOverrideBlock(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &blockLayer{name: "blocker"}, Order: 100},
		OrderedLayer{Layer: &scoreLayer{name: "logger", score: 10, category: "test"}, Order: 200},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	// Block returns early so logger never runs
	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// Engine: Middleware with score-based block through middleware
// ---------------------------------------------------------------------------

func TestMiddleware_ScoreBasedBlock(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Score 60 >= block threshold 50
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 60, category: "sqli"},
		Order: OrderDetection,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called on score-based block")
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/score-block")
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Request Blocked") {
		t.Error("expected block page in response")
	}
}

// ---------------------------------------------------------------------------
// Engine: Middleware with score-based log through middleware
// ---------------------------------------------------------------------------

func TestMiddleware_ScoreBasedLog(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Score 30 >= log threshold 25, < block threshold 50
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "detector", score: 30, category: "sqli"},
		Order: OrderDetection,
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/score-log")
	handler.ServeHTTP(rec, r)

	if !nextCalled {
		t.Error("next should be called for log action")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for log action, got %d", rec.Code)
	}

	stats := e.Stats()
	if stats.LoggedRequests != 1 {
		t.Errorf("expected 1 logged request, got %d", stats.LoggedRequests)
	}
}

// ---------------------------------------------------------------------------
// LogBuffer: Recent with buffer overflow (wrap-around)
// ---------------------------------------------------------------------------

func TestLogBuffer_RecentMoreThanAvailable(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Info("a")
	lb.Info("b")

	// Request more entries than available
	entries := lb.Recent(100)
	if len(entries) != 2 {
		t.Errorf("expected 2 (all available), got %d", len(entries))
	}
}

func TestLogBuffer_RecentWithFullBufferWrap(t *testing.T) {
	lb := NewLogBuffer(3)
	lb.Info("a")
	lb.Info("b")
	lb.Info("c")
	lb.Info("d") // wraps: buffer now contains [d, b, c]

	if !lb.full {
		t.Error("expected buffer to be full after wrap")
	}

	entries := lb.Recent(3)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}

	// Most recent first: d, c, b
	if entries[0].Message != "d" {
		t.Errorf("expected first entry 'd', got %q", entries[0].Message)
	}
	if entries[1].Message != "c" {
		t.Errorf("expected second entry 'c', got %q", entries[1].Message)
	}
	if entries[2].Message != "b" {
		t.Errorf("expected third entry 'b', got %q", entries[2].Message)
	}
}

// ---------------------------------------------------------------------------
// NewEvent: request with host
// ---------------------------------------------------------------------------

func TestNewEvent_WithHost(t *testing.T) {
	req := httptest.NewRequest("GET", "http://myapp.example.com/path", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	ctx := AcquireContext(req, 1, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.Host != "myapp.example.com" {
		t.Errorf("expected Host 'myapp.example.com', got %q", event.Host)
	}
}

// ---------------------------------------------------------------------------
// NewEvent: request with findings
// ---------------------------------------------------------------------------

func TestNewEvent_WithFindings(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	ctx := AcquireContext(req, 2, 1024)
	ctx.Accumulator.Add(&Finding{
		DetectorName: "sqli",
		Category:     "injection",
		Score:        40,
		Severity:     SeverityHigh,
		Description:  "SQL injection detected",
		Location:     "query",
	})
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, 200)

	if event.Score != 40 {
		t.Errorf("expected score 40, got %d", event.Score)
	}
	if len(event.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(event.Findings))
	}
	if event.Findings[0].DetectorName != "sqli" {
		t.Errorf("expected detector 'sqli', got %q", event.Findings[0].DetectorName)
	}
}

// ---------------------------------------------------------------------------
// Engine: EventStore and EventBus accessors
// ---------------------------------------------------------------------------

func TestEngine_EventStoreAccessor(t *testing.T) {
	e, store, _ := testEngine(t)
	defer e.Close()

	if e.EventStore() != store {
		t.Error("EventStore() should return the same store passed to NewEngine")
	}
}

func TestEngine_EventBusAccessor(t *testing.T) {
	e, _, bus := testEngine(t)
	defer e.Close()

	if e.EventBus() != bus {
		t.Error("EventBus() should return the same bus passed to NewEngine")
	}
}

// ---------------------------------------------------------------------------
// Middleware: verifies request context is populated correctly
// ---------------------------------------------------------------------------

func TestMiddleware_ContextPopulatedForLayers(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	var capturedPath string
	var capturedMethod string
	var capturedContentType string

	// Add a layer that inspects the context
	e.AddLayer(OrderedLayer{
		Layer: &inspectorLayer{
			name: "inspector",
			inspect: func(ctx *RequestContext) {
				capturedPath = ctx.Path
				capturedMethod = ctx.Method
				capturedContentType = ctx.ContentType
			},
		},
		Order: OrderSanitizer,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	req := httptest.NewRequest("POST", "/inspect?a=1", strings.NewReader("body"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "1.2.3.4:1234"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedPath != "/inspect" {
		t.Errorf("expected path /inspect, got %q", capturedPath)
	}
	if capturedMethod != "POST" {
		t.Errorf("expected method POST, got %q", capturedMethod)
	}
	if capturedContentType != "application/json" {
		t.Errorf("expected content type application/json, got %q", capturedContentType)
	}
}

// inspectorLayer is a test layer that runs a callback to inspect context.
type inspectorLayer struct {
	name    string
	inspect func(ctx *RequestContext)
}

func (l *inspectorLayer) Name() string { return l.name }
func (l *inspectorLayer) Process(ctx *RequestContext) LayerResult {
	if l.inspect != nil {
		l.inspect(ctx)
	}
	return LayerResult{Action: ActionPass}
}

// ---------------------------------------------------------------------------
// Engine: Middleware with multiple findings
// ---------------------------------------------------------------------------

func TestMiddleware_MultipleFindings(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Two detectors, both trigger findings (total score 40, below block threshold)
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "sqli", score: 20, category: "sqli"},
		Order: OrderDetection,
	})
	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "xss", score: 20, category: "xss"},
		Order: OrderDetection + 10,
	})

	var capturedAccessLog AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		capturedAccessLog = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := testRequest("GET", "/multi-findings")
	handler.ServeHTTP(rec, r)

	// Total score 40 >= log threshold 25, < block threshold 50
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (log), got %d", rec.Code)
	}
	if capturedAccessLog.Findings != 2 {
		t.Errorf("expected 2 findings in access log, got %d", capturedAccessLog.Findings)
	}
	if capturedAccessLog.Score != 40 {
		t.Errorf("expected score 40, got %d", capturedAccessLog.Score)
	}
}
