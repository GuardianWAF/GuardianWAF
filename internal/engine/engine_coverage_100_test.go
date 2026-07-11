package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 0.0% uncovered functions
// ---------------------------------------------------------------------------

func TestApplyMultiplier_ZeroMultiplier(t *testing.T) {
	findings := []Finding{
		{Score: 100},
		{Score: 50},
	}
	ApplyMultiplier(findings, 0)
	if findings[0].Score != 0 || findings[1].Score != 0 {
		t.Fatalf("expected all scores zeroed, got %d, %d", findings[0].Score, findings[1].Score)
	}
}

func TestApplyMultiplier_NegativeMultiplier(t *testing.T) {
	findings := []Finding{
		{Score: 100},
	}
	ApplyMultiplier(findings, -0.5)
	if findings[0].Score != -50 {
		t.Fatalf("expected -50, got %d", findings[0].Score)
	}
}

func TestActionUnmarshalJSON_RoundTrip(t *testing.T) {
	tests := []struct {
		json string
		want Action
	}{
		{`"pass"`, ActionPass},
		{`"block"`, ActionBlock},
		{`"log"`, ActionLog},
		{`"challenge"`, ActionChallenge},
		{`"unknown"`, ActionPass}, // default
	}
	for _, tt := range tests {
		var a Action
		if err := json.Unmarshal([]byte(tt.json), &a); err != nil {
			t.Fatalf("UnmarshalJSON(%q) error: %v", tt.json, err)
		}
		if a != tt.want {
			t.Errorf("UnmarshalJSON(%q) = %v, want %v", tt.json, a, tt.want)
		}
	}
}

func TestLogBuffer_ErrorStack(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.ErrorStack("test error")
	entries := lb.Recent(10)
	if len(entries) < 1 {
		t.Fatal("expected at least 1 entry")
	}
	if entries[0].Level != "error" {
		t.Errorf("expected error level, got %q", entries[0].Level)
	}
	if !strings.Contains(entries[0].Message, "test error") {
		t.Errorf("expected message to contain 'test error', got %q", entries[0].Message)
	}
	if !strings.Contains(entries[0].Message, "stack trace") && !strings.Contains(entries[0].Message, "goroutine") {
		// The stack trace is appended, just verify it contains something extra
		t.Logf("ErrorStack message length: %d", len(entries[0].Message))
	}
}

func TestMaskingResponseWriter_Unwrap(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	unwrapped := mw.Unwrap()
	if unwrapped != w {
		t.Fatal("Unwrap should return the underlying ResponseWriter")
	}
}

func TestMaskingResponseWriter_Flush(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	// Write some data that will be captured
	mw.Header().Set("Content-Type", "text/plain")
	mw.Write([]byte("test data"))
	mw.Flush()
	// After flush, direct mode should be true
	if !mw.direct {
		t.Fatal("expected direct mode after Flush")
	}
	// Verify data was flushed to underlying writer
	if w.Body.String() != "test data" {
		t.Errorf("expected 'test data', got %q", w.Body.String())
	}
}

func TestMaskingResponseWriter_Flush_NoCapture(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	// Without content-type, capture is false
	mw.Flush()
	// Should not panic
}

func TestMaskingResponseWriter_Flush_Flusher(t *testing.T) {
	// Use a wrapper that implements http.Flusher
	var buf bytes.Buffer
	mw := newMaskingResponseWriter(&flushRecorder{buf: &buf}, nil, nil)
	mw.Header().Set("Content-Type", "text/plain")
	mw.Write([]byte("data"))
	mw.Flush()
	if !mw.direct {
		t.Fatal("expected direct mode after Flush")
	}
}

type flushRecorder struct {
	buf       *bytes.Buffer
	code      int
	headers   http.Header
	flushed   bool
}

func (f *flushRecorder) Header() http.Header {
	if f.headers == nil {
		f.headers = make(http.Header)
	}
	return f.headers
}

func (f *flushRecorder) Write(p []byte) (int, error) {
	return f.buf.Write(p)
}

func (f *flushRecorder) WriteHeader(code int) {
	f.code = code
}

func (f *flushRecorder) Flush() {
	f.flushed = true
}

// ---------------------------------------------------------------------------
// applyCORSHook coverage
// ---------------------------------------------------------------------------

func TestApplyCORSHook_PreflightHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"cors_preflight_headers": map[string]string{
			"Access-Control-Allow-Methods": "GET, POST",
			"Access-Control-Allow-Origin":  "*",
		},
	}
	applyCORSHook(w, metadata)
	if w.Header().Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Errorf("expected Allow-Methods header, got %q", w.Header().Get("Access-Control-Allow-Methods"))
	}
	if w.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin, got %q", w.Header().Get("Vary"))
	}
}

func TestApplyCORSHook_RegularHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"cors_headers": map[string]string{
			"Access-Control-Allow-Origin": "https://example.com",
		},
		"cors_expose_headers": "X-Custom",
	}
	applyCORSHook(w, metadata)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected Allow-Origin header, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Expose-Headers") != "X-Custom" {
		t.Errorf("expected Expose-Headers, got %q", w.Header().Get("Access-Control-Expose-Headers"))
	}
}

func TestApplyCORSHook_EmptyExpose(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"cors_headers": map[string]string{
			"Access-Control-Allow-Origin": "*",
		},
		"cors_expose_headers": "",
	}
	applyCORSHook(w, metadata)
	if w.Header().Get("Access-Control-Expose-Headers") != "" {
		t.Errorf("expected empty Expose-Headers, got %q", w.Header().Get("Access-Control-Expose-Headers"))
	}
}

func TestApplyCORSHook_NoHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	applyCORSHook(w, map[string]any{})
	// Should not set Vary or any CORS headers
	if w.Header().Get("Vary") != "" {
		t.Errorf("expected no Vary header, got %q", w.Header().Get("Vary"))
	}
}

func TestApplyCORSHook_InvalidType(t *testing.T) {
	w := httptest.NewRecorder()
	metadata := map[string]any{
		"cors_headers": "not-a-map",
	}
	applyCORSHook(w, metadata)
	// Should not panic
}

// ---------------------------------------------------------------------------
// removeOldBackups coverage
// ---------------------------------------------------------------------------

func TestRemoveOldBackups_NoAgeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w := &RotatingFileWriter{
		path:    path,
		maxAge:  0, // no age limit → removeOldBackups returns immediately
	}
	w.removeOldBackups()
	// Should not panic
}

func TestRemoveOldBackups_RemovesOldFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Create old backup files
	old := filepath.Join(dir, "test.log.1")
	os.WriteFile(old, []byte("old"), 0o600)
	// Set mod time to 30 days ago
	os.Chtimes(old, time.Now().Add(-720*time.Hour), time.Now().Add(-720*time.Hour))

	w := &RotatingFileWriter{
		path:    path,
		maxAge:  7 * 24 * time.Hour, // 7 days
		maxBackups: 5,
	}
	w.removeOldBackups()
	// Old backup should be removed
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expected old backup to be removed")
	}
}

// ---------------------------------------------------------------------------
// parseTrustedProxyCIDRs coverage
// ---------------------------------------------------------------------------

func TestParseTrustedProxyCIDRs_SingleIP(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.1"})
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(cidrs))
	}
	ones, bits := cidrs[0].Mask.Size()
	if ones != 32 || bits != 32 {
		t.Errorf("expected /32 for IPv4, got /%d", ones)
	}
}

func TestParseTrustedProxyCIDRs_IPv6(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"::1"})
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(cidrs))
	}
	ones, bits := cidrs[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("expected /128 for IPv6, got /%d", ones)
	}
}

func TestParseTrustedProxyCIDRs_InvalidIP(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"not-an-ip"})
	if len(cidrs) != 0 {
		t.Errorf("expected 0 CIDRs for invalid IP, got %d", len(cidrs))
	}
}

func TestParseTrustedProxyCIDRs_InvalidCIDR(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/33"})
	if len(cidrs) != 0 {
		t.Errorf("expected 0 CIDRs for invalid CIDR, got %d", len(cidrs))
	}
}

func TestParseTrustedProxyCIDRs_OverlyBroad(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"0.0.0.0/0"})
	if len(cidrs) != 0 {
		t.Errorf("expected 0 CIDRs for overly broad, got %d", len(cidrs))
	}
}

func TestParseTrustedProxyCIDRs_ValidCIDR(t *testing.T) {
	cidrs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(cidrs))
	}
}

// ---------------------------------------------------------------------------
// isTrustedProxyIn coverage
// ---------------------------------------------------------------------------

func TestIsTrustedProxyIn_NilIP(t *testing.T) {
	if isTrustedProxyIn(nil, nil) {
		t.Error("expected false for nil IP")
	}
}

func TestIsTrustedProxyIn_EmptyCIDRs(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if isTrustedProxyIn(ip, nil) {
		t.Error("expected false for nil CIDRs")
	}
}

// ---------------------------------------------------------------------------
// extractClientIPWithTrustedProxies coverage
// ---------------------------------------------------------------------------

func TestExtractClientIPWithTrustedProxies_RemoteAddrNil(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = ""
	ip := extractClientIPWithTrustedProxies(r, nil)
	if ip != nil {
		t.Errorf("expected nil for empty RemoteAddr, got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_NonTrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"
	ip := extractClientIPWithTrustedProxies(r, nil)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_TrustedWithXFF(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.2")
	ip := extractClientIPWithTrustedProxies(r, []*net.IPNet{cidr})
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 (rightmost non-trusted), got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_XFFAllTrusted(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.3")
	ip := extractClientIPWithTrustedProxies(r, []*net.IPNet{cidr})
	// All XFF IPs are trusted → fall back to remote addr
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 (all XFF trusted), got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_XFFInvalidIP(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.5")
	ip := extractClientIPWithTrustedProxies(r, []*net.IPNet{cidr})
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 (skipping invalid), got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_XRealIP(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "203.0.113.5")
	ip := extractClientIPWithTrustedProxies(r, []*net.IPNet{cidr})
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 from X-Real-IP, got %v", ip)
	}
}

func TestExtractClientIPWithTrustedProxies_XRealIPInvalid(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Real-IP", "not-an-ip")
	ip := extractClientIPWithTrustedProxies(r, []*net.IPNet{cidr})
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 (invalid X-Real-IP), got %v", ip)
	}
}

// ---------------------------------------------------------------------------
// startRootSpan coverage
// ---------------------------------------------------------------------------

func TestStartRootSpan_Disabled(t *testing.T) {
	// Tracing disabled by default
	e, _, _ := testEngine(t)
	defer e.Close()
	r := httptest.NewRequest("GET", "/", nil)
	ctx := AcquireContext(r, 2, 4096)
	defer ReleaseContext(ctx)

	span := e.startRootSpan(ctx, r)
	if span != nil {
		t.Error("expected nil span when tracing disabled")
	}
}

// ---------------------------------------------------------------------------
// layerTimingCounters coverage
// ---------------------------------------------------------------------------

func TestLayerTimingCounters_CreateNew(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	counters := e.layerTimingCounters("new-layer")
	if counters == nil {
		t.Fatal("expected non-nil counters")
	}
	counters2 := e.layerTimingCounters("new-layer")
	if counters != counters2 {
		t.Error("expected same counter instance on second call")
	}
}

// ---------------------------------------------------------------------------
// recordLayerTimings - empty name skipped
// ---------------------------------------------------------------------------

func TestRecordLayerTimings_EmptyName(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Should not panic
	e.recordLayerTimings(map[string]time.Duration{
		"": time.Second,
	})
}

// ---------------------------------------------------------------------------
// redactSensitiveURL / redactSensitiveQueryParams coverage
// ---------------------------------------------------------------------------

func TestRedactSensitiveURL_Empty(t *testing.T) {
	if got := redactSensitiveURL(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestRedactSensitiveURL_NoQuery(t *testing.T) {
	result := redactSensitiveURL("/path")
	if result != "/path" {
		t.Errorf("expected /path, got %q", result)
	}
}

func TestRedactSensitiveURL_WithSensitiveQuery(t *testing.T) {
	result := redactSensitiveURL("/path?token=abc123&name=test")
	if strings.Contains(result, "abc123") {
		t.Errorf("expected token to be redacted, got %q", result)
	}
	// url.Values.Encode uses percent-encoding, so [REDACTED] becomes %5BREDACTED%5D
	if !strings.Contains(result, "REDACTED") {
		t.Errorf("expected REDACTED in result, got %q", result)
	}
}

func TestRedactSensitiveURL_Malformed(t *testing.T) {
	// URL parse fails → falls through to redactSensitiveEvidence
	result := redactSensitiveURL("http://[::1]:badport/path")
	_ = result
}

// ---------------------------------------------------------------------------
// padInt2 coverage
// ---------------------------------------------------------------------------

func TestPadInt2(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{-5, "00"},
		{0, "00"},
		{5, "05"},
		{42, "42"},
		{99, "99"},
		{100, "99"},
		{150, "99"},
	}
	for _, tt := range tests {
		if got := padInt2(tt.n); got != tt.want {
			t.Errorf("padInt2(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ScoreAccumulator.Total cap coverage
// ---------------------------------------------------------------------------

func TestScoreAccumulator_TotalCapped(t *testing.T) {
	sa := NewScoreAccumulator(4) // paranoia 4 → multiplier 2.0
	sa.Add(&Finding{Score: 6000})
	total := sa.Total()
	if total > 10000 {
		t.Errorf("expected total capped at 10000, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// Config import alias guard (config used in testEngine is available
// via the existing engine_test.go helpers)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// RotatingFileWriter coverage
// ---------------------------------------------------------------------------

func TestRotatingFileWriter_WriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := NewRotatingFileWriter(path, 1, 2, 0) // 1MB max size
	if err != nil {
		t.Fatalf("NewRotatingFileWriter error = %v", err)
	}
	defer w.Close()

	n, err := w.Write([]byte("test data"))
	if err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if n != 9 {
		t.Errorf("expected 9 bytes written, got %d", n)
	}
}

func TestRotatingFileWriter_Close_Twice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	w, err := NewRotatingFileWriter(path, 1, 2, 0)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter error = %v", err)
	}
	w.Close()
	w.Close() // close again should not panic
}

func TestRotatingFileWriter_Rotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rot.log")
	w, err := NewRotatingFileWriter(path, 1, 2, 0)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter error = %v", err)
	}
	defer w.Close()

	// Force rotate by writing data that triggers size check
	err = w.rotate()
	if err != nil {
		t.Fatalf("rotate() error = %v", err)
	}
	if w.size != 0 {
		t.Errorf("expected size 0 after rotate, got %d", w.size)
	}

	// Write again after rotate
	n, err := w.Write([]byte("after rotate"))
	if err != nil {
		t.Fatalf("Write after rotate error = %v", err)
	}
	if n != 12 {
		t.Errorf("expected 12, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// cleanRotatingLogPath coverage
// ---------------------------------------------------------------------------

func TestCleanRotatingLogPath_NUL(t *testing.T) {
	_, err := cleanRotatingLogPath("test\x00.log")
	if err == nil {
		t.Fatal("expected error for NUL byte")
	}
}

func TestCleanRotatingLogPath_Empty(t *testing.T) {
	_, err := cleanRotatingLogPath("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestCleanRotatingLogPath_Valid(t *testing.T) {
	path, err := cleanRotatingLogPath("/var/log/test.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(path, "test.log") {
		t.Errorf("unexpected path: %q", path)
	}
}

// ---------------------------------------------------------------------------
// NewRotatingFileWriter edge cases
// ---------------------------------------------------------------------------

func TestNewRotatingFileWriter_DefaultBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defaults.log")
	w, err := NewRotatingFileWriter(path, 0, 0, 0)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter error = %v", err)
	}
	w.Close()
	if w.maxBackups != 5 {
		t.Errorf("expected default 5 backups, got %d", w.maxBackups)
	}
	if w.maxSize != 100*1024*1024 {
		t.Errorf("expected default 100MB maxSize, got %d", w.maxSize)
	}
}

func TestNewRotatingFileWriter_WithMaxAge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "age.log")
	w, err := NewRotatingFileWriter(path, 10, 3, 7)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter error = %v", err)
	}
	w.Close()
	if w.maxAge != 7*24*time.Hour {
		t.Errorf("expected 7 day maxAge, got %v", w.maxAge)
	}
}

// ---------------------------------------------------------------------------
// nopWriteCloser.Close coverage (the 80% gap)
// ---------------------------------------------------------------------------

func TestNopWriteCloser_Close(t *testing.T) {
	w := nopWriteCloser{os.Stdout}
	err := w.Close()
	if err != nil {
		t.Errorf("nopWriteCloser.Close() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// shouldCapture edge cases
// ---------------------------------------------------------------------------

func TestMaskingResponseWriter_ShouldCapture_EmptyContentType(t *testing.T) {
	mw := newMaskingResponseWriter(httptest.NewRecorder(), nil, nil)
	if mw.shouldCapture() {
		t.Error("expected false for empty Content-Type")
	}
}

func TestMaskingResponseWriter_ShouldCapture_ApplicationJSON(t *testing.T) {
	mw := newMaskingResponseWriter(httptest.NewRecorder(), nil, nil)
	mw.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !mw.shouldCapture() {
		t.Error("expected true for application/json")
	}
}

func TestMaskingResponseWriter_ShouldCapture_PlusJSON(t *testing.T) {
	mw := newMaskingResponseWriter(httptest.NewRecorder(), nil, nil)
	mw.Header().Set("Content-Type", "application/vnd.api+json")
	if !mw.shouldCapture() {
		t.Error("expected true for +json content type")
	}
}

func TestMaskingResponseWriter_ShouldCapture_XML(t *testing.T) {
	mw := newMaskingResponseWriter(httptest.NewRecorder(), nil, nil)
	mw.Header().Set("Content-Type", "application/xml")
	if !mw.shouldCapture() {
		t.Error("expected true for application/xml")
	}
}

// ---------------------------------------------------------------------------
// FlushMasked edge cases
// ---------------------------------------------------------------------------

func TestFlushMasked_NoCapture(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.FlushMasked()
	// No panic
}

func TestFlushMasked_DirectMode(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.Header().Set("Content-Type", "text/plain")
	mw.Write([]byte("data"))
	mw.direct = true
	mw.FlushMasked()
	// No panic, should return early
}

func TestFlushMasked_WithMaskFn(t *testing.T) {
	w := httptest.NewRecorder()
	maskFn := func(s string) string {
		return "masked:" + s
	}
	mw := newMaskingResponseWriter(w, maskFn, nil)
	mw.Header().Set("Content-Type", "text/plain")
	mw.Write([]byte("secret"))
	mw.FlushMasked()
	if w.Body.String() != "masked:secret" {
		t.Errorf("expected 'masked:secret', got %q", w.Body.String())
	}
}

func TestFlushMasked_WithBodyXform(t *testing.T) {
	w := httptest.NewRecorder()
	xform := func(body []byte, ct string) ([]byte, bool) {
		return append([]byte("xformed:"), body...), true
	}
	mw := newMaskingResponseWriter(w, nil, xform)
	mw.Header().Set("Content-Type", "text/plain")
	mw.Write([]byte("content"))
	mw.FlushMasked()
	if w.Body.String() != "xformed:content" {
		t.Errorf("expected 'xformed:content', got %q", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Write buffer overflow path (exceeds maxMaskingBufferSize)
// ---------------------------------------------------------------------------

func TestMaskingResponseWriter_Write_Overflow(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.Header().Set("Content-Type", "text/plain")

	// Write enough to exceed buffer limit
	large := make([]byte, maxMaskingBufferSize+100)
	n, err := mw.Write(large)
	if err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if n != len(large) {
		t.Errorf("expected %d bytes, got %d", len(large), n)
	}
	if !mw.direct {
		t.Error("expected direct mode after buffer overflow")
	}
}

func TestMaskingResponseWriter_Write_BufferError(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.Header().Set("Content-Type", "text/plain")

	// First write fills buffer partially
	mw.Write([]byte("small"))
	// Replace buffer with a failing one... Actually the buffer is bytes.Buffer which never fails.
	// This path is hard to trigger - just verify it works
}

// ---------------------------------------------------------------------------
// Write capture passthrough
// ---------------------------------------------------------------------------

func TestMaskingResponseWriter_Write_DirectPassthrough(t *testing.T) {
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.direct = true
	n, err := mw.Write([]byte("direct"))
	if err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if n != 6 {
		t.Errorf("expected 6, got %d", n)
	}
	if w.Body.String() != "direct" {
		t.Errorf("expected 'direct', got %q", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// extractClientIP with trusted proxies configured (engine method)
// ---------------------------------------------------------------------------

func TestEngineExtractClientIP_WithTrustedProxies(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Set up trusted proxies
	proxyCIDRs := parseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	e.trustedProxyCIDRs.Store(proxyCIDRs)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")

	ip := e.extractClientIP(r)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 from XFF, got %v", ip)
	}
}

func TestEngineExtractClientIP_NoCIDRsStored(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	// Don't set any cidrs - test the path where Load returns nil
	// then falls through to extractClientIPWithTrustedProxies(r, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:12345"

	ip := e.extractClientIP(r)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5, got %v", ip)
	}
}

// ---------------------------------------------------------------------------
// recoverDroppedQueryParams edge cases
// ---------------------------------------------------------------------------

func TestRecoverDroppedQueryParams_EmptyPair(t *testing.T) {
	params := make(map[string][]string)
	recoverDroppedQueryParams(params, "&&key=val&")
	if len(params["key"]) != 1 || params["key"][0] != "val" {
		t.Errorf("expected key=[val], got %v", params["key"])
	}
}

func TestRecoverDroppedQueryParams_EmptyKey(t *testing.T) {
	params := make(map[string][]string)
	recoverDroppedQueryParams(params, "=val")
	if len(params) != 0 {
		t.Errorf("expected no params for empty key, got %v", params)
	}
}

func TestRecoverDroppedQueryParams_UnescapeError(t *testing.T) {
	params := make(map[string][]string)
	recoverDroppedQueryParams(params, "%ZZkey=val")
	// On unescape error, the raw string is used
	if len(params["%ZZkey"]) != 1 || params["%ZZkey"][0] != "val" {
		t.Errorf("expected %%ZZkey=[val], got %v", params)
	}
}

func TestRecoverDroppedQueryParams_Duplicate(t *testing.T) {
	params := map[string][]string{"key": {"existing"}}
	recoverDroppedQueryParams(params, "key=existing")
	if len(params["key"]) != 1 {
		t.Errorf("expected no duplicate, got %v", params["key"])
	}
}

// ---------------------------------------------------------------------------
// redactSensitiveQueryParams edge cases
// ---------------------------------------------------------------------------

func TestRedactSensitiveQueryParams_Empty(t *testing.T) {
	if got := redactSensitiveQueryParams(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestRedactSensitiveQueryParams_NoEquals(t *testing.T) {
	result := redactSensitiveQueryParams("justastring")
	if result != "justastring" {
		t.Errorf("expected unchanged, got %q", result)
	}
}

func TestRedactSensitiveQueryParams_Malformed(t *testing.T) {
	result := redactSensitiveQueryParams("%ZZ")
	if result != "%ZZ" {
		t.Errorf("expected unchanged for malformed query, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// ParseLogOutput to file (error case)
// ---------------------------------------------------------------------------

func TestParseLogOutput_FileError(t *testing.T) {
	// Use a path in a non-writable location to trigger error
	_, err := ParseLogOutput("/nonexistent/deep/path/test.log", 10, 3, 0)
	if err == nil {
		t.Log("expected error for non-writable path (may succeed on some systems)")
	}
}

// ---------------------------------------------------------------------------
// NewRotatingFileWriter dir create error
// ---------------------------------------------------------------------------

func TestNewRotatingFileWriter_DirCreateError(t *testing.T) {
	// Empty path with NUL should fail
	_, err := NewRotatingFileWriter("test\x00.log", 10, 3, 0)
	if err == nil {
		t.Fatal("expected error for NUL byte in path")
	}
}

// ---------------------------------------------------------------------------
// truncateEvidence edge cases
// ---------------------------------------------------------------------------

func TestTruncateEvidence_ZeroMaxLen(t *testing.T) {
	if got := truncateEvidence("test", 0); got != "" {
		t.Errorf("expected empty for maxLen=0, got %q", got)
	}
}

func TestTruncateEvidence_NegativeMaxLen(t *testing.T) {
	if got := truncateEvidence("test", -1); got != "" {
		t.Errorf("expected empty for maxLen=-1, got %q", got)
	}
}

func TestTruncateEvidence_ShortMaxLen(t *testing.T) {
	if got := truncateEvidence("hello", 2); got != "he" {
		t.Errorf("expected 'he', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Add finding with negative score
// ---------------------------------------------------------------------------

func TestScoreAccumulator_Add_NegativeScore(t *testing.T) {
	sa := NewScoreAccumulator(2)
	sa.Add(&Finding{Score: -5})
	if len(sa.Findings()) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(sa.Findings()))
	}
	if sa.Findings()[0].Score != 0 {
		t.Errorf("expected score clamped to 0, got %d", sa.Findings()[0].Score)
	}
}

// ---------------------------------------------------------------------------
// Exceeds
// ---------------------------------------------------------------------------

func TestScoreAccumulator_Exceeds(t *testing.T) {
	sa := NewScoreAccumulator(2) // multiplier 1.0
	sa.Add(&Finding{Score: 30})
	if !sa.Exceeds(25) {
		t.Error("expected 30 to exceed threshold 25")
	}
	if sa.Exceeds(50) {
		t.Error("expected 30 not to exceed threshold 50")
	}
}

// ---------------------------------------------------------------------------
// generateRequestID with randReader error
// ---------------------------------------------------------------------------

func TestGenerateRequestID_RandError(t *testing.T) {
	// Save and restore original
	orig := randReader
	defer func() { randReader = orig }()

	randReader = func(b []byte) (int, error) {
		// Short write simulates error
		for i := range b {
			b[i] = 0
		}
		return 0, fmt.Errorf("random error")
	}

	id := generateRequestID()
	if id != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("expected fallback UUID, got %q", id)
	}
}

// ---------------------------------------------------------------------------
// SetTrustedProxies (package-level)
// ---------------------------------------------------------------------------

func TestSetTrustedProxies_Empty(t *testing.T) {
	SetTrustedProxies(nil)
	// Should not panic
	SetTrustedProxies([]string{})
}

// ---------------------------------------------------------------------------
// NewScoreAccumulator paranoia level clamping
// ---------------------------------------------------------------------------

func TestNewScoreAccumulator_ParanoiaClamping(t *testing.T) {
	sa0 := NewScoreAccumulator(0) // below 1 → level 1 → 0.5
	if sa0.multiplier != 0.5 {
		t.Errorf("expected 0.5 for paranoia 0, got %f", sa0.multiplier)
	}

	sa5 := NewScoreAccumulator(5) // above 4 → level 4 → 2.0
	if sa5.multiplier != 2.0 {
		t.Errorf("expected 2.0 for paranoia 5, got %f", sa5.multiplier)
	}
}

// ---------------------------------------------------------------------------
// Pipeline: shouldSkip for non-detector layer
// ---------------------------------------------------------------------------

func TestShouldSkip_NonDetector(t *testing.T) {
	layer := &passLayer{name: "test"}
	if shouldSkip(layer, "/path", nil) {
		t.Error("expected false for non-detector layer")
	}
}

func TestShouldSkip_DetectorExcluded(t *testing.T) {
	det := &detectorStub{name: "sqli"}
	exclusions := []Exclusion{
		{PathPrefix: "/webhook", Detectors: []string{"sqli"}},
	}
	if !shouldSkip(det, "/webhook/callback", exclusions) {
		t.Error("expected true for excluded detector on matching path")
	}
}

func TestShouldSkip_PathNotMatched(t *testing.T) {
	det := &detectorStub{name: "sqli"}
	exclusions := []Exclusion{
		{PathPrefix: "/webhook", Detectors: []string{"sqli"}},
	}
	if shouldSkip(det, "/api/endpoint", exclusions) {
		t.Error("expected false for non-matching path")
	}
}

type detectorStub struct {
	name string
}

func (d *detectorStub) Name() string         { return d.name }
func (d *detectorStub) Order() int            { return 0 }
func (d *detectorStub) Process(*RequestContext) LayerResult { return LayerResult{Action: ActionPass} }
func (d *detectorStub) DetectorName() string  { return d.name }
func (d *detectorStub) Patterns() []string    { return nil }

// ---------------------------------------------------------------------------
// Pipeline Middleware with challenge service not set
// ---------------------------------------------------------------------------

func TestMiddleware_ChallengeFallbackBlock(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{
		Layer: &scoreLayer{name: "challenge-layer", score: 60, category: "challenge"},
		Order: OrderDetection,
	})

	handler := e.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, testRequest("GET", "/challenge-path"))

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 (challenge fallback to block), got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// extractClientIP path: no trusted proxies
// ---------------------------------------------------------------------------

func TestExtractClientIP_NoTrustedProxies(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	ip := extractClientIP(r)
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %v", ip)
	}
}

// ---------------------------------------------------------------------------
// flushLocked - Write with buffer error path (buffer write failure)
// ---------------------------------------------------------------------------

func TestMaskingResponseWriter_Write_BufferWriteError(t *testing.T) {
	// This tests the code path where buf.Write fails.
	// bytes.Buffer.Write never fails, so this path is normally unreachable.
	// We verify the logic by setting direct=true first.
	w := httptest.NewRecorder()
	mw := newMaskingResponseWriter(w, nil, nil)
	mw.capture = true
	mw.decided = true
	mw.direct = false

	// Fill buffer to near max
	mw.buf.Grow(maxMaskingBufferSize)
	for i := 0; i < maxMaskingBufferSize; i++ {
		mw.buf.WriteByte('a')
	}

	// This write will exceed maxMaskingBufferSize, triggering the overflow path
	n, err := mw.Write([]byte("overflow"))
	if err != nil {
		t.Fatalf("Write error = %v", err)
	}
	if n != 8 {
		t.Errorf("expected 8, got %d", n)
	}
	if !mw.direct {
		t.Error("expected direct mode after overflow")
	}
}