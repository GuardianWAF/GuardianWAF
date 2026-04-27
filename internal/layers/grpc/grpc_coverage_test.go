package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Frame.IsData ---

func TestCoverage_Frame_IsData(t *testing.T) {
	frame := &Frame{Type: FrameData}
	if !frame.IsData() {
		t.Error("IsData(DATA) should be true")
	}
	frame.Type = FrameHeaders
	if frame.IsData() {
		t.Error("IsData(HEADERS) should be false")
	}
}

// --- Frame.IsEndHeaders ---

func TestCoverage_Frame_IsEndHeaders(t *testing.T) {
	frame := &Frame{Flags: 0x04}
	if !frame.IsEndHeaders() {
		t.Error("IsEndHeaders(0x04) should be true")
	}
	frame.Flags = 0x00
	if frame.IsEndHeaders() {
		t.Error("IsEndHeaders(0x00) should be false")
	}
}

// --- Security.GetRateLimiter ---

func TestCoverage_Security_GetRateLimiter_Found(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled: true,
		MethodRateLimits: []config.GRPCRateLimit{
			{Method: "test.Service/Method", RequestsPerSecond: 10, BurstSize: 5},
		},
	}
	s, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer s.Stop()

	rl := s.GetRateLimiter("test.Service/Method")
	if rl == nil {
		t.Error("GetRateLimiter should return limiter for configured method")
	}

	rl = s.GetRateLimiter("unknown.Method")
	if rl != nil {
		t.Error("GetRateLimiter should return nil for unknown method")
	}
}

// --- Security.ValidateRequest ---

func TestCoverage_Security_ValidateRequest_Disabled(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: false}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	req := &http.Request{URL: &url.URL{Path: "/test.Service/Method"}}
	if err := s.ValidateRequest(req); err != nil {
		t.Errorf("ValidateRequest(disabled) should pass, got: %v", err)
	}
}

func TestCoverage_Security_ValidateRequest_RequireTLS(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:    true,
		RequireTLS: true,
	}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	req := &http.Request{
		URL:  &url.URL{Path: "/test.Service/Method"},
		TLS:  nil, // no TLS
	}
	if err := s.ValidateRequest(req); err == nil {
		t.Error("ValidateRequest(RequireTLS, no TLS) should fail")
	}
}

func TestCoverage_Security_ValidateRequest_MethodNotAllowed(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:        true,
		AllowedMethods: []string{"test.Service/Allowed"},
	}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	req := &http.Request{
		URL: &url.URL{Path: "/test.Service/Blocked"},
	}
	if err := s.ValidateRequest(req); err == nil {
		t.Error("ValidateRequest(method not allowed) should fail")
	}
}

func TestCoverage_Security_ValidateRequest_RateLimited(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled: true,
		MethodRateLimits: []config.GRPCRateLimit{
			{Method: "test.Service/Method", RequestsPerSecond: 1, BurstSize: 1},
		},
	}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	req := &http.Request{
		URL: &url.URL{Path: "/test.Service/Method"},
	}
	// First request should pass
	if err := s.ValidateRequest(req); err != nil {
		t.Errorf("first request should pass, got: %v", err)
	}
	// Second request should be rate limited
	if err := s.ValidateRequest(req); err == nil {
		t.Error("second request should be rate limited")
	}
}

// --- Handler.SetAPIKey ---

func TestCoverage_Handler_SetAPIKey(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	handler.SetAPIKey("test-api-key")

	// Test with valid API key
	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/stats", nil)
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ServeHTTP(valid key) status = %d, want %d", w.Code, http.StatusOK)
	}

	// Test with invalid API key
	req = httptest.NewRequest(http.MethodGet, "/api/v1/grpc/stats", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("ServeHTTP(wrong key) status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// --- Handler.ServeHTTP with nil security ---

func TestCoverage_Handler_ServeHTTP_NilSecurity(t *testing.T) {
	handler := NewHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ServeHTTP(nil security) status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// --- Handler.ServeHTTP unknown path ---

func TestCoverage_Handler_ServeHTTP_UnknownPath(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/unknown", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("ServeHTTP(unknown path) status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// --- Handler.handleStats wrong method ---

func TestCoverage_Handler_Stats_WrongMethod(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grpc/stats", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleStats(POST) status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- Handler.handleStreams wrong method ---

func TestCoverage_Handler_Streams_WrongMethod(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grpc/streams", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleStreams(POST) status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- Handler.handleServices wrong method ---

func TestCoverage_Handler_Services_WrongMethod(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/grpc/services", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleServices(POST) status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// --- Handler.handleStreams with service filter ---

func TestCoverage_Handler_Streams_ServiceFilter(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	s.RegisterStream(1, "ServiceA", "Method1", false, false)
	s.RegisterStream(2, "ServiceB", "Method1", false, false)

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/streams?service=ServiceA", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	streams := result["streams"].([]any)
	if len(streams) != 1 {
		t.Errorf("streams with ServiceA filter = %d, want 1", len(streams))
	}
}

// --- Handler.handleServices with streams and config ---

func TestCoverage_Handler_Services_WithStreams(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:         true,
		AllowedServices: []string{"ConfigService"},
		BlockedServices: []string{"BlockedService"},
	}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	s.RegisterStream(1, "StreamService", "Method1", false, false)
	s.RegisterStream(2, "StreamService", "Method2", false, false)

	handler := NewHandler(s)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/services", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	services := result["services"].([]any)
	if len(services) < 2 {
		t.Errorf("services count = %d, want >= 2", len(services))
	}
}

// --- Handler.HealthCheck ---

func TestCoverage_Handler_HealthCheck(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	handler := NewHandler(s)
	if err := handler.HealthCheck(); err != nil {
		t.Errorf("HealthCheck(with security) error = %v", err)
	}

	nilHandler := NewHandler(nil)
	if err := nilHandler.HealthCheck(); err == nil {
		t.Error("HealthCheck(nil security) should fail")
	}
}

// --- Layer.Process with TLS required ---

func TestCoverage_Layer_Process_TLSRequired(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:    true,
		RequireTLS: true,
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		URL:  &url.URL{Path: "/test.Service/Method"},
		Header: http.Header{
			"Content-Type": []string{"application/grpc"},
		},
	}
	ctx := &engine.RequestContext{Request: req}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Process(TLS required, no TLS) action = %v, want Block", result.Action)
	}
}

// --- Layer.Process with tenant config ---

func TestCoverage_Layer_Process_TenantDisabled(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	tenantCfg := &config.WAFConfig{}
	tenantCfg.GRPC.Enabled = false

	req := &http.Request{
		URL: &url.URL{Path: "/test.Service/Method"},
		Header: http.Header{
			"Content-Type": []string{"application/grpc"},
		},
	}
	ctx := &engine.RequestContext{
		Request:        req,
		TenantWAFConfig: tenantCfg,
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Process(tenant disabled) action = %v, want Pass", result.Action)
	}
}

// --- Layer.GetSecurity ---

func TestCoverage_Layer_GetSecurity(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	layer, _ := NewLayer(cfg)
	defer layer.Stop()

	if layer.GetSecurity() == nil {
		t.Error("GetSecurity should return security instance")
	}
}

// --- Layer.IsGRPCRequest ---

func TestCoverage_Layer_IsGRPCRequest(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: false}
	layer, _ := NewLayer(cfg)
	defer layer.Stop()

	req := &http.Request{
		Header: http.Header{"Content-Type": []string{"application/grpc"}},
	}
	if !layer.IsGRPCRequest(req) {
		t.Error("IsGRPCRequest should return true for gRPC request")
	}
}

// --- Layer.GetRequestInfo ---

func TestCoverage_Layer_GetRequestInfo(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: false}
	layer, _ := NewLayer(cfg)

	req := &http.Request{
		URL:    &url.URL{Path: "/test.Service/Method"},
		Header: http.Header{"Content-Type": []string{"application/grpc"}},
	}
	info := layer.GetRequestInfo(req)
	if info.Service != "test.Service" {
		t.Errorf("Service = %s, want test.Service", info.Service)
	}
	if info.Method != "Method" {
		t.Errorf("Method = %s, want Method", info.Method)
	}
}

// --- Layer with nil config ---

func TestCoverage_Layer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil) failed: %v", err)
	}
	if layer.security != nil {
		t.Error("security should be nil with nil config")
	}
}

// --- Layer.Stop without security ---

func TestCoverage_Layer_Stop_NoSecurity(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: false}
	layer, _ := NewLayer(cfg)
	layer.Stop() // Should not panic
}

// --- Security.Stop idempotent ---

func TestCoverage_Security_Stop_Twice(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	s, _ := NewSecurity(cfg)
	s.Stop()
	s.Stop() // should not panic
}

// --- Security.NewSecurity nil config ---

func TestCoverage_Security_NilConfig(t *testing.T) {
	s, err := NewSecurity(nil)
	if err != nil {
		t.Fatalf("NewSecurity(nil) failed: %v", err)
	}
	s.Stop()
}

// --- ReadHTTP2Preface short read ---

func TestCoverage_ReadHTTP2Preface_ShortRead(t *testing.T) {
	reader := bytes.NewReader([]byte("PRI"))
	err := ReadHTTP2Preface(reader)
	if err == nil {
		t.Error("ReadHTTP2Preface(short data) should fail")
	}
}

// --- GetStreamFromContext with stream ---

func TestCoverage_GetStreamFromContext_WithStream(t *testing.T) {
	stream := &Stream{ID: 1}
	ctx := context.WithValue(context.Background(), ContextKeyStream, stream)
	result := GetStreamFromContext(ctx)
	if result == nil || result.ID != 1 {
		t.Error("GetStreamFromContext should return the stream")
	}

	// With wrong type
	ctx = context.WithValue(context.Background(), ContextKeyStream, "not-a-stream")
	result = GetStreamFromContext(ctx)
	if result != nil {
		t.Error("GetStreamFromContext with wrong type should return nil")
	}
}

// --- parseUint edge cases ---

func TestCoverage_ParseUint_EdgeCases(t *testing.T) {
	// Empty string
	_, err := parseUint("")
	if err == nil {
		t.Error("parseUint(empty) should fail")
	}

	// Non-digit character
	_, err = parseUint("12a3")
	if err == nil {
		t.Error("parseUint(12a3) should fail")
	}

	// Large value
	val, err := parseUint("9999999999")
	if err != nil {
		t.Errorf("parseUint(9999999999) error = %v", err)
	}
	if val != 9999999999 {
		t.Errorf("parseUint(9999999999) = %d, want 9999999999", val)
	}
}

// --- encodeGRPCMessage coverage ---

func TestCoverage_EncodeGRPCMessage(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"test%value", "test%25value"},
		{"a\nb", "a%0Ab"},
	}
	for _, tt := range tests {
		result := encodeGRPCMessage(tt.input)
		if result != tt.expected {
			t.Errorf("encodeGRPCMessage(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// --- parseGRPCTimeout edge cases ---

func TestCoverage_ParseGRPCTimeout_EdgeCases(t *testing.T) {
	// Single character (too short)
	_, err := parseGRPCTimeout("S")
	if err == nil {
		t.Error("parseGRPCTimeout(S) should fail")
	}

	// Overflow value
	_, err = parseGRPCTimeout("99999999999999999999S")
	if err == nil {
		t.Error("parseGRPCTimeout(huge value) should fail")
	}

	// Unknown unit
	_, err = parseGRPCTimeout("10Z")
	if err == nil {
		t.Error("parseGRPCTimeout(10Z) should fail")
	}
}

// --- IsAllowedService wildcard ---

func TestCoverage_IsAllowedService_Wildcard(t *testing.T) {
	cfg := &config.GRPCConfig{
		AllowedServices: []string{"*"},
	}
	s, _ := NewSecurity(cfg)
	defer s.Stop()

	if !s.IsAllowedService("any.Service") {
		t.Error("IsAllowedService(*) should allow any service")
	}
}

// --- RateLimiter drain ---

func TestCoverage_RateLimiter_Drain(t *testing.T) {
	rl := NewRateLimiter(100, 2)
	if !rl.Allow() {
		t.Error("first request should be allowed")
	}
	if !rl.Allow() {
		t.Error("second request should be allowed")
	}
	if rl.Allow() {
		t.Error("third request should be denied (burst=2)")
	}
}
