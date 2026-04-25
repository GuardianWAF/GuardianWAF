package canary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- SetCountryContext ---

func TestSetCountryContext(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	out := SetCountryContext(req, "US")
	if out == req {
		t.Error("expected new request with country context")
	}
	val := out.Context().Value(countryContextKey)
	if val == nil {
		t.Fatal("expected country value in context")
	}
	if val.(string) != "US" {
		t.Errorf("country = %v, want US", val)
	}
}

func TestSetCountryContext_Empty(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	out := SetCountryContext(req, "")
	if out != req {
		t.Error("empty country should return same request")
	}
}

// --- Geographic strategy ---

func TestShouldRouteToCanary_Geographic_ContextCountry(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Strategy: StrategyGeographic,
		Regions:  []string{"US", "DE"},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req = SetCountryContext(req, "US")
	if !c.ShouldRouteToCanary(req) {
		t.Error("should route to canary for US region")
	}

	req2, _ := http.NewRequest("GET", "/test", nil)
	req2 = SetCountryContext(req2, "JP")
	if c.ShouldRouteToCanary(req2) {
		t.Error("should not route to canary for JP region")
	}
}

func TestShouldRouteToCanary_Geographic_HeaderFallback(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Strategy: StrategyGeographic,
		Regions:  []string{"DE"},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("CF-IPCountry", "DE")
	if !c.ShouldRouteToCanary(req) {
		t.Error("should route to canary for DE via CF-IPCountry header")
	}

	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Country-Code", "DE")
	if !c.ShouldRouteToCanary(req2) {
		t.Error("should route to canary for DE via X-Country-Code header")
	}

	req3, _ := http.NewRequest("GET", "/test", nil)
	if c.ShouldRouteToCanary(req3) {
		t.Error("should not route when no country info available")
	}
}

func TestShouldRouteToCanary_Geographic_ContextOverridesHeader(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Strategy: StrategyGeographic,
		Regions:  []string{"US"},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req = SetCountryContext(req, "US")
	req.Header.Set("CF-IPCountry", "JP")
	if !c.ShouldRouteToCanary(req) {
		t.Error("context country should override header")
	}
}

// --- Health check integration ---

func TestPerformHealthCheck_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
			Timeout:  1 * time.Second,
			Path:     "/healthz",
		},
		CanaryUpstream: server.URL,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.performHealthCheck()

	stats := c.GetStats()
	lastCheck := stats["last_health_check"]
	if lastCheck == nil {
		t.Error("expected last_health_check to be set")
	}
}

func TestPerformHealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
			Timeout:  1 * time.Second,
			Path:     "/healthz",
		},
		CanaryUpstream: server.URL,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.performHealthCheck()
	if c.healthCount.Load() != 0 {
		t.Errorf("healthCount = %d, want 0 after failed check", c.healthCount.Load())
	}
}

func TestPerformHealthCheck_UnreachableUpstream(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
			Timeout:  100 * time.Millisecond,
			Path:     "/healthz",
		},
		CanaryUpstream: "http://127.0.0.1:1",
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.performHealthCheck()
	if c.healthCount.Load() != 0 {
		t.Errorf("healthCount = %d, want 0", c.healthCount.Load())
	}
}

func TestPerformHealthCheck_AutoUnhalt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
			Timeout:  1 * time.Second,
			Path:     "/healthz",
		},
		CanaryUpstream: server.URL,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Halt()
	if !c.IsHalted() {
		t.Fatal("expected canary to be halted")
	}

	c.performHealthCheck()
	c.performHealthCheck()
	c.performHealthCheck()

	if c.IsHalted() {
		t.Error("expected canary to auto-unhalt after 3 successful health checks")
	}
}

func TestPerformHealthCheck_InvalidURL(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled: true,
			Path:    "/healthz",
		},
		CanaryUpstream: "://invalid-url",
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.performHealthCheck()
}

// --- NewLayer enabled path ---

func TestNewLayer_Enabled(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:    true,
			Percentage: 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if layer.canary == nil {
		t.Error("expected canary to be initialized when enabled")
	}
}

func TestNewLayer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if layer.canary != nil {
		t.Error("expected nil canary for nil config")
	}
}

func TestNewLayer_InvalidConfig(t *testing.T) {
	_, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:    true,
			Percentage: 200,
		},
	})
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

// --- Layer.Process enabled paths ---

func TestLayer_Process_Enabled(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:        true,
			Strategy:       StrategyPercentage,
			Percentage:     100,
			CanaryUpstream: "canary:8080",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	ctx := &engine.RequestContext{
		Request:  req,
		Metadata: make(map[string]any),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
	canaryVal, ok := ctx.Metadata["canary"]
	if !ok || canaryVal != true {
		t.Errorf("expected canary=true in metadata, got %v", ctx.Metadata["canary"])
	}
	upstream, ok := ctx.Metadata["canary_upstream"]
	if !ok || upstream != "canary:8080" {
		t.Errorf("expected canary_upstream=canary:8080, got %v", upstream)
	}
}

func TestLayer_Process_EnabledWithGeoCountry(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:        true,
			Strategy:       StrategyGeographic,
			Regions:        []string{"US"},
			CanaryUpstream: "canary:8080",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := &engine.RequestContext{
		Request: req,
		Metadata: map[string]any{
			"country_code": "US",
		},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
	if ctx.Metadata["canary"] != true {
		t.Error("expected canary routing for US country")
	}
}

func TestLayer_Process_EnabledWithInvalidCountry(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:        true,
			Strategy:       StrategyGeographic,
			Regions:        []string{"US"},
			CanaryUpstream: "canary:8080",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := &engine.RequestContext{
		Request: req,
		Metadata: map[string]any{
			"country_code": 123,
		},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

func TestLayer_Process_TenantDisabled(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:    true,
			Percentage: 100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := &engine.RequestContext{
		Request:         req,
		Metadata:        make(map[string]any),
		TenantWAFConfig: &config.WAFConfig{Canary: config.CanaryConfig{Enabled: false}},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
	if _, ok := ctx.Metadata["canary"]; ok {
		t.Error("should not set canary metadata when tenant disabled")
	}
}

func TestLayer_Process_NilMetadata(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config: &Config{
			Enabled:        true,
			Strategy:       StrategyPercentage,
			Percentage:     0,
			CanaryUpstream: "canary:8080",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := &engine.RequestContext{
		Request:  req,
		Metadata: nil,
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

// --- Layer.GetCanary ---

func TestLayer_GetCanary(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config:  &Config{Enabled: true, Percentage: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()

	if layer.GetCanary() == nil {
		t.Error("expected canary instance, got nil")
	}
}

func TestLayer_GetCanary_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	if layer.GetCanary() != nil {
		t.Error("expected nil canary for disabled layer")
	}
}

// --- Layer.GetStats ---

func TestLayer_GetStats_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	stats := layer.GetStats()
	if stats["enabled"] != false {
		t.Error("expected enabled=false")
	}
}

func TestLayer_GetStats_Enabled(t *testing.T) {
	layer, err := NewLayer(&LayerConfig{
		Enabled: true,
		Config:  &Config{Enabled: true, Percentage: 30},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	stats := layer.GetStats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
}

// --- Layer.Close ---

func TestLayer_Close_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})
	if err := layer.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// --- GetConfig ---

func TestGetConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Percentage: 42,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	got := c.GetConfig()
	if got.Percentage != 42 {
		t.Errorf("Percentage = %d, want 42", got.Percentage)
	}
	if !got.Enabled {
		t.Error("expected Enabled=true")
	}
}

// --- RecordingResponseWriter ---

func TestRecordingResponseWriter(t *testing.T) {
	mock := &mockResponseWriter{headers: make(http.Header)}
	c, _ := New(&Config{Enabled: true, Percentage: 50})
	defer c.Close()

	rw := NewRecordingResponseWriter(mock, c, true)
	if rw == nil {
		t.Fatal("expected writer, got nil")
	}

	rw.WriteHeader(404)
	if rw.statusCode != 404 {
		t.Errorf("statusCode = %d, want 404", rw.statusCode)
	}

	rw.Close()
	stats := c.GetStats()
	if stats["total_requests"] != int64(1) {
		t.Errorf("total_requests = %v, want 1", stats["total_requests"])
	}
	if stats["canary_requests"] != int64(1) {
		t.Errorf("canary_requests = %v, want 1", stats["canary_requests"])
	}
}

func TestRecordingResponseWriter_NilCanary(t *testing.T) {
	mock := &mockResponseWriter{headers: make(http.Header)}
	rw := NewRecordingResponseWriter(mock, nil, false)
	rw.Close()
}

func TestRecordingResponseWriter_StableRequest(t *testing.T) {
	mock := &mockResponseWriter{headers: make(http.Header)}
	c, _ := New(&Config{Enabled: true, Percentage: 50})
	defer c.Close()

	rw := NewRecordingResponseWriter(mock, c, false)
	rw.WriteHeader(200)
	rw.Close()

	stats := c.GetStats()
	if stats["canary_requests"] != int64(0) {
		t.Errorf("canary_requests = %v, want 0", stats["canary_requests"])
	}
	if stats["total_requests"] != int64(1) {
		t.Errorf("total_requests = %v, want 1", stats["total_requests"])
	}
}

// --- Router nil cases ---

func TestRouter_NilCanary(t *testing.T) {
	router := NewRouter(nil)
	req, _ := http.NewRequest("GET", "/test", nil)

	if router.IsCanaryRequest(req) {
		t.Error("nil canary should not route to canary")
	}
	if upstream := router.SelectUpstream(req); upstream != "" {
		t.Errorf("nil canary upstream = %q, want empty", upstream)
	}
}

// --- Middleware nil canary ---

func TestMiddleware_NilCanary(t *testing.T) {
	middleware := NewMiddleware(nil)

	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	wrapped := middleware.Handler(testHandler)
	req, _ := http.NewRequest("GET", "/test", nil)
	rr := &mockResponseWriter{headers: make(http.Header)}

	wrapped.ServeHTTP(rr, req)
	if !handlerCalled {
		t.Error("handler should be called even with nil canary")
	}
}

// --- randomInt edge cases ---

func TestRandomInt_ZeroMax(t *testing.T) {
	c, _ := New(&Config{Enabled: true, Percentage: 50})
	defer c.Close()
	result := c.randomInt(0)
	if result != 0 {
		t.Errorf("randomInt(0) = %d, want 0", result)
	}
}

func TestRandomInt_NegativeMax(t *testing.T) {
	c, _ := New(&Config{Enabled: true, Percentage: 50})
	defer c.Close()
	result := c.randomInt(-5)
	if result != 0 {
		t.Errorf("randomInt(-5) = %d, want 0", result)
	}
}

// --- Latency-based rollback ---

func TestAutoRollback_Latency(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Percentage:       100,
		AutoRollback:     true,
		ErrorThreshold:   100.0,
		LatencyThreshold: 10 * time.Millisecond,
	}
	c, _ := New(cfg)
	defer c.Close()

	for i := 0; i < 200; i++ {
		c.RecordResult(true, 200, 1*time.Second)
	}

	if !c.IsHalted() {
		t.Error("canary should be halted due to high latency")
	}
}

// --- No rollback when disabled ---

func TestCanaryHealth_NoRollback(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Percentage:       100,
		AutoRollback:     false,
		ErrorThreshold:   5.0,
		LatencyThreshold: 1 * time.Millisecond,
	}
	c, _ := New(cfg)
	defer c.Close()

	for i := 0; i < 200; i++ {
		c.RecordResult(true, 500, 5*time.Second)
	}

	if c.IsHalted() {
		t.Error("canary should not halt when auto_rollback=false")
	}
}

// --- New with nil config ---

func TestNew_NilConfig_Coverage(t *testing.T) {
	c, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	got := c.GetConfig()
	if got.Enabled {
		t.Error("nil config should use defaults (disabled)")
	}
}

// --- Header strategy with regex ---

func TestCheckHeader_RegexMatch(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		Strategy:    StrategyHeader,
		HeaderName:  "X-Canary",
		HeaderValue: `v2\.0\.0-.*`,
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Canary", "v2.0.0-beta.1")
	if !c.ShouldRouteToCanary(req) {
		t.Error("should route for regex match")
	}

	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-Canary", "v1.0.0")
	if c.ShouldRouteToCanary(req2) {
		t.Error("should not route for regex mismatch")
	}
}

// --- checkCookie without value ---

func TestCheckCookie_NoValue(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyCookie,
		CookieName: "canary",
	}
	c, _ := New(cfg)
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{Name: "canary", Value: "any-value"})
	if !c.ShouldRouteToCanary(req) {
		t.Error("should route when cookie exists (no value filter)")
	}
}

// --- ShouldRouteToCanary when unhealthy + autoRollback ---

func TestShouldRouteToCanary_UnhealthyWithAutoRollback(t *testing.T) {
	cfg := &Config{
		Enabled:      true,
		Strategy:     StrategyPercentage,
		Percentage:   100,
		AutoRollback: true,
	}
	c, _ := New(cfg)
	defer c.Close()

	c.stats.Healthy.Store(false)

	req, _ := http.NewRequest("GET", "/test", nil)
	if c.ShouldRouteToCanary(req) {
		t.Error("should not route when unhealthy and autoRollback enabled")
	}
}

// --- checkPercentage with RemoteAddr fallback ---

func TestCheckPercentage_RemoteAddr(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyPercentage,
		Percentage: 100,
	}
	c, _ := New(cfg)
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:5678"
	if !c.ShouldRouteToCanary(req) {
		t.Error("100% should always route regardless of key source")
	}
}

// --- healthCheckLoop with zero interval ---

func TestHealthCheckLoop_ZeroInterval(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 0,
			Timeout:  1 * time.Second,
			Path:     "/healthz",
		},
	}
	c, _ := New(cfg)
	c.Close()
}

// --- Validate sets default strategy ---

func TestValidate_EmptyStrategy(t *testing.T) {
	cfg := &Config{
		Percentage:     50,
		ErrorThreshold: 5,
		Strategy:       "",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Strategy != StrategyPercentage {
		t.Errorf("strategy = %q, want percentage", cfg.Strategy)
	}
}

// --- Validate negative percentage ---

func TestValidate_NegativePercentage(t *testing.T) {
	cfg := &Config{Percentage: -1}
	if err := cfg.Validate(); err == nil {
		t.Error("negative percentage should error")
	}
}

// --- Validate negative error threshold ---

func TestValidate_NegativeErrorThreshold(t *testing.T) {
	cfg := &Config{
		Percentage:     50,
		ErrorThreshold: -1,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("negative error_threshold should error")
	}
}

// --- New with health check disabled ---

func TestNew_HealthCheckDisabled(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		HealthCheck: HealthCheckConfig{
			Enabled: false,
		},
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stats := c.GetStats()
	if stats["enabled"] != true {
		t.Error("expected enabled=true")
	}
}

// --- Concurrent access ---

func TestConcurrentAccess(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyPercentage,
		Percentage: 50,
	}
	c, _ := New(cfg)
	defer c.Close()

	done := make(chan struct{})

	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Request-ID", string(rune(i)))
			c.ShouldRouteToCanary(req)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			c.RecordResult(true, 200, 10*time.Millisecond)
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			c.GetStats()
		}
	}()

	<-done
	<-done
	<-done
}

// --- Check CountryContext type assertion failure ---

func TestCheckGeographic_InvalidContextValue(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Strategy: StrategyGeographic,
		Regions:  []string{"US"},
	}
	c, _ := New(cfg)
	defer c.Close()

	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), countryContextKey, 12345)
	req = req.WithContext(ctx)

	if c.ShouldRouteToCanary(req) {
		t.Error("should not route with invalid country context value type")
	}
}
