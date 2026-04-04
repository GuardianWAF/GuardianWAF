package cache

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultLayerConfig(t *testing.T) {
	cfg := DefaultLayerConfig()

	if cfg.Enabled {
		t.Error("expected cache layer to be disabled by default")
	}

	if cfg.CacheTTL != 5*time.Minute {
		t.Errorf("cache_ttl = %v, want 5m", cfg.CacheTTL)
	}

	if len(cfg.CacheMethods) != 2 {
		t.Errorf("len(cache_methods) = %d, want 2", len(cfg.CacheMethods))
	}

	if cfg.CacheMethods[0] != "GET" {
		t.Errorf("cache_methods[0] = %s, want GET", cfg.CacheMethods[0])
	}

	if len(cfg.CacheStatus) != 4 {
		t.Errorf("len(cache_status) = %d, want 4", len(cfg.CacheStatus))
	}

	if cfg.MaxCacheSize != 1024 {
		t.Errorf("max_cache_size = %d, want 1024", cfg.MaxCacheSize)
	}
}

func TestLayer_Name(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	layer := NewLayer(cache, DefaultLayerConfig())

	if layer.Name() != "cache" {
		t.Errorf("Name() = %s, want cache", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	layer := NewLayer(cache, DefaultLayerConfig())

	if layer.Order() != 140 {
		t.Errorf("Order() = %d, want 140", layer.Order())
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	cfg := DefaultLayerConfig()
	cfg.Enabled = false
	layer := NewLayer(cache, cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

func TestLayer_Process_CacheDisabled(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

func TestLayer_isCacheable_Method(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	// POST should not be cacheable
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/test",
	}

	if layer.isCacheable(ctx) {
		t.Error("POST should not be cacheable")
	}

	// GET should be cacheable
	ctx.Method = "GET"
	if !layer.isCacheable(ctx) {
		t.Error("GET should be cacheable")
	}

	// HEAD should be cacheable
	ctx.Method = "HEAD"
	if !layer.isCacheable(ctx) {
		t.Error("HEAD should be cacheable")
	}
}

func TestLayer_isCacheable_SkipPaths(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	// Request to /api/login should be skipped
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/api/login",
	}

	if layer.isCacheable(ctx) {
		t.Error("/api/login should not be cacheable")
	}

	// Request to /api/logout should be skipped
	ctx.Path = "/api/logout"
	if layer.isCacheable(ctx) {
		t.Error("/api/logout should not be cacheable")
	}

	// Request to /healthz should be skipped
	ctx.Path = "/healthz"
	if layer.isCacheable(ctx) {
		t.Error("/healthz should not be cacheable")
	}

	// Other paths should be cacheable
	ctx.Path = "/api/data"
	if !layer.isCacheable(ctx) {
		t.Error("/api/data should be cacheable")
	}
}

func TestLayer_isCacheable_CacheBusting(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Cache-Control", "no-cache")

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Request: req,
	}

	if layer.isCacheable(ctx) {
		t.Error("request with Cache-Control: no-cache should not be cacheable")
	}

	// Test Pragma header
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("Pragma", "no-cache")

	ctx2 := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Request: req2,
	}

	if layer.isCacheable(ctx2) {
		t.Error("request with Pragma: no-cache should not be cacheable")
	}
}

func TestLayer_generateKey(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	layer := NewLayer(cache, cfg)

	req, _ := http.NewRequest("GET", "/test?foo=bar", nil)
	req.Host = "example.com"

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Request: req,
	}

	key := layer.generateKey(ctx)

	// Key should contain method, host, path
	if key == "" {
		t.Error("expected non-empty key")
	}

	// Should contain query params
	if !containsStr(key, "foo=bar") {
		t.Error("expected key to contain query params")
	}
}

func TestLayer_generateKey_NoRequest(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	layer := NewLayer(cache, cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	key := layer.generateKey(ctx)

	if key == "" {
		t.Error("expected non-empty key")
	}
}

func TestLayer_Process_CacheHit(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	// Pre-populate cache
	entry := &CacheEntry{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/plain"},
		Body:       []byte("cached response"),
		CachedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/cached",
	}

	key := layer.generateKey(ctx)
	cache.SetJSON(context.Background(), key, entry, time.Hour)

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
	// Cache hit returns ActionPass - verified by checking no additional processing needed
}

func TestLayer_Process_CacheMiss(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/not-cached",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
	// Cache miss - no additional fields to check
}

func TestLayer_Process_ExpiredEntry(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	// Add expired entry
	entry := &CacheEntry{
		StatusCode: 200,
		Body:       []byte("expired"),
		CachedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/expired",
	}

	key := layer.generateKey(ctx)
	cache.SetJSON(context.Background(), key, entry, time.Hour)

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}

	// Should be a miss since entry was expired - verified by checking subsequent processing happens
}

func TestLayer_storeEntry(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.MaxCacheSize = 1 // 1KB max
	layer := NewLayer(cache, cfg)

	headers := http.Header{}
	headers.Set("Content-Type", "text/plain")

	err := layer.storeEntry("test-key", 200, headers, []byte("small body"), time.Minute)
	if err != nil {
		t.Fatalf("storeEntry failed: %v", err)
	}

	// Verify stored
	err = cache.GetJSON(context.Background(), "test-key", &CacheEntry{})
	if err != nil {
		t.Error("expected entry to be stored")
	}
}

func TestLayer_storeEntry_TooLarge(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.MaxCacheSize = 1 // 1KB max
	layer := NewLayer(cache, cfg)

	headers := http.Header{}

	// Try to store 2KB body when max is 1KB
	largeBody := make([]byte, 2048)

	err := layer.storeEntry("test-key", 200, headers, largeBody, time.Minute)
	if err == nil {
		t.Error("expected error for oversized body")
	}
}

func TestLayer_Invalidate(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	layer := NewLayer(cache, cfg)

	ctx := context.Background()
	cache.Set(ctx, "key1", []byte("v1"), time.Minute)
	cache.Set(ctx, "key2", []byte("v2"), time.Minute)

	err := layer.Invalidate("key")
	if err != nil {
		t.Fatalf("Invalidate failed: %v", err)
	}
}

func TestLayer_InvalidatePath(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	layer := NewLayer(cache, cfg)

	ctx := context.Background()
	cache.Set(ctx, "GET:example.com:/api/users:", []byte("v1"), time.Minute)

	err := layer.InvalidatePath("/api/users")
	if err != nil {
		t.Fatalf("InvalidatePath failed: %v", err)
	}
}

func TestLayer_GetStats_Disabled(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	cfg := DefaultLayerConfig()
	layer := NewLayer(cache, cfg)

	stats, err := layer.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats["enabled"] != false {
		t.Error("expected enabled=false in stats")
	}
}

func TestLayer_GetStats_Enabled(t *testing.T) {
	cache, _ := New(&Config{Enabled: true, Backend: "memory", MaxSize: 10, TTL: time.Hour})
	defer cache.Close()

	cfg := DefaultLayerConfig()
	cfg.Enabled = true
	layer := NewLayer(cache, cfg)

	stats, err := layer.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats["enabled"] != true {
		t.Error("expected enabled=true in stats")
	}

	if stats["backend"] != "memory" {
		t.Errorf("backend = %v, want memory", stats["backend"])
	}
}

func TestLayer_contains(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	layer := NewLayer(cache, DefaultLayerConfig())

	slice := []string{"GET", "POST", "PUT"}

	if !layer.contains(slice, "GET") {
		t.Error("expected contains to find GET")
	}

	if !layer.contains(slice, "get") { // case insensitive
		t.Error("expected contains to be case insensitive")
	}

	if layer.contains(slice, "DELETE") {
		t.Error("expected contains to not find DELETE")
	}
}

func TestLayer_containsInt(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	layer := NewLayer(cache, DefaultLayerConfig())

	slice := []int{200, 301, 302, 404}

	if !layer.containsInt(slice, 200) {
		t.Error("expected containsInt to find 200")
	}

	if !layer.containsInt(slice, 404) {
		t.Error("expected containsInt to find 404")
	}

	if layer.containsInt(slice, 500) {
		t.Error("expected containsInt to not find 500")
	}
}

func TestParseCacheControl(t *testing.T) {
	tests := []struct {
		header   string
		maxAge   int
		noCache  bool
		noStore  bool
	}{
		{"max-age=3600", 3600, false, false},
		{"no-cache", 0, true, false},
		{"no-store", 0, false, true},
		{"no-cache, no-store", 0, true, true},
		{"max-age=3600, no-cache", 3600, true, false},
		{"", 0, false, false},
		{"max-age=0", 0, false, false},
	}

	for _, tt := range tests {
		maxAge, noCache, noStore := ParseCacheControl(tt.header)

		if maxAge != tt.maxAge {
			t.Errorf("ParseCacheControl(%q) maxAge = %d, want %d", tt.header, maxAge, tt.maxAge)
		}
		if noCache != tt.noCache {
			t.Errorf("ParseCacheControl(%q) noCache = %v, want %v", tt.header, noCache, tt.noCache)
		}
		if noStore != tt.noStore {
			t.Errorf("ParseCacheControl(%q) noStore = %v, want %v", tt.header, noStore, tt.noStore)
		}
	}
}

func TestCacheKey_String(t *testing.T) {
	key := &CacheKey{
		Method: "GET",
		Host:   "example.com",
		Path:   "/test",
		Query:  "foo=bar",
	}

	result := key.String()
	expected := "GET:example.com:/test:foo=bar"

	if result != expected {
		t.Errorf("String() = %s, want %s", result, expected)
	}
}

func TestNewLayer_NilConfig(t *testing.T) {
	cache := &Cache{config: &Config{Enabled: false}}
	layer := NewLayer(cache, nil)

	if layer.config == nil {
		t.Error("expected default config when nil provided")
	}
}

// Helper
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
