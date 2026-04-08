package cache

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer provides caching as a WAF layer.
type Layer struct {
	cache      *Cache
	config     *LayerConfig
	httpClient *http.Client
}

// LayerConfig for cache layer.
type LayerConfig struct {
	Enabled       bool     `yaml:"enabled"`
	CacheTTL      time.Duration `yaml:"cache_ttl"`
	CacheMethods  []string `yaml:"cache_methods"`
	CacheStatus   []int    `yaml:"cache_status"`
	SkipPaths     []string `yaml:"skip_paths"`
	SkipCookies   []string `yaml:"skip_cookies"`
	MaxCacheSize  int      `yaml:"max_cache_size"` // KB
	StaleWhileRevalidate bool `yaml:"stale_while_revalidate"`
}

// DefaultLayerConfig returns default layer config.
func DefaultLayerConfig() *LayerConfig {
	return &LayerConfig{
		Enabled:       false,
		CacheTTL:      5 * time.Minute,
		CacheMethods:  []string{"GET", "HEAD"},
		CacheStatus:   []int{200, 301, 302, 404},
		SkipPaths:     []string{"/api/login", "/api/logout", "/healthz"},
		SkipCookies:   []string{"session", "auth"},
		MaxCacheSize:  1024, // 1MB
		StaleWhileRevalidate: false,
	}
}

// CacheKey represents a cache key.
type CacheKey struct {
	Method string
	Path   string
	Host   string
	Query  string
}

// String returns the cache key string.
func (k *CacheKey) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", k.Method, k.Host, k.Path, k.Query)
}

// CacheEntry represents a cached response.
type CacheEntry struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
	CachedAt   time.Time         `json:"cached_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

// NewLayer creates a new cache layer.
func NewLayer(cache *Cache, cfg *LayerConfig) *Layer {
	if cfg == nil {
		cfg = DefaultLayerConfig()
	}

	return &Layer{
		cache:  cache,
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "cache"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 140 // After CORS, before detection
}

// Process implements the layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled || !l.cache.IsEnabled() {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Check if request is cacheable
	if !l.isCacheable(ctx) {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Generate cache key
	key := l.generateKey(ctx)

	// Try to get from cache
	entry, err := l.getCachedEntry(key)
	if err == nil && entry != nil {
		// Check if entry is expired
		if time.Now().After(entry.ExpiresAt) {
			// Delete expired entry - best effort, error ignored
			_ = l.cache.Delete(context.Background(), key)
		} else {
			// Return cached response - pass through to indicate cache hit
			return engine.LayerResult{Action: engine.ActionPass}
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

// isCacheable checks if a request should be cached.
func (l *Layer) isCacheable(ctx *engine.RequestContext) bool {
	// Check method
	if !l.contains(l.config.CacheMethods, ctx.Method) {
		return false
	}

	// Check path
	for _, path := range l.config.SkipPaths {
		if strings.HasPrefix(ctx.Path, path) {
			return false
		}
	}

	// Check for cache-busting headers
	if ctx.Request != nil {
		if ctx.Request.Header.Get("Cache-Control") == "no-cache" {
			return false
		}
		if ctx.Request.Header.Get("Pragma") == "no-cache" {
			return false
		}
	}

	return true
}

// generateKey generates a cache key from the request context.
func (l *Layer) generateKey(ctx *engine.RequestContext) string {
	host := ""
	if ctx.Request != nil {
		host = ctx.Request.Host
	}

	key := &CacheKey{
		Method: ctx.Method,
		Path:   ctx.Path,
		Host:   host,
		Query:  "", // Could include normalized query params
	}

	// Vary by query params if present
	if ctx.Request != nil && len(ctx.Request.URL.Query()) > 0 {
		// Sort and normalize query params for consistent keys
		// Simplified: just use raw query
		key.Query = ctx.Request.URL.RawQuery
	}

	return key.String()
}

// getCachedEntry retrieves a cached entry.
func (l *Layer) getCachedEntry(key string) (*CacheEntry, error) {
	entry := &CacheEntry{}
	if err := l.cache.GetJSON(context.Background(), key, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// storeEntry stores a response in cache.
func (l *Layer) storeEntry(key string, statusCode int, headers http.Header, body []byte, ttl time.Duration) error {
	if ttl == 0 {
		ttl = l.config.CacheTTL
	}

	// Check max size
	if len(body) > l.config.MaxCacheSize*1024 {
		return fmt.Errorf("response too large for cache")
	}

	// Convert headers to map
	hdrMap := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			hdrMap[k] = v[0]
		}
	}

	entry := &CacheEntry{
		StatusCode: statusCode,
		Headers:    hdrMap,
		Body:       body,
		CachedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}

	return l.cache.SetJSON(context.Background(), key, entry, ttl)
}

// Invalidate invalidates cache entries matching a pattern.
func (l *Layer) Invalidate(pattern string) error {
	if !l.cache.IsEnabled() {
		return nil
	}

	keys, err := l.cache.Keys(context.Background(), pattern)
	if err != nil {
		return err
	}

	for _, key := range keys {
		_ = l.cache.Delete(context.Background(), key) // Best effort, errors ignored
	}

	return nil
}

// InvalidatePath invalidates cache entries for a specific path.
func (l *Layer) InvalidatePath(path string) error {
	// Generate pattern for this path
	pattern := fmt.Sprintf("*:%s:*", path)
	return l.Invalidate(pattern)
}

// GetStats returns cache statistics.
func (l *Layer) GetStats() (map[string]any, error) {
	if !l.cache.IsEnabled() {
		return map[string]any{
			"enabled": false,
		}, nil
	}

	return map[string]any{
		"enabled":   true,
		"backend":   l.cache.config.Backend,
		"ttl":       l.config.CacheTTL.String(),
		"methods":   l.config.CacheMethods,
	}, nil
}

// contains checks if a slice contains a string.
func (l *Layer) contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// containsInt checks if a slice contains an int.
func (l *Layer) containsInt(slice []int, item int) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}

// ParseCacheControl parses Cache-Control header.
func ParseCacheControl(header string) (maxAge int, noCache bool, noStore bool) {
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "no-cache" {
			noCache = true
		} else if part == "no-store" {
			noStore = true
		} else if strings.HasPrefix(part, "max-age=") {
			age, _ := strconv.Atoi(part[8:])
			maxAge = age
		}
	}
	return maxAge, noCache, noStore
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)
