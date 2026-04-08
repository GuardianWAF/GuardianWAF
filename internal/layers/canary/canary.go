// Package canary provides traffic splitting and gradual rollout capabilities.
package canary

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// Strategy defines how traffic is split between stable and canary.
type Strategy string

const (
	StrategyPercentage Strategy = "percentage"
	StrategyHeader     Strategy = "header"
	StrategyCookie     Strategy = "cookie"
	StrategyGeographic Strategy = "geographic"
	StrategyRandom     Strategy = "random"
)

// Config for canary releases.
type Config struct {
	Enabled        bool              `yaml:"enabled"`
	CanaryVersion  string            `yaml:"canary_version"`  // e.g., "v2.0.0-beta"
	StableUpstream string            `yaml:"stable_upstream"`
	CanaryUpstream string            `yaml:"canary_upstream"`
	Strategy       Strategy          `yaml:"strategy"`
	Percentage     int               `yaml:"percentage"`      // 0-100
	HeaderName     string            `yaml:"header_name"`     // for header strategy
	HeaderValue    string            `yaml:"header_value"`    // optional match value
	CookieName     string            `yaml:"cookie_name"`     // for cookie strategy
	CookieValue    string            `yaml:"cookie_value"`    // optional match value
	Regions        []string          `yaml:"regions"`         // for geographic strategy
	HealthCheck    HealthCheckConfig `yaml:"health_check"`
	AutoRollback   bool              `yaml:"auto_rollback"`
	ErrorThreshold float64           `yaml:"error_threshold"` // error rate % for rollback
	LatencyThreshold time.Duration   `yaml:"latency_threshold"`
	Metadata       map[string]string `yaml:"metadata"`
}

// HealthCheckConfig defines health checking for canary.
type HealthCheckConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Path     string        `yaml:"path"`
}

// DefaultConfig returns default canary config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:        false,
		Strategy:       StrategyPercentage,
		Percentage:     10,
		HeaderName:     "X-Canary",
		CookieName:     "canary",
		HealthCheck: HealthCheckConfig{
			Enabled:  true,
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Path:     "/healthz",
		},
		AutoRollback:     true,
		ErrorThreshold:   5.0,  // 5% error rate
		LatencyThreshold: 500 * time.Millisecond,
		Metadata:         make(map[string]string),
	}
}

// Canary manages traffic splitting between versions.
type Canary struct {
	config     *Config
	mu         sync.RWMutex
	haltCanary atomic.Bool
	stats      *Stats
	stopCh     chan struct{}
}

// Stats tracks canary performance.
type Stats struct {
	TotalRequests   atomic.Int64
	CanaryRequests  atomic.Int64
	CanaryErrors    atomic.Int64
	TotalLatency    atomic.Int64 // nanoseconds
	CanaryLatency   atomic.Int64 // nanoseconds
	LastHealthCheck time.Time
	Healthy         atomic.Bool
}

// New creates a new canary manager.
func New(cfg *Config) (*Canary, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	c := &Canary{
		config: cfg,
		stats:  &Stats{},
		stopCh: make(chan struct{}),
	}

	c.stats.Healthy.Store(true)

	// Start health check if enabled
	if cfg.HealthCheck.Enabled {
		go c.healthCheckLoop()
	}

	return c, nil
}

// Validate checks config validity.
func (c *Config) Validate() error {
	if c.Percentage < 0 || c.Percentage > 100 {
		return fmt.Errorf("percentage must be between 0 and 100")
	}

	if c.Strategy == "" {
		c.Strategy = StrategyPercentage
	}

	if c.ErrorThreshold < 0 || c.ErrorThreshold > 100 {
		return fmt.Errorf("error_threshold must be between 0 and 100")
	}

	return nil
}

// ShouldRouteToCanary determines if request should go to canary version.
func (c *Canary) ShouldRouteToCanary(r *http.Request) bool {
	if !c.config.Enabled || c.haltCanary.Load() {
		return false
	}

	// Check health
	if !c.stats.Healthy.Load() && c.config.AutoRollback {
		return false
	}

	switch c.config.Strategy {
	case StrategyHeader:
		return c.checkHeader(r)
	case StrategyCookie:
		return c.checkCookie(r)
	case StrategyGeographic:
		return c.checkGeographic(r)
	case StrategyRandom:
		return c.checkRandom()
	default:
		return c.checkPercentage(r)
	}
}

// checkHeader routes based on header presence/value.
func (c *Canary) checkHeader(r *http.Request) bool {
	value := r.Header.Get(c.config.HeaderName)
	if value == "" {
		return false
	}

	// If specific value configured, check match
	if c.config.HeaderValue != "" {
		matched, _ := regexp.MatchString(c.config.HeaderValue, value)
		return matched
	}

	return true
}

// checkCookie routes based on cookie presence/value.
func (c *Canary) checkCookie(r *http.Request) bool {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return false
	}

	// If specific value configured, check match
	if c.config.CookieValue != "" {
		return cookie.Value == c.config.CookieValue
	}

	return true
}

// checkGeographic routes based on region (requires GeoIP).
func (c *Canary) checkGeographic(r *http.Request) bool {
	// Extract region from request (would need GeoIP integration)
	// For now, use CF-IPCountry header as example
	country := r.Header.Get("CF-IPCountry")
	if country == "" {
		country = r.Header.Get("X-Country-Code")
	}

	for _, region := range c.config.Regions {
		if region == country {
			return true
		}
	}

	return false
}

// checkRandom uses pure random selection.
func (c *Canary) checkRandom() bool {
	return c.randomInt(100) < c.config.Percentage
}

// checkPercentage routes based on percentage with sticky sessions.
func (c *Canary) checkPercentage(r *http.Request) bool {
	// Try to use request ID or IP for consistent routing
	key := r.Header.Get("X-Request-ID")
	if key == "" {
		key = r.RemoteAddr + r.UserAgent()
	}

	// Hash-based consistent routing
	hash := fnv32a(key)
	return (hash % 100) < uint32(c.config.Percentage)
}

// fnv32a computes FNV-1a hash for consistent routing.
func fnv32a(s string) uint32 {
	const prime = 16777619
	hash := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime
	}
	return hash
}

// randomInt generates cryptographically secure random int.
func (c *Canary) randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use time-based value if CSPRNG fails
		return int(time.Now().UnixNano() % int64(max))
	}
	val := binary.BigEndian.Uint32(b)
	return int(val % uint32(max))
}

// RecordResult records request result for monitoring.
func (c *Canary) RecordResult(isCanary bool, statusCode int, latency time.Duration) {
	c.stats.TotalRequests.Add(1)
	c.stats.TotalLatency.Add(int64(latency))

	if isCanary {
		c.stats.CanaryRequests.Add(1)
		c.stats.CanaryLatency.Add(int64(latency))

		if statusCode >= 500 {
			c.stats.CanaryErrors.Add(1)
		}

		// Check if we should halt canary
		c.checkCanaryHealth()
	}
}

// checkCanaryHealth evaluates if canary should be halted.
func (c *Canary) checkCanaryHealth() {
	if !c.config.AutoRollback {
		return
	}

	canaryReqs := c.stats.CanaryRequests.Load()
	if canaryReqs < 100 {
		// Not enough samples
		return
	}

	// Check error rate
	errorRate := float64(c.stats.CanaryErrors.Load()) / float64(canaryReqs) * 100
	if errorRate > c.config.ErrorThreshold {
		c.haltCanary.Store(true)
		c.stats.Healthy.Store(false)
		return
	}

	// Check latency
	avgLatency := time.Duration(c.stats.CanaryLatency.Load() / canaryReqs)
	if avgLatency > c.config.LatencyThreshold {
		c.haltCanary.Store(true)
		c.stats.Healthy.Store(false)
	}
}

// healthCheckLoop periodically checks canary health.
func (c *Canary) healthCheckLoop() {
	ticker := time.NewTicker(c.config.HealthCheck.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.performHealthCheck()
		case <-c.stopCh:
			return
		}
	}
}

// performHealthCheck checks if canary upstream is healthy.
func (c *Canary) performHealthCheck() {
	// This would make an HTTP request to canary upstream
	// Simplified implementation
	c.stats.LastHealthCheck = time.Now()

	// If canary was halted but health check passes, consider unhalting
	if c.haltCanary.Load() {
		// Canary remains halted - explicit un halt required after health check pass
		return
	}
}

// GetUpstream returns the appropriate upstream for a request.
func (c *Canary) GetUpstream(r *http.Request) string {
	if c.ShouldRouteToCanary(r) {
		return c.config.CanaryUpstream
	}
	return c.config.StableUpstream
}

// GetStats returns current canary statistics.
func (c *Canary) GetStats() map[string]any {
	total := c.stats.TotalRequests.Load()
	canary := c.stats.CanaryRequests.Load()

	var canaryRate, errorRate float64
	if total > 0 {
		canaryRate = float64(canary) / float64(total) * 100
	}
	if canary > 0 {
		errorRate = float64(c.stats.CanaryErrors.Load()) / float64(canary) * 100
	}

	return map[string]any{
		"enabled":          c.config.Enabled,
		"strategy":         c.config.Strategy,
		"percentage":       c.config.Percentage,
		"canary_version":   c.config.CanaryVersion,
		"total_requests":   total,
		"canary_requests":  canary,
		"canary_rate":      canaryRate,
		"error_rate":       errorRate,
		"healthy":          c.stats.Healthy.Load(),
		"halted":           c.haltCanary.Load(),
		"last_health_check": c.stats.LastHealthCheck,
	}
}

// IsHalted returns if canary is temporarily halted.
func (c *Canary) IsHalted() bool {
	return c.haltCanary.Load()
}

// Resume unhalts canary traffic.
func (c *Canary) Resume() {
	c.haltCanary.Store(false)
	c.stats.Healthy.Store(true)
}

// Halt stops canary traffic.
func (c *Canary) Halt() {
	c.haltCanary.Store(true)
}

// AdjustPercentage updates canary percentage dynamically.
func (c *Canary) AdjustPercentage(pct int) error {
	if pct < 0 || pct > 100 {
		return fmt.Errorf("percentage must be between 0 and 100")
	}
	c.mu.Lock()
	c.config.Percentage = pct
	c.mu.Unlock()
	return nil
}

// Close stops the canary manager.
func (c *Canary) Close() error {
	close(c.stopCh)
	return nil
}

// GetConfig returns the current config.
func (c *Canary) GetConfig() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return *c.config
}
