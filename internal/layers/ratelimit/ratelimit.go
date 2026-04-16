package ratelimit

import (
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Rule defines a rate limiting rule.
type Rule struct {
	ID           string
	Scope        string        // "ip" or "ip+path"
	Paths        []string      // path patterns (glob-like); empty means match all
	Limit        int           // requests per window (used as max tokens)
	Window       time.Duration // refill window
	Burst        int           // burst capacity (if 0, uses Limit)
	Action       string        // "block" or "log"
	AutoBanAfter int           // auto-ban after N violations (0 = disabled)
}

// Config holds the rate limiter configuration.
type Config struct {
	Enabled bool
	Rules   []Rule
}

// Layer implements engine.Layer for rate limiting.
type Layer struct {
	mu         sync.RWMutex
	config     Config
	buckets    sync.Map // key -> *TokenBucket
	violations sync.Map // key -> *int64 (violation count for auto-ban)
	bucketCount atomic.Int64

	// OnAutoBan is called when violation count exceeds AutoBanAfter.
	OnAutoBan func(ip string, reason string)
}

const maxBuckets = 500000 // Hard cap to prevent memory exhaustion

// NewLayer creates a new rate limiter layer.
func NewLayer(cfg *Config) *Layer {
	return &Layer{
		config: *cfg,
	}
}

// Name returns the layer name.
func (l *Layer) Name() string { return "ratelimit" }

// AddRule adds a rate limit rule dynamically at runtime.
func (l *Layer) AddRule(rule Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Replace if rule with same ID exists
	for i, r := range l.config.Rules {
		if r.ID == rule.ID {
			l.config.Rules[i] = rule
			return
		}
	}
	l.config.Rules = append(l.config.Rules, rule)
}

// RemoveRule removes a rate limit rule by ID. Returns true if found and removed.
func (l *Layer) RemoveRule(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, r := range l.config.Rules {
		if r.ID == id {
			l.config.Rules = append(l.config.Rules[:i], l.config.Rules[i+1:]...)
			// Clean up buckets associated with this rule
			l.buckets.Range(func(key, _ any) bool {
				k, ok := key.(string)
			if !ok {
				l.buckets.Delete(key)
				return true
			}
			if strings.HasPrefix(k, id+":") {
					l.buckets.Delete(key)
				}
				return true
			})
			return true
		}
	}
	return false
}

// Cleanup removes stale token buckets that haven't been used recently.
// Should be called periodically (e.g., every 5 minutes) to prevent unbounded memory growth.
func (l *Layer) Cleanup(maxAge time.Duration) {
	now := time.Now()
	l.buckets.Range(func(key, value any) bool {
		b, ok := value.(*TokenBucket)
		if !ok || now.Sub(b.LastAccess()) > maxAge {
			l.buckets.Delete(key)
			l.bucketCount.Add(-1)
		}
		return true
	})
}

// Process checks the request against all rate limit rules.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	// Check if rate limiting is enabled (tenant config takes precedence)
	l.mu.RLock()
	enabled := l.config.Enabled
	l.mu.RUnlock()
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.RateLimit.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	ip := ""
	if ctx.ClientIP != nil {
		ip = ctx.ClientIP.String()
	}
	reqPath := ctx.Path

	var findings []engine.Finding
	totalScore := 0
	blocked := false

	l.mu.RLock()
	tenantID := ctx.TenantID
	rules := make([]Rule, len(l.config.Rules))
	copy(rules, l.config.Rules)
	l.mu.RUnlock()

	for i := range rules {
		rule := &rules[i]

		if !l.matchesRule(rule, reqPath) {
			continue
		}

		key := l.bucketKey(rule, tenantID, ip, reqPath)
		bucket := l.getOrCreateBucket(key, rule)
	if bucket == nil {
		// Bucket limit (500K) reached — system overload. Block all to prevent bypass.
		finding := engine.Finding{
			DetectorName: "ratelimit",
			Category:    "ratelimit",
			Score:       85,
			Severity:    engine.SeverityHigh,
			Description: "Rate limit system overloaded — bucket limit reached: " + rule.ID,
			MatchedValue: key,
			Location:    "ip",
		}
		findings = append(findings, finding)
		totalScore += finding.Score
		blocked = true
		continue
	}

		if !bucket.Allow() {
			finding := engine.Finding{
				DetectorName: "ratelimit",
				Category:     "ratelimit",
				Score:        70,
				Severity:     engine.SeverityHigh,
				Description:  "Rate limit exceeded: " + rule.ID,
				MatchedValue: key,
				Location:     "ip",
			}
			findings = append(findings, finding)
			totalScore += finding.Score

			if rule.Action == "block" {
				blocked = true
			}

			// Track violations for auto-ban
			if rule.AutoBanAfter > 0 {
				l.trackViolation(tenantID, ip, rule)
			}
		}
	}

	action := engine.ActionPass
	if blocked {
		action = engine.ActionBlock
	} else if len(findings) > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
	}
}

// bucketKey generates a unique key for the token bucket based on rule scope and tenant.
// Includes tenant ID in the key to provide per-tenant rate limit isolation.
func (l *Layer) bucketKey(rule *Rule, tenantID, ip, reqPath string) string {
	// Normalize IP: convert IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1)
	// to their IPv4 representation to prevent dual-stack bypass.
	normalizedIP := ip
	if parsed := net.ParseIP(ip); parsed != nil {
		normalizedIP = parsed.String()
	}

	switch rule.Scope {
	case "ip+path":
		// Normalize path: strip query strings and resolve ".." sequences
		normalized := path.Clean(reqPath)
		return rule.ID + ":" + tenantID + ":" + normalizedIP + ":" + normalized
	default: // "ip" or anything else
		return rule.ID + ":" + tenantID + ":" + normalizedIP
	}
}

// getOrCreateBucket retrieves or creates a token bucket for the given key.
func (l *Layer) getOrCreateBucket(key string, rule *Rule) *TokenBucket {
	if val, ok := l.buckets.Load(key); ok {
		return val.(*TokenBucket)
	}

	// Hard cap: reject new bucket creation when limit reached
	if l.bucketCount.Load() >= maxBuckets {
		return nil
	}

	maxTokens := float64(rule.Limit)
	if rule.Burst > 0 {
		maxTokens = float64(rule.Burst)
	}

	// refillRate = Limit tokens per Window
	var refillRate float64
	if rule.Window > 0 {
		refillRate = float64(rule.Limit) / rule.Window.Seconds()
	}

	bucket := NewTokenBucket(maxTokens, refillRate)
	actual, loaded := l.buckets.LoadOrStore(key, bucket)
	if !loaded {
		l.bucketCount.Add(1)
	}
	return actual.(*TokenBucket)
}

// matchesRule checks if the request path matches the rule's path patterns.
func (l *Layer) matchesRule(rule *Rule, reqPath string) bool {
	// If no paths specified, match all
	if len(rule.Paths) == 0 {
		return true
	}

	for _, pattern := range rule.Paths {
		if matchPath(pattern, reqPath) {
			return true
		}
	}
	return false
}

// matchPath performs glob-like matching of a pattern against a path.
func matchPath(pattern, p string) bool {
	// Use path.Match for glob matching
	// Handle ** prefix patterns (match all under a prefix)
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}

	// Exact match or standard glob
	matched, err := path.Match(pattern, p)
	if err != nil {
		return false
	}
	return matched
}

// trackViolation increments the violation counter for a tenant+IP combination
// and triggers auto-ban callback if threshold is exceeded.
func (l *Layer) trackViolation(tenantID, ip string, rule *Rule) {
	key := "violation:" + rule.ID + ":" + tenantID + ":" + ip

	// Pre-check to avoid allocating on every call
	actual, loaded := l.violations.Load(key)
	if !loaded {
		newPtr := new(atomic.Int64)
		actual, _ = l.violations.LoadOrStore(key, newPtr)
	}
	counter := actual.(*atomic.Int64)
	count := counter.Add(1)

	if int(count) >= rule.AutoBanAfter && l.OnAutoBan != nil {
		l.OnAutoBan(ip, "rate limit exceeded: "+rule.ID+" ("+strconv.FormatInt(min(count, 9), 10)+" violations)")
		// Reset counter after ban so next violation cycle requires fresh threshold
		counter.Store(0)
	}
}

// CleanupExpired removes stale token buckets and violation counters that haven't been accessed recently.
// staleDuration defines how old a bucket must be to be removed.
func (l *Layer) CleanupExpired(staleDuration time.Duration) {
	cutoff := time.Now().Add(-staleDuration)

	l.buckets.Range(func(key, value any) bool {
		bucket := value.(*TokenBucket)
		if bucket.LastAccess().Before(cutoff) {
			l.buckets.Delete(key)
		}
		return true
	})

	// Also clean up violation counters for IPs whose buckets were evicted.
	// A violation key has the form "violation:<ruleID>:<tenantID>:<ip>", and the corresponding
	// bucket key is "<ruleID>:<tenantID>:<ip>". If the bucket is gone, the violation counter is stale.
	l.violations.Range(func(key, _ any) bool {
		k := key.(string)
		// Strip "violation:" prefix to get the bucket key
		if len(k) > 10 && k[:10] == "violation:" {
			bucketKey := k[10:] // "violation:" + rest
			if _, exists := l.buckets.Load(bucketKey); !exists {
				l.violations.Delete(key)
			}
		}
		return true
	})
}
