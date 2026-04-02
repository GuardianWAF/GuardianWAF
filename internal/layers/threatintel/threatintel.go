// Package threatintel provides IP and domain reputation checking against
// threat intelligence feeds. It supports file-based and URL-based feeds
// with automatic refresh.
package threatintel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Config holds the configuration for the Threat Intelligence layer.
type Config struct {
	Enabled      bool            `yaml:"enabled"`
	IPReputation IPRepConfig     `yaml:"ip_reputation"`
	DomainRep    DomainRepConfig `yaml:"domain_reputation"`
	CacheSize    int             `yaml:"cache_size"`
	CacheTTL     time.Duration   `yaml:"cache_ttl"`
	Feeds        []FeedConfig    `yaml:"feeds"`
}

// IPRepConfig configures IP reputation checking.
type IPRepConfig struct {
	Enabled        bool `yaml:"enabled"`
	BlockMalicious bool `yaml:"block_malicious"`
	ScoreThreshold int  `yaml:"score_threshold"`
}

// DomainRepConfig configures domain reputation checking.
type DomainRepConfig struct {
	Enabled        bool `yaml:"enabled"`
	BlockMalicious bool `yaml:"block_malicious"`
	CheckRedirects bool `yaml:"check_redirects"`
}

// Layer implements engine.Layer for threat intelligence.
type Layer struct {
	config      Config
	ipCache     *Cache
	domainCache *Cache
	cidrCache   map[string]*ThreatInfo // CIDR prefixes for lookup
	feeds       []*FeedManager
	mu          sync.RWMutex
	started     bool
}

// NewLayer creates a new Threat Intelligence layer.
func NewLayer(cfg Config) (*Layer, error) {
	cacheSize := cfg.CacheSize
	if cacheSize == 0 {
		cacheSize = 100000
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 60 * time.Minute
	}

	l := &Layer{
		config:      cfg,
		ipCache:     NewCache(cacheSize, cacheTTL),
		domainCache: NewCache(cacheSize/10, cacheTTL),
		cidrCache:   make(map[string]*ThreatInfo),
	}

	// Initialize feed managers
	for _, fc := range cfg.Feeds {
		fm := NewFeedManager(fc)
		fm.SetUpdateCallback(l.updateEntries)
		l.feeds = append(l.feeds, fm)
	}

	// Load initial data
	for _, fm := range l.feeds {
		entries, err := fm.LoadOnce(context.Background())
		if err == nil {
			l.updateEntries(entries)
		}
	}

	return l, nil
}

// Name returns the layer name.
func (l *Layer) Name() string { return "threat_intel" }

// Start begins feed refresh loops.
func (l *Layer) Start() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.started {
		return
	}

	for _, fm := range l.feeds {
		fm.Start()
	}
	l.started = true
}

// Stop stops all feed refresh loops.
func (l *Layer) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, fm := range l.feeds {
		fm.Stop()
	}
	l.started = false
}

// Process checks IP and domain reputation.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var findings []engine.Finding
	totalScore := 0

	// Check IP reputation
	if l.config.IPReputation.Enabled && ctx.ClientIP != nil {
		if info, ok := l.checkIP(ctx.ClientIP); ok {
			if info.Score >= l.config.IPReputation.ScoreThreshold {
				if l.config.IPReputation.BlockMalicious {
					return engine.LayerResult{
						Action: engine.ActionBlock,
						Findings: []engine.Finding{{
							DetectorName: "threat_intel",
							Category:     "reputation",
							Severity:     engine.SeverityCritical,
							Score:        info.Score,
							Description:  fmt.Sprintf("IP in threat feed: %s (source: %s)", info.Type, info.Source),
							MatchedValue: ctx.ClientIP.String(),
							Location:     "ip",
						}},
						Score: info.Score,
					}
				}
				findings = append(findings, engine.Finding{
					DetectorName: "threat_intel",
					Category:     "reputation",
					Severity:     engine.SeverityHigh,
					Score:        info.Score,
					Description:  fmt.Sprintf("IP flagged: %s", info.Type),
					MatchedValue: ctx.ClientIP.String(),
					Location:     "ip",
				})
				totalScore += info.Score
			}
		}
	}

	// Check destination domain (Host header)
	if l.config.DomainRep.Enabled {
		host := getHost(ctx.Headers)
		if host != "" {
			if info, ok := l.checkDomain(host); ok {
				if l.config.DomainRep.BlockMalicious && info.Score >= 70 {
					findings = append(findings, engine.Finding{
						DetectorName: "threat_intel",
						Category:     "reputation",
						Severity:     engine.SeverityHigh,
						Score:        info.Score,
						Description:  fmt.Sprintf("Domain flagged: %s", info.Type),
						MatchedValue: host,
						Location:     "header:Host",
					})
					totalScore += info.Score
				} else {
					// Log but don't block
					findings = append(findings, engine.Finding{
						DetectorName: "threat_intel",
						Category:     "reputation",
						Severity:     engine.SeverityMedium,
						Score:        info.Score / 2,
						Description:  fmt.Sprintf("Domain suspicious: %s", info.Type),
						MatchedValue: host,
						Location:     "header:Host",
					})
					totalScore += info.Score / 2
				}
			}
		}
	}

	if len(findings) > 0 {
		return engine.LayerResult{
			Action:   engine.ActionPass,
			Findings: findings,
			Score:    totalScore,
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

// checkIP looks up an IP in the cache and CIDR ranges.
func (l *Layer) checkIP(ip net.IP) (*ThreatInfo, bool) {
	ipStr := ip.String()

	// Check exact IP match
	if info, ok := l.ipCache.Get(ipStr); ok {
		return info, true
	}

	// Check CIDR ranges
	l.mu.RLock()
	for cidr, info := range l.cidrCache {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			l.mu.RUnlock()
			// Cache the result for this specific IP
			l.ipCache.Set(ipStr, info)
			return info, true
		}
	}
	l.mu.RUnlock()

	return nil, false
}

// checkDomain looks up a domain in the cache.
func (l *Layer) checkDomain(domain string) (*ThreatInfo, bool) {
	// Remove port if present
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}
	domain = strings.ToLower(domain)

	// Check exact match
	if info, ok := l.domainCache.Get(domain); ok {
		return info, true
	}

	// Check parent domains (subdomain matching)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if info, ok := l.domainCache.Get(parent); ok {
			return info, true
		}
	}

	return nil, false
}

// updateEntries is called when a feed refreshes.
func (l *Layer) updateEntries(entries []ThreatEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, e := range entries {
		if e.Info == nil {
			continue
		}

		if e.IP != "" {
			l.ipCache.Set(e.IP, e.Info)
		}
		if e.CIDR != "" {
			l.cidrCache[e.CIDR] = e.Info
		}
		if e.Domain != "" {
			l.domainCache.Set(strings.ToLower(e.Domain), e.Info)
		}
	}
}

// AddIP manually adds an IP to the threat cache.
// Used for runtime threat feed management and advanced integrations.
// Note: Not currently exposed via dashboard API.
func (l *Layer) AddIP(ip string, info *ThreatInfo) {
	l.ipCache.Set(ip, info)
}

// AddDomain manually adds a domain to the threat cache.
// Used for runtime threat feed management and advanced integrations.
// Note: Not currently exposed via dashboard API.
func (l *Layer) AddDomain(domain string, info *ThreatInfo) {
	l.domainCache.Set(strings.ToLower(domain), info)
}

// RemoveIP removes an IP from the cache.
// Used for runtime threat feed management and advanced integrations.
// Note: Not currently exposed via dashboard API.
func (l *Layer) RemoveIP(ip string) {
	l.ipCache.Delete(ip)
}

// Stats returns cache statistics.
func (l *Layer) Stats() map[string]int {
	return map[string]int{
		"ip_cache_size":     l.ipCache.Len(),
		"domain_cache_size": l.domainCache.Len(),
		"cidr_entries":      len(l.cidrCache),
	}
}

// Helper function
func getHost(headers map[string][]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "host") && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
