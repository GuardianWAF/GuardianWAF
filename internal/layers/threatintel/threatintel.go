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
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
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
	// cidrTree is read on every request and swapped wholesale on feed refresh.
	// An atomic pointer keeps request-path reads lock-free and guarantees they
	// never observe a half-rebuilt tree (the new tree is fully built, then
	// published in one store).
	cidrTree atomic.Pointer[ipacl.RadixTree]
	// cidrEntries accumulates every feed's CIDR ranges keyed by the CIDR
	// string. Each FeedManager callback carries only its own entries, so the
	// published tree must be rebuilt from this union — replacing it with one
	// feed's slice made the last refresh win and silently dropped every other
	// feed's ranges from the blocking path.
	cidrEntries map[string]*ThreatInfo
	feeds       []*FeedManager
	mu          sync.RWMutex
	lifecycleMu sync.Mutex // serializes Start/Stop without blocking feed callbacks
	started     bool
}

// NewLayer creates a new Threat Intelligence layer.
func NewLayer(cfg *Config) (*Layer, error) {
	cacheSize := cfg.CacheSize
	if cacheSize == 0 {
		cacheSize = 100000
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 60 * time.Minute
	}

	l := &Layer{
		config:      *cfg,
		ipCache:     NewCache(cacheSize, cacheTTL),
		domainCache: NewCache(cacheSize/10, cacheTTL),
		cidrEntries: make(map[string]*ThreatInfo),
	}
	l.cidrTree.Store(ipacl.NewRadixTree())

	// Initialize feed managers
	for i := range cfg.Feeds {
		fc := &cfg.Feeds[i]
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
func (l *Layer) Order() int   { return engine.OrderThreatIntel }

// Start begins feed refresh loops.
func (l *Layer) Start() {
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()

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
	_ = l.StopWithContext(context.Background())
}

// StopWithContext stops all feed refresh loops without waiting past ctx.
func (l *Layer) StopWithContext(ctx context.Context) error {
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()

	var firstErr error
	for _, fm := range l.feeds {
		if err := fm.StopWithContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.started = false
	return firstErr
}

// Process checks IP and domain reputation.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Check if threat intel is enabled (tenant config takes precedence)
	enabled := l.config.Enabled
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.ThreatIntel.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
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
						Score:    info.Score,
						Duration: time.Since(start),
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
				if l.domainMustBlock(info) {
					// Mirror the IP path: BlockMalicious must actually block,
					// not just log a finding the pipeline scores as a pass.
					return engine.LayerResult{
						Action: engine.ActionBlock,
						Findings: []engine.Finding{{
							DetectorName: "threat_intel",
							Category:     "reputation",
							Severity:     engine.SeverityHigh,
							Score:        info.Score,
							Description:  fmt.Sprintf("Domain flagged: %s", info.Type),
							MatchedValue: host,
							Location:     "header:Host",
						}},
						Score:    info.Score,
						Duration: time.Since(start),
					}
				}
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

		// ADR 0034 check_redirects: the request body is scanned for URLs and
		// their hostnames are checked too — a form submission that POSTs to a
		// known phishing domain must trigger the alert (and the block, when
		// block_malicious is set). The Host above was already checked, so it is
		// skipped here; the same policy applies to every body URL host.
		if l.config.DomainRep.CheckRedirects {
			for _, domain := range bodyURLCandidates(ctx.BodyString) {
				if domain == host {
					continue
				}
				info, ok := l.checkDomain(domain)
				if !ok {
					continue
				}
				if l.domainMustBlock(info) {
					return engine.LayerResult{
						Action: engine.ActionBlock,
						Findings: []engine.Finding{{
							DetectorName: "threat_intel",
							Category:     "reputation",
							Severity:     engine.SeverityHigh,
							Score:        info.Score,
							Description:  fmt.Sprintf("Domain flagged in request body: %s", info.Type),
							MatchedValue: domain,
							Location:     "body:url",
						}},
						Score:    info.Score,
						Duration: time.Since(start),
					}
				}
				findings = append(findings, engine.Finding{
					DetectorName: "threat_intel",
					Category:     "reputation",
					Severity:     engine.SeverityMedium,
					Score:        info.Score / 2,
					Description:  fmt.Sprintf("Domain suspicious in request body: %s", info.Type),
					MatchedValue: domain,
					Location:     "body:url",
				})
				totalScore += info.Score / 2
			}
		}
	}

	if len(findings) > 0 {
		return engine.LayerResult{
			Action:   engine.ActionPass,
			Findings: findings,
			Score:    totalScore,
			Duration: time.Since(start),
		}
	}

	return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
}

// checkIP looks up an IP in the cache and CIDR radix tree.
func (l *Layer) checkIP(ip net.IP) (*ThreatInfo, bool) {
	ipStr := ip.String()

	// Check exact IP match (LRU cache)
	if info, ok := l.ipCache.Get(ipStr); ok {
		return info, true
	}

	// Check CIDR ranges via radix tree — O(128) regardless of entry count
	if val, ok := l.cidrTree.Load().Lookup(ip); ok {
		if info, ok := val.(*ThreatInfo); ok {
			l.ipCache.Set(ipStr, info)
			return info, true
		}
	}

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
			l.cidrEntries[e.CIDR] = e.Info
		}
		if e.Domain != "" {
			l.domainCache.Set(strings.ToLower(e.Domain), e.Info)
		}
	}

	// Rebuild the CIDR tree from the accumulated union of ALL feeds' ranges
	// before publishing it, so concurrent request-path readers never observe
	// a half-populated tree. Building it from the callback's slice alone made
	// the last refresh win: with multiple feeds, every refresh dropped the
	// other feeds' ranges from the blocking path until their next refresh.
	// Accumulation trades per-feed removals for never losing cross-feed
	// coverage — the safe direction for a blocking control, and the same
	// accumulate-on-refresh behavior the caches already have.
	newTree := ipacl.NewRadixTree()
	for cidr, info := range l.cidrEntries {
		_ = newTree.Insert(cidr, info) //nolint:errcheck // #nosec G104 -- in-memory tree insert; cannot fail
	}
	l.cidrTree.Store(newTree)
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
		"cidr_entries":      l.cidrTree.Load().Len(),
	}
}

// domainBlockScore is the feed score at which a domain match blocks when
// block_malicious is set. The IP path has its own operator-tunable threshold;
// the domain bar is fixed (see ADR 0034).
const domainBlockScore = 70

// domainMustBlock reports whether a feed match on a domain must block rather
// than only be reported. Shared by the Host check and the check_redirects body
// scan so the two paths cannot drift apart.
func (l *Layer) domainMustBlock(info *ThreatInfo) bool {
	return l.config.DomainRep.BlockMalicious && info.Score >= domainBlockScore
}

// maxBodyURLHosts bounds how many distinct body URL hostnames one request may
// add to the reputation lookup, so a body full of links cannot turn a single
// request into unbounded cache work.
const maxBodyURLHosts = 32

// bodyURLHosts returns the distinct hostnames of the http(s) URLs found in a
// request body, in first-seen order. check_redirects (ADR 0034) uses it to
// extend domain reputation to URLs carried in the body. A bracketed IPv6
// literal keeps its brackets and trailing sentence punctuation is trimmed, so
// "see https://evil.example." still yields the domain.
func bodyURLHosts(body string) []string {
	if body == "" {
		return nil
	}
	var hosts []string
	seen := make(map[string]struct{}, 8)

	for idx := 0; idx < len(body); {
		start := indexHTTP(body, idx)
		if start < 0 {
			break
		}

		var authorityStart int
		switch {
		case len(body)-start >= len("https://") && strings.EqualFold(body[start:start+len("https://")], "https://"):
			authorityStart = start + len("https://")
		case len(body)-start >= len("http://") && strings.EqualFold(body[start:start+len("http://")], "http://"):
			authorityStart = start + len("http://")
		default:
			idx = start + 1
			continue
		}

		end := urlAuthorityEnd(body, authorityStart)
		idx = end
		host := urlHost(strings.ToLower(body[authorityStart:end]))
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
		if len(hosts) >= maxBodyURLHosts {
			return hosts
		}
	}
	return hosts
}

// indexHTTP returns the index of the next 'h'/'H' at or after from — the only
// byte an http(s) scheme can start with — or -1 when there is none. Searching
// byte-wise keeps the scan case-insensitive without copying the body.
func indexHTTP(s string, from int) int {
	for i := from; i < len(s); i++ {
		if s[i] == 'h' || s[i] == 'H' {
			return i
		}
	}
	return -1
}

// bodyURLCandidates returns the distinct body-URL hostnames to check, from the
// raw body and from its percent-decoded form: a form submission carries the URL
// encoded (ADR 0034's example is exactly that), and this layer runs at order 125,
// before the sanitizer populates the Normalized* views, so the raw body is the
// only available input. The union is bounded by maxBodyURLHosts.
func bodyURLCandidates(body string) []string {
	hosts := bodyURLHosts(body)
	if len(hosts) >= maxBodyURLHosts {
		return hosts[:maxBodyURLHosts]
	}

	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		seen[h] = struct{}{}
	}
	// The decoded view must survive a malformed escape ANYWHERE in the body.
	// url.QueryUnescape is all-or-nothing: one invalid escape makes it return
	// ("", err), so the whole decoded view was discarded — and with it the
	// only view that can see a percent-encoded URL (a form submission). A
	// stray "%" in an unrelated field ("note=100%") therefore silenced the
	// phishing check for the entire request. sanitizer.DecodeURLRecursive is
	// the repo's canonical decoder: it keeps an invalid escape literal
	// instead of failing the whole body, and it reaches the fixed point, so a
	// double-encoded URL is seen too. This layer runs at order 125, before
	// the sanitizer layer populates the Normalized* views, so the body is
	// normalized on demand here — the same pattern rules.go uses for the
	// canonical path.
	decoded := sanitizer.DecodeURLRecursive(body)
	if decoded == body {
		return hosts
	}
	for _, h := range bodyURLHosts(decoded) {
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
		if len(hosts) >= maxBodyURLHosts {
			break
		}
	}
	return hosts
}

// urlAuthorityEnd returns the end of a URL authority (host[:port]) inside s,
// starting at from: it stops at the first character that cannot be part of an
// authority in prose or in a query string.
func urlAuthorityEnd(s string, from int) int {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '/', '?', '#', ' ', '\t', '\r', '\n', '"', '\'', '<', '>', '(', ')',
			'{', '}', ',', ';', '&', '\\', '*', '|', '^', '`':
			return i
		}
	}
	return len(s)
}

// urlHost reduces a URL authority to its hostname: userinfo and port are
// dropped, a bracketed IPv6 literal keeps its brackets, and trailing sentence
// punctuation is trimmed.
func urlHost(authority string) string {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	if strings.HasPrefix(authority, "[") {
		if end := strings.IndexByte(authority, ']'); end >= 0 {
			return authority[:end+1]
		}
		return ""
	}
	if colon := strings.IndexByte(authority, ':'); colon >= 0 {
		authority = authority[:colon]
	}
	return strings.TrimRight(authority, ".")
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
