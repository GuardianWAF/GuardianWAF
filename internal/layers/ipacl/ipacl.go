package ipacl

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Config holds the configuration for the IP ACL layer.
type Config struct {
	Enabled   bool
	Whitelist []string // IPs and CIDRs
	Blacklist []string
	AutoBan   AutoBanConfig
}

// AutoBanConfig configures the auto-ban feature.
type AutoBanConfig struct {
	Enabled           bool
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	MaxAutoBanEntries int
	PersistPath       string        // File path to persist bans across restarts (empty = no persistence)
	PersistInterval   time.Duration // How often to save (default: 30s)
}

type autoBanEntry struct {
	ExpiresAt atomic.Value // time.Time — stored atomically for lock-free reads
	Reason    string
	Count     int // protected by Layer.mu
}

// Layer implements engine.Layer for IP-based access control.
type Layer struct {
	config    Config
	whitelist *RadixTree
	blacklist *RadixTree
	autoBan   map[string]*autoBanEntry // IP string -> entry
	mu        sync.RWMutex             // protects autoBan
	stopCh    chan struct{}            // signals persistence goroutine to stop
}

// NewLayer creates a new IP ACL layer from the given config.
func NewLayer(cfg *Config) (*Layer, error) {
	l := &Layer{
		config:    *cfg,
		whitelist: NewRadixTree(),
		blacklist: NewRadixTree(),
		autoBan:   make(map[string]*autoBanEntry),
		stopCh:    make(chan struct{}),
	}

	// Load persisted bans and start periodic save if configured
	if cfg.AutoBan.PersistPath != "" {
		l.LoadBans(cfg.AutoBan.PersistPath)
		interval := cfg.AutoBan.PersistInterval
		if interval == 0 {
			interval = 30 * time.Second
		}
		go l.persistLoop(interval)
	}

	for _, cidr := range cfg.Whitelist {
		if err := l.whitelist.Insert(cidr, true); err != nil {
			return nil, err
		}
	}

	for _, cidr := range cfg.Blacklist {
		if err := l.blacklist.Insert(cidr, true); err != nil {
			return nil, err
		}
	}

	return l, nil
}

// Name returns the layer name.
func (l *Layer) Name() string { return "ipacl" }

// Process checks the request's client IP against whitelist, blacklist, and auto-ban.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Check if IP ACL is enabled (tenant config takes precedence)
	enabled := l.config.Enabled
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.IPACL.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	ip := ctx.ClientIP
	if ip == nil {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// 1. Check whitelist first -- if match, skip ALL remaining checks
	if _, found := l.whitelist.Lookup(ip); found {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// 2. Check blacklist
	if _, found := l.blacklist.Lookup(ip); found {
		return engine.LayerResult{
			Action: engine.ActionBlock,
			Findings: []engine.Finding{{
				DetectorName: "ipacl",
				Category:     "ipacl",
				Score:        100,
				Severity:     engine.SeverityCritical,
				Description:  "IP is blacklisted",
				MatchedValue: ip.String(),
				Location:     "ip",
			}},
			Score:    100,
			Duration: time.Since(start),
		}
	}

	// 3. Check auto-ban
	if l.isAutoBanned(ip.String()) {
		return engine.LayerResult{
			Action: engine.ActionBlock,
			Findings: []engine.Finding{{
				DetectorName: "ipacl",
				Category:     "ipacl",
				Score:        100,
				Severity:     engine.SeverityCritical,
				Description:  "IP is auto-banned",
				MatchedValue: ip.String(),
				Location:     "ip",
			}},
			Score:    100,
			Duration: time.Since(start),
		}
	}

	return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
}

// AddWhitelist adds an IP or CIDR to the whitelist at runtime.
func (l *Layer) AddWhitelist(cidr string) error {
	return l.whitelist.Insert(cidr, true)
}

// RemoveWhitelist removes an IP or CIDR from the whitelist at runtime.
func (l *Layer) RemoveWhitelist(cidr string) error {
	return l.whitelist.Remove(cidr)
}

// AddBlacklist adds an IP or CIDR to the blacklist at runtime.
func (l *Layer) AddBlacklist(cidr string) error {
	return l.blacklist.Insert(cidr, true)
}

// RemoveBlacklist removes an IP or CIDR from the blacklist at runtime.
func (l *Layer) RemoveBlacklist(cidr string) error {
	return l.blacklist.Remove(cidr)
}

// WhitelistEntries returns all whitelist CIDRs.
func (l *Layer) WhitelistEntries() []string {
	return l.whitelist.Entries()
}

// BlacklistEntries returns all blacklist CIDRs.
func (l *Layer) BlacklistEntries() []string {
	return l.blacklist.Entries()
}

// AddAutoBan adds an IP to the auto-ban list with TTL.
func (l *Layer) AddAutoBan(ip, reason string, ttl time.Duration) {
	if l.config.AutoBan.MaxTTL > 0 && ttl > l.config.AutoBan.MaxTTL {
		ttl = l.config.AutoBan.MaxTTL
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, exists := l.autoBan[ip]
	if exists {
		entry.Count++
		entry.ExpiresAt.Store(time.Now().Add(ttl))
		entry.Reason = reason
	} else {
		if l.config.AutoBan.MaxAutoBanEntries > 0 && len(l.autoBan) >= l.config.AutoBan.MaxAutoBanEntries {
			return
		}
		var expiresAt atomic.Value
		expiresAt.Store(time.Now().Add(ttl))
		l.autoBan[ip] = &autoBanEntry{
			ExpiresAt: expiresAt,
			Reason:    reason,
			Count:     1,
		}
	}
}

// RemoveAutoBan removes an IP from the auto-ban list.
func (l *Layer) RemoveAutoBan(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.autoBan, ip)
}

// BanEntry represents an active temporary ban (exported for API).
type BanEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
	Count     int       `json:"count"`
}

// ActiveBans returns all non-expired auto-ban entries.
func (l *Layer) ActiveBans() []BanEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := time.Now()
	var result []BanEntry
	for ip, entry := range l.autoBan {
		expiresAt, _ := entry.ExpiresAt.Load().(time.Time)
		if now.Before(expiresAt) {
			result = append(result, BanEntry{
				IP: ip, Reason: entry.Reason,
				ExpiresAt: expiresAt, Count: entry.Count,
			})
		}
	}
	return result
}

// ActiveBansAny returns active bans as any (for dashboard API without circular import).
func (l *Layer) ActiveBansAny() any {
	return l.ActiveBans()
}

// CleanupExpired removes expired auto-ban entries.
func (l *Layer) CleanupExpired() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, entry := range l.autoBan {
		expiresAt, _ := entry.ExpiresAt.Load().(time.Time)
		if now.After(expiresAt) {
			delete(l.autoBan, ip)
		}
	}
}

// isAutoBanned checks if IP is currently auto-banned.
func (l *Layer) isAutoBanned(ip string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	entry, exists := l.autoBan[ip]
	if !exists {
		return false
	}
	expiresAt, _ := entry.ExpiresAt.Load().(time.Time)
	return time.Now().Before(expiresAt)
}


// Stop signals the persistence goroutine to stop and flushes bans to disk.
func (l *Layer) Stop() {
	if l.config.AutoBan.PersistPath != "" {
		select {
		case l.stopCh <- struct{}{}:
		default:
		}
		l.SaveBans(l.config.AutoBan.PersistPath)
	}
}

// persistLoop periodically saves bans to disk.
func (l *Layer) persistLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.SaveBans(l.config.AutoBan.PersistPath)
		case <-l.stopCh:
			return
		}
	}
}

// SaveBans writes active (non-expired) bans to a JSON file.
func (l *Layer) SaveBans(path string) {
	bans := l.ActiveBans()
	if len(bans) == 0 {
		os.Remove(path)
		return
	}
	data, err := json.Marshal(bans)
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0600)
}

// LoadBans loads persisted bans from a JSON file.
// Expired bans are skipped automatically.
func (l *Layer) LoadBans(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var bans []BanEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		return
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range bans {
		if now.After(b.ExpiresAt) {
			continue
		}
		var expiresAt atomic.Value
		expiresAt.Store(b.ExpiresAt)
		l.autoBan[b.IP] = &autoBanEntry{
			ExpiresAt: expiresAt,
			Reason:    b.Reason,
			Count:     b.Count,
		}
	}
}
