package ipacl

import (
	"sync"
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
	Enabled    bool
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

type autoBanEntry struct {
	ExpiresAt time.Time
	Reason    string
	Count     int
}

// Layer implements engine.Layer for IP-based access control.
type Layer struct {
	config    Config
	whitelist *RadixTree
	blacklist *RadixTree
	autoBan   map[string]*autoBanEntry // IP string -> entry
	mu        sync.RWMutex             // protects autoBan
}

// NewLayer creates a new IP ACL layer from the given config.
func NewLayer(cfg Config) (*Layer, error) {
	l := &Layer{
		config:    cfg,
		whitelist: NewRadixTree(),
		blacklist: NewRadixTree(),
		autoBan:   make(map[string]*autoBanEntry),
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
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	ip := ctx.ClientIP
	if ip == nil {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// 1. Check whitelist first -- if match, skip ALL remaining checks
	if _, found := l.whitelist.Lookup(ip); found {
		return engine.LayerResult{Action: engine.ActionPass}
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
			Score: 100,
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
			Score: 100,
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
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
		entry.ExpiresAt = time.Now().Add(ttl)
		entry.Reason = reason
	} else {
		l.autoBan[ip] = &autoBanEntry{
			ExpiresAt: time.Now().Add(ttl),
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
		if now.Before(entry.ExpiresAt) {
			result = append(result, BanEntry{
				IP: ip, Reason: entry.Reason,
				ExpiresAt: entry.ExpiresAt, Count: entry.Count,
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
		if now.After(entry.ExpiresAt) {
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
	return time.Now().Before(entry.ExpiresAt)
}
