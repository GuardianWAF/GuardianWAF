// Package tenant provides multi-tenancy support with namespace isolation.
// Each tenant has isolated configurations, rules, rate limits, and event storage.
package tenant

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	logging "github.com/guardianwaf/guardianwaf/internal/logging"
	"github.com/guardianwaf/guardianwaf/internal/netutil"
)

// persistenceError identifies a failed durable mutation at HTTP adapter seams.
type persistenceError struct {
	op  string
	err error
}

func (e *persistenceError) Error() string       { return e.op + ": " + e.err.Error() }
func (e *persistenceError) Unwrap() error       { return e.err }
func (e *persistenceError) HTTPStatusCode() int { return http.StatusInternalServerError }

// Tenant represents a single tenant with isolated WAF configuration.
type Tenant struct {
	// Metadata
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Active      bool      `json:"active"`

	// Authentication
	APIKeyHash string   `json:"api_key_hash"` // SHA256 hash
	Domains    []string `json:"domains"`      // Allowed domains for this tenant

	// Resource quotas
	Quota ResourceQuota `json:"quota"`

	// Isolated configuration
	Config *config.Config `json:"config"`

	// Usage tracking
	mu            sync.RWMutex
	RequestCount  int64
	ByteCount     int64
	BlockedCount  int64
	LastRequestAt time.Time
}

// ResourceQuota defines resource limits for a tenant.
type ResourceQuota struct {
	MaxRequestsPerMinute int64 `json:"max_requests_per_minute"`
	MaxRequestsPerHour   int64 `json:"max_requests_per_hour"`
	MaxBandwidthMbps     int   `json:"max_bandwidth_mbps"`
	MaxRules             int   `json:"max_rules"`
	MaxRateLimitRules    int   `json:"max_rate_limit_rules"`
	MaxIPACLs            int   `json:"max_ip_acls"`
}

// DefaultQuota returns default resource quotas.
func DefaultQuota() ResourceQuota {
	return ResourceQuota{
		MaxRequestsPerMinute: 10000,
		MaxRequestsPerHour:   500000,
		MaxBandwidthMbps:     100,
		MaxRules:             100,
		MaxRateLimitRules:    10,
		MaxIPACLs:            1000,
	}
}

// Manager manages multiple tenants with isolation.
type Manager struct {
	mu      sync.RWMutex
	tenants map[string]*Tenant // key: tenant ID
	domains map[string]string  // key: domain -> tenant ID

	// Default tenant for unauthenticated requests
	defaultTenantID string

	// RejectUnmatched causes ResolveTenant to return nil when no tenant
	// matches the request, instead of falling back to the default tenant.
	RejectUnmatched bool

	// Global limits
	maxTenants int

	// Rate limiting
	rateLimiter *TenantRateLimiter
	hourLimiter *TenantRateLimiter // 1-hour sliding window for MaxRequestsPerHour

	// Tenant-specific rules
	rulesManager *TenantRulesManager

	// Alerts
	alertManager *AlertManager

	// apiKeyCache memoizes API-key → tenant-ID resolution keyed by a fast
	// SHA-256 of the presented key. Without it, every request runs the
	// deliberately-expensive PBKDF2 verification against every tenant, which an
	// unauthenticated attacker can turn into a CPU-exhaustion DoS. A cached
	// negative result (empty tenant ID) blunts repeated invalid keys. The cache
	// is fully cleared whenever any key changes, so it never returns a stale
	// mapping.
	apiKeyCacheMu sync.Mutex
	apiKeyCache   map[string]string

	// Persistence
	store *Store

	// Cluster sync for multi-node replication
	clusterSync     ClusterSync
	clusterSyncMu   sync.RWMutex
	broadcastSem    chan struct{}
	broadcastMu     sync.Mutex
	broadcastClosed bool
	broadcastWG     sync.WaitGroup

	// Structured logger
	log *slog.Logger
}

// NewManager creates a new tenant manager.
func NewManager(maxTenants int) *Manager {
	return NewManagerWithStore(maxTenants, "")
}

// NewManagerWithStore creates a new tenant manager with persistence.
func NewManagerWithStore(maxTenants int, storePath string) *Manager {
	m := &Manager{
		tenants:      make(map[string]*Tenant),
		domains:      make(map[string]string),
		maxTenants:   maxTenants,
		rateLimiter:  NewTenantRateLimiter(time.Minute),
		hourLimiter:  NewTenantRateLimiter(time.Hour),
		rulesManager: NewTenantRulesManager(100),
		alertManager: NewAlertManager(),
		store:        NewStore(storePath),
		broadcastSem: make(chan struct{}, 16),
		log:          logging.NewLogger("tenant"),
	}
	return m
}

// Init initializes the manager and loads persisted tenants.
func (m *Manager) Init() error {
	if m.store == nil {
		return nil
	}
	if err := m.store.Init(); err != nil {
		return err
	}
	return m.LoadTenants()
}

// LoadTenants loads all tenants from persistent storage.
func (m *Manager) LoadTenants() error {
	if m.store == nil {
		return nil
	}

	tenants, err := m.store.LoadAllTenants()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, tenant := range tenants {
		m.tenants[tenant.ID] = tenant
		for _, domain := range tenant.Domains {
			m.domains[domainKey(domain)] = tenant.ID
		}
		// Set first tenant as default
		if m.defaultTenantID == "" {
			m.defaultTenantID = tenant.ID
			m.log.Warn("Default tenant set for unmatched requests", "tenantName", tenant.Name, "tenantID", tenant.ID)
		}
	}

	return nil
}

// SaveTenant persists a tenant to storage. UpdatedAt is stamped under the
// per-tenant lock so the write is ordered with the tenant.mu readers
// (sanitizeTenant) even though callers hold only m.mu.
func (m *Manager) SaveTenant(tenant *Tenant) error {
	if m.store == nil || tenant == nil {
		return nil
	}
	tenant.mu.Lock()
	tenant.UpdatedAt = time.Now()
	tenant.mu.Unlock()
	return m.store.SaveTenant(tenant)
}

// Close stops tenant-owned background workers.
func (m *Manager) Close() {
	_ = m.CloseWithContext(context.Background())
}

// CloseWithContext stops tenant-owned background workers and waits within ctx.
func (m *Manager) CloseWithContext(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.broadcastMu.Lock()
	m.broadcastClosed = true
	m.broadcastMu.Unlock()

	var alertErr error
	if m.alertManager != nil {
		alertErr = m.alertManager.CloseWithContext(ctx)
	}
	broadcastErr := waitForTenantBroadcast(ctx, &m.broadcastWG)
	if alertErr != nil {
		return alertErr
	}
	return broadcastErr
}

// CreateTenant creates a new tenant.
func (m *Manager) CreateTenant(name, description string, domains []string, quota *ResourceQuota) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check tenant limit
	if m.maxTenants > 0 && len(m.tenants) >= m.maxTenants {
		return nil, fmt.Errorf("maximum number of tenants (%d) reached", m.maxTenants)
	}

	// Generate tenant ID
	id, err := generateTenantID(name)
	if err != nil {
		return nil, err
	}

	// Check if tenant exists
	if _, exists := m.tenants[id]; exists {
		return nil, fmt.Errorf("tenant with ID %s already exists", id)
	}

	// Check domain uniqueness. Domains are normalized first at this
	// index-write seam: resolution strips the port from Host
	// (netutil.StripPort) and Host headers cannot carry whitespace, so raw
	// port-suffixed or padded values would register index keys that can
	// never match a request. Case is preserved for display (domainKey
	// lowercases the index keys).
	normalizedDomains := make([]string, 0, len(domains))
	for _, domain := range domains {
		d := normalizeDomain(domain)
		if d == "" {
			return nil, fmt.Errorf("invalid domain %q: empty after normalization", domain)
		}
		normalizedDomains = append(normalizedDomains, d)
	}
	domains = normalizedDomains

	for _, domain := range domains {
		if existingID, exists := m.domains[domainKey(domain)]; exists {
			return nil, fmt.Errorf("domain %s already assigned to tenant %s", domain, existingID)
		}
	}

	// Generate API key
	apiKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	apiKeyHash, err := hashAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	// Use default quota if not provided
	q := DefaultQuota()
	if quota != nil {
		q = *quota
	}

	tenant := &Tenant{
		ID:          id,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Active:      true,
		APIKeyHash:  apiKeyHash,
		Domains:     domains,
		Quota:       q,
		Config:      config.DefaultConfig(),
	}

	// Do not publish a tenant whose credentials/config did not reach storage.
	if err := m.SaveTenant(tenant); err != nil {
		return nil, &persistenceError{op: "persist tenant", err: err}
	}

	m.tenants[id] = tenant
	m.invalidateAPIKeyCache()

	// Register domains
	for _, domain := range domains {
		m.domains[domainKey(domain)] = id
	}

	// Set as default if first tenant
	if len(m.tenants) == 1 {
		m.defaultTenantID = id
	}

	// Broadcast to cluster
	m.broadcast("tenant", tenant.ID, "create", map[string]any{
		"id":          tenant.ID,
		"name":        tenant.Name,
		"description": tenant.Description,
		"domains":     tenant.Domains,
		"active":      tenant.Active,
		"quota":       tenant.Quota,
	})

	return tenant, nil
}

// GetTenant returns a tenant by ID.
func (m *Manager) GetTenant(id string) *Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenants[id]
}

// IsTenantActive returns whether the tenant is active (thread-safe).
func (m *Manager) IsTenantActive(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[id]
	if !ok {
		return false
	}
	return t.Active
}

// GetDefaultTenantID returns the default tenant ID (thread-safe).
func (m *Manager) GetDefaultTenantID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultTenantID
}

// GetTenantByDomain returns the tenant for a given domain.
func (m *Manager) GetTenantByDomain(domain string) *Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// DNS names are case-insensitive: the index stores normalized keys.
	domain = domainKey(domain)

	// Exact match
	if tenantID, exists := m.domains[domain]; exists {
		return m.tenants[tenantID]
	}

	// Try wildcard match. Multiple wildcard patterns can match one host
	// (e.g. *.example.com and *.sub.example.com both match
	// shop.sub.example.com), and Go map iteration order is randomized, so
	// returning on the first hit made tenant resolution nondeterministic.
	// Standard DNS wildcard semantics apply: the longest (most-specific)
	// suffix wins. Two distinct equal-length patterns cannot both
	// suffix-match one host, so longest-pattern alone is deterministic.
	bestPattern := ""
	var bestTenantID string
	for d, tenantID := range m.domains {
		if matchWildcard(domain, d) && len(d) > len(bestPattern) {
			bestPattern = d
			bestTenantID = tenantID
		}
	}
	if bestPattern != "" {
		return m.tenants[bestTenantID]
	}

	return nil
}

// apiKeyCacheMax bounds the verification cache so it cannot itself grow
// unbounded under a spray of unique invalid keys.
const apiKeyCacheMax = 4096

// fastKeyHash returns a fast, non-reversible cache key for an API key.
func fastKeyHash(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return string(sum[:])
}

// GetTenantByAPIKey returns the tenant for a given API key.
func (m *Manager) GetTenantByAPIKey(apiKey string) *Tenant {
	if apiKey == "" {
		return nil
	}

	// Keep verification, cache reads/publication, and key invalidation in one
	// manager-lock order. Otherwise a completed lookup can repopulate an old
	// key after a concurrent rotation has invalidated the cache.
	m.mu.RLock()
	defer m.mu.RUnlock()
	cacheKey := fastKeyHash(apiKey)

	// Fast path: consult the memoized result and skip PBKDF2 entirely.
	if tenantID, ok := m.cachedTenantID(cacheKey); ok {
		if tenantID == "" {
			return nil // cached negative result
		}
		tenant := m.tenants[tenantID]
		if tenant != nil {
			return tenant
		}
		// Tenant vanished (deleted without a cache clear); fall through to
		// the slow path, which re-verifies the key from scratch.
	}

	// Slow path: verify against each tenant (expensive PBKDF2).
	var found *Tenant
	for _, tenant := range m.tenants {
		tenant.mu.RLock()
		hash := tenant.APIKeyHash
		tenant.mu.RUnlock()
		if matched, legacy := verifyAPIKey(hash, apiKey); matched {
			if legacy {
				// Auto-upgrade unsalted hash to salted hash
				newHash, err := hashAPIKey(apiKey)
				if err != nil {
					m.log.Error("failed to upgrade legacy API key hash", "tenantID", tenant.ID, "err", err)
				} else {
					tenant.mu.Lock()
					tenant.APIKeyHash = newHash
					tenant.mu.Unlock()
					m.log.Info("upgraded legacy unsalted API key hash", "tenantID", tenant.ID)
				}
			}
			found = tenant
			break
		}
	}
	m.cacheAPIKeyResult(cacheKey, found)
	return found
}

// cachedTenantID returns the memoized tenant ID for cacheKey and whether the
// cache held an entry for it at all (an entry of "" is a cached NEGATIVE
// result, distinct from a miss).
//
// The lock is taken and released exactly once, on every path. The previous
// inline fast path released apiKeyCacheMu inside the cache-hit branch and then
// fell through to a second, unconditional Unlock at the end of the block — so a
// cache entry naming a tenant that was no longer in m.tenants (the
// "deleted without a cache clear" case) released the mutex twice. On a
// sync.Mutex that is `fatal error: sync: unlock of unlocked mutex`, a runtime
// throw rather than a recoverable panic: one unauthenticated request carrying
// the affected key aborted the whole process. Scoping the read to this helper
// makes the single release structural instead of something each branch has to
// remember.
func (m *Manager) cachedTenantID(cacheKey string) (tenantID string, ok bool) {
	m.apiKeyCacheMu.Lock()
	defer m.apiKeyCacheMu.Unlock()
	if m.apiKeyCache == nil {
		return "", false
	}
	tenantID, ok = m.apiKeyCache[cacheKey]
	return tenantID, ok
}

// cacheAPIKeyResult memoizes an API-key verification outcome (found may be nil
// for a negative result).
func (m *Manager) cacheAPIKeyResult(cacheKey string, found *Tenant) {
	m.apiKeyCacheMu.Lock()
	defer m.apiKeyCacheMu.Unlock()
	if m.apiKeyCache == nil {
		m.apiKeyCache = make(map[string]string)
	}
	// Simple bound: drop the whole cache if it grows too large. Cheap and safe
	// since entries are pure memoization rebuilt on demand.
	if len(m.apiKeyCache) >= apiKeyCacheMax {
		m.apiKeyCache = make(map[string]string)
	}
	if found == nil {
		m.apiKeyCache[cacheKey] = ""
	} else {
		m.apiKeyCache[cacheKey] = found.ID
	}
}

// invalidateAPIKeyCache clears the verification cache. Called whenever any key
// changes so a stale mapping can never be returned.
func (m *Manager) invalidateAPIKeyCache() {
	m.apiKeyCacheMu.Lock()
	m.apiKeyCache = nil
	m.apiKeyCacheMu.Unlock()
}

// ResolveTenant determines the tenant for an incoming request.
// Priority: API Key header > Domain > Default tenant (or reject if RejectUnmatched)
func (m *Manager) ResolveTenant(r *http.Request) *Tenant {
	// 1. Try API key
	apiKey := r.Header.Get("X-GuardianWAF-Tenant-Key")
	if apiKey != "" {
		if tenant := m.GetTenantByAPIKey(apiKey); tenant != nil {
			return tenant
		}
	}

	// 2. Try domain — r.Host carries "host:port" for any request to a
	// non-default port, so strip the port before matching registered
	// domains (mirrors the proxy virtual-host router).
	domain := netutil.StripPort(r.Host)
	if domain != "" {
		if tenant := m.GetTenantByDomain(domain); tenant != nil {
			return tenant
		}
	}

	// 3. Reject unmatched or return default tenant
	if m.RejectUnmatched {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenants[m.defaultTenantID]
}

// UpdateTenant updates a tenant's configuration atomically.
// All updates (config, domains) are performed under a single m.mu lock
// to prevent race conditions between related fields.
func (m *Manager) UpdateTenant(id string, updates *TenantUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, exists := m.tenants[id]
	if !exists {
		return fmt.Errorf("tenant %s not found", id)
	}

	// Validate domains before publishing any part of the update.
	var normalizedDomains []string
	if len(updates.Domains) > 0 {
		// Normalize at this index-write seam (see CreateTenant): raw
		// port-suffixed or padded values could never match a request.
		normalizedDomains = make([]string, 0, len(updates.Domains))
		for _, domain := range updates.Domains {
			d := normalizeDomain(domain)
			if d == "" {
				return fmt.Errorf("invalid domain %q: empty after normalization", domain)
			}
			normalizedDomains = append(normalizedDomains, d)
		}
		for _, domain := range normalizedDomains {
			if existingID, exists := m.domains[domainKey(domain)]; exists && existingID != id {
				return fmt.Errorf("domain %s already assigned to tenant %s", domain, existingID)
			}
		}
	}

	// Build a detached record. Requests holding the live tenant pointer must
	// observe only committed state, including while disk I/O is in progress.
	tenant.mu.RLock()
	staged := tenantRecord(tenant)
	tenant.mu.RUnlock()
	if updates.Name != "" {
		staged.Name = updates.Name
	}
	if updates.Description != "" {
		staged.Description = updates.Description
	}
	if updates.Active != nil {
		staged.Active = *updates.Active
	}
	if updates.Quota != nil {
		staged.Quota = *updates.Quota
	}
	if updates.Config != nil {
		staged.Config = updates.Config.DeepCopy()
	}
	if len(updates.Domains) > 0 {
		staged.Domains = normalizedDomains
	}
	if err := m.SaveTenant(staged); err != nil {
		return &persistenceError{op: "persist tenant update", err: err}
	}

	// Publish under both the index and tenant locks. Preserve the live pointer
	// and its usage counters; callers may already be using this tenant.
	tenant.mu.Lock()
	for _, oldDomain := range tenant.Domains {
		delete(m.domains, domainKey(oldDomain))
	}
	tenant.Name, tenant.Description = staged.Name, staged.Description
	tenant.Active, tenant.Quota = staged.Active, staged.Quota
	tenant.Config, tenant.Domains = staged.Config, staged.Domains
	tenant.UpdatedAt = staged.UpdatedAt
	for _, domain := range tenant.Domains {
		m.domains[domainKey(domain)] = id
	}
	tenant.mu.Unlock()

	// Broadcast to cluster
	m.broadcast("tenant", tenant.ID, "update", map[string]any{
		"id":          tenant.ID,
		"name":        tenant.Name,
		"description": tenant.Description,
		"domains":     tenant.Domains,
		"active":      tenant.Active,
		"quota":       tenant.Quota,
	})

	return nil
}

// DeleteTenant deletes a tenant.
func (m *Manager) DeleteTenant(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, exists := m.tenants[id]
	if !exists {
		return fmt.Errorf("tenant %s not found", id)
	}

	// A failed deletion must leave the live tenant and its key intact.
	if m.store != nil {
		if err := m.store.DeleteTenant(id); err != nil {
			return &persistenceError{op: "delete tenant from storage", err: err}
		}
	}

	// Remove domain mappings
	for _, domain := range tenant.Domains {
		delete(m.domains, domainKey(domain))
	}

	delete(m.tenants, id)
	m.invalidateAPIKeyCache()

	// Update default tenant if needed
	if m.defaultTenantID == id {
		m.defaultTenantID = ""
		for tid := range m.tenants {
			m.defaultTenantID = tid
			break
		}
	}

	// Broadcast to cluster
	m.broadcast("tenant", id, "delete", map[string]any{
		"id": id,
	})

	return nil
}

// RegenerateAPIKey generates a new API key for a tenant.
func (m *Manager) RegenerateAPIKey(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, exists := m.tenants[id]
	if !exists {
		return "", fmt.Errorf("tenant %s not found", id)
	}

	newKey, err := generateAPIKey()
	if err != nil {
		return "", err
	}
	newHash, err := hashAPIKey(newKey)
	if err != nil {
		return "", err
	}
	tenant.mu.RLock()
	staged := tenantRecord(tenant)
	tenant.mu.RUnlock()
	staged.APIKeyHash = newHash
	if err := m.SaveTenant(staged); err != nil {
		return "", &persistenceError{op: "persist API key update", err: err}
	}
	tenant.mu.Lock()
	tenant.APIKeyHash, tenant.UpdatedAt = staged.APIKeyHash, staged.UpdatedAt
	tenant.mu.Unlock()
	m.invalidateAPIKeyCache()

	return newKey, nil
}

// tenantRecord copies persisted fields without copying the live mutex/counters.
// The caller holds tenant.mu for reading.
func tenantRecord(t *Tenant) *Tenant {
	return &Tenant{
		ID: t.ID, Name: t.Name, Description: t.Description,
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt, Active: t.Active,
		APIKeyHash: t.APIKeyHash, Domains: append([]string(nil), t.Domains...),
		Quota: t.Quota, Config: t.Config,
	}
}

// VerifyTenantAPIKey checks current committed credentials while holding the
// manager lock. Dashboard authentication must not use a stale copied key list.
func (m *Manager) VerifyTenantAPIKey(id, key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := m.tenants[id]
	if t == nil || key == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.Active {
		return false
	}
	matched, _ := verifyAPIKey(t.APIKeyHash, key)
	return matched
}

// TenantConfigSnapshot returns a detached config for an administrative patch.
func (m *Manager) TenantConfigSnapshot(id string) (*config.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := m.tenants[id]
	if t == nil {
		return nil, fmt.Errorf("tenant %s not found", id)
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Config == nil {
		return config.DefaultConfig(), nil
	}
	return t.Config.DeepCopy(), nil
}

// ListTenants returns all tenants.
func (m *Manager) ListTenants() []*Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]*Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		tenants = append(tenants, t)
	}
	return tenants
}

// TenantAPIKeyHashes returns an immutable snapshot of tenant authentication
// hashes. Copying under the manager lock prevents dashboard synchronization
// from racing with tenant creation, deletion, or key regeneration.
func (m *Manager) TenantAPIKeyHashes() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hashes := make(map[string]string, len(m.tenants))
	for id, tenant := range m.tenants {
		if tenant != nil && tenant.APIKeyHash != "" {
			hashes[id] = tenant.APIKeyHash
		}
	}
	return hashes
}

// CheckQuota checks if a tenant has exceeded their quota.
func (m *Manager) CheckQuota(tenant *Tenant) error {
	if tenant == nil {
		return nil
	}

	tenant.mu.RLock()
	defer tenant.mu.RUnlock()

	// Check if tenant is active
	if !tenant.Active {
		return fmt.Errorf("tenant is not active")
	}

	// Check requests per minute using sliding window
	if tenant.Quota.MaxRequestsPerMinute > 0 {
		if !m.rateLimiter.Check(tenant.ID, tenant.Quota.MaxRequestsPerMinute) {
			return fmt.Errorf("rate limit exceeded: %d requests per minute", tenant.Quota.MaxRequestsPerMinute)
		}
	}

	// Check requests per hour using sliding window. The > 0 guard is required:
	// TenantRateLimiter.Check treats limit <= 0 as its internal default, but a
	// zero hourly quota means unlimited.
	if tenant.Quota.MaxRequestsPerHour > 0 {
		if !m.hourLimiter.Check(tenant.ID, tenant.Quota.MaxRequestsPerHour) {
			return fmt.Errorf("rate limit exceeded: %d requests per hour", tenant.Quota.MaxRequestsPerHour)
		}
	}

	return nil
}

// RecordUsage records request usage for a tenant.
func (m *Manager) RecordUsage(tenant *Tenant, bytes int64) {
	if tenant == nil {
		return
	}

	tenant.mu.Lock()
	tenant.RequestCount++
	tenant.ByteCount += bytes
	tenant.LastRequestAt = time.Now()
	tenant.mu.Unlock()

	// Record in rate limiter for sliding window tracking
	m.rateLimiter.Record(tenant.ID)
	m.hourLimiter.Record(tenant.ID)

	// Check quota alerts
	if m.alertManager != nil {
		currentRPM := m.rateLimiter.Count(tenant.ID)
		m.alertManager.CheckQuotaAlert(tenant, currentRPM)
	}
}

// CleanupRateLimiter cleans up old rate limiter entries.
func (m *Manager) CleanupRateLimiter(maxAge time.Duration) {
	if m == nil {
		return
	}
	if m.rateLimiter != nil {
		m.rateLimiter.Cleanup(maxAge)
	}
	if m.hourLimiter != nil {
		m.hourLimiter.Cleanup(maxAge)
	}

	// Cleanup alerts too
	if m.alertManager != nil {
		m.alertManager.Cleanup(maxAge * 2)
	}
}

// RecordBlocked records a blocked request for a tenant.
func (m *Manager) RecordBlocked(tenant *Tenant) {
	if tenant == nil {
		return
	}

	tenant.mu.Lock()
	tenant.BlockedCount++
	tenant.mu.Unlock()
}

// AlertManager returns the alert manager.
func (m *Manager) AlertManager() *AlertManager {
	return m.alertManager
}

// TenantUpdate contains fields that can be updated.
type TenantUpdate struct {
	Name        string
	Description string
	Active      *bool
	Domains     []string
	Quota       *ResourceQuota
	Config      *config.Config
}

// GetTenantUsage returns real-time usage for a specific tenant.
func (m *Manager) GetTenantUsage(tenantID string) *UsageStats {
	tenant := m.GetTenant(tenantID)
	if tenant == nil {
		return nil
	}

	// Get current rate limiter counts
	var requestsPerMinute int64
	if m.rateLimiter != nil {
		requestsPerMinute = m.rateLimiter.Count(tenantID)
	}
	var requestsPerHour int64
	if m.hourLimiter != nil {
		requestsPerHour = m.hourLimiter.Count(tenantID)
	}

	tenant.mu.RLock()
	stats := &UsageStats{
		TenantID:          tenantID,
		Name:              tenant.Name,
		Active:            tenant.Active,
		RequestsPerMinute: requestsPerMinute,
		RequestsPerHour:   requestsPerHour,
		TotalRequests:     tenant.RequestCount,
		BlockedRequests:   tenant.BlockedCount,
		BytesTransferred:  tenant.ByteCount,
		LastRequestAt:     tenant.LastRequestAt,
	}

	// Calculate bandwidth (simplified)
	if !tenant.LastRequestAt.IsZero() {
		duration := time.Since(tenant.CreatedAt).Seconds()
		if duration > 0 {
			stats.BandwidthMbps = float64(tenant.ByteCount*8) / duration / 1000000
		}
	}

	// Calculate quota status
	if tenant.Quota.MaxRequestsPerMinute > 0 {
		stats.QuotaPercentage = float64(requestsPerMinute) / float64(tenant.Quota.MaxRequestsPerMinute) * 100
		if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute {
			stats.QuotaStatus = "exceeded"
		} else if requestsPerMinute >= tenant.Quota.MaxRequestsPerMinute*80/100 {
			stats.QuotaStatus = "warning"
		} else {
			stats.QuotaStatus = "ok"
		}
	} else {
		stats.QuotaStatus = "unlimited"
	}
	tenant.mu.RUnlock()

	return stats
}

// GetAllUsage returns usage for all tenants.
func (m *Manager) GetAllUsage() []*UsageStats {
	tenants := m.ListTenants()
	usageStats := make([]*UsageStats, 0, len(tenants))

	for _, tenant := range tenants {
		stats := m.GetTenantUsage(tenant.ID)
		if stats != nil {
			usageStats = append(usageStats, stats)
		}
	}

	return usageStats
}

// Stats returns manager statistics.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return ManagerStats{
		TenantCount:     len(m.tenants),
		DomainCount:     len(m.domains),
		DefaultTenantID: m.defaultTenantID,
		MaxTenants:      m.maxTenants,
	}
}

// ManagerStats contains manager statistics.
type ManagerStats struct {
	TenantCount     int    `json:"tenant_count"`
	DomainCount     int    `json:"domain_count"`
	DefaultTenantID string `json:"default_tenant_id"`
	MaxTenants      int    `json:"max_tenants"`
}

// Helper functions

// domainKey normalizes a domain for the tenant domain index. DNS names are
// case-insensitive, so index keys and lookups are lowercased; tenant.Domains
// keeps the operator's original spelling for display and the API.
func domainKey(domain string) string {
	return strings.ToLower(domain)
}

// normalizeDomain canonicalizes an operator-provided domain at the tenant
// domain index-write seams. Resolution strips the port from Host
// (netutil.StripPort) and Host headers cannot carry whitespace, so a stored
// domain containing either could never match a request. Trimming and
// port-stripping are semantic corrections; case is preserved for display
// (the index lowercases keys via domainKey).
func normalizeDomain(domain string) string {
	return netutil.StripPort(strings.TrimSpace(domain))
}

func generateTenantID(name string) (string, error) {
	b := make([]byte, 16) // 128-bit entropy for collision resistance at scale
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating tenant ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating API key: %w", err)
	}
	return "gwaf_" + hex.EncodeToString(b), nil
}

// PBKDF2 iteration counts for API key hashing.
const (
	// apiKeyHashIterationsLegacy is the v2 iteration count (100K). Kept for
	// backward-compatible verification of existing hashes.
	apiKeyHashIterationsLegacy = 100000
)

// apiKeyHashIterations is the iteration count for new hashes (600K), matching
// OWASP 2023+ guidance for PBKDF2-HMAC-SHA256. It is a variable only so the
// package tests can lower it: v3 hashes record their own iteration count, so
// verification behaves identically at any value.
var apiKeyHashIterations = 600000

// hashAPIKey hashes an API key using PBKDF2-HMAC-SHA256 (via crypto/pbkdf2)
// with a random salt. Returns "v3$iterations$salt$hash" format. The v3
// prefix and embedded iteration count make the hash self-describing so
// future iteration increases need no format change.
func hashAPIKey(apiKey string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	derived := deriveKey([]byte(apiKey), salt, apiKeyHashIterations)
	return "v3$" + strconv.Itoa(apiKeyHashIterations) + "$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(derived), nil
}

// deriveKey performs standard PBKDF2-HMAC-SHA256 key derivation using
// crypto/pbkdf2 (Go 1.24+). Output is byte-identical to the previous
// hand-rolled implementation for the same inputs.
func deriveKey(password, salt []byte, iterations int) []byte {
	derived, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, sha256.Size)
	if err != nil {
		// pbkdf2.Key only errors on keyLen < 1, which cannot happen here.
		panic(fmt.Sprintf("pbkdf2.Key failed unexpectedly: %v", err))
	}
	return derived
}

// verifyAPIKey checks if an API key matches a stored hash.
// Supports v3 (self-describing iterations), v2 (100K iterated HMAC), v1 (salted SHA256),
// and legacy (unsalted SHA256).
// Returns (matched, legacy) where legacy is true if the hash should be rehashed.
func verifyAPIKey(storedHash, apiKey string) (matched bool, legacy bool) {
	parts := strings.Split(storedHash, "$")

	// v3 format: v3$iterations$salt$hash (self-describing iteration count)
	if len(parts) == 4 && parts[0] == "v3" {
		iterations, err := strconv.Atoi(parts[1])
		if err != nil || iterations < 1 {
			return false, false
		}
		salt, err := hex.DecodeString(parts[2])
		if err != nil {
			return false, false
		}
		expected, err := hex.DecodeString(parts[3])
		if err != nil {
			return false, false
		}
		derived := deriveKey([]byte(apiKey), salt, iterations)
		if subtle.ConstantTimeCompare(derived, expected) == 1 {
			return true, false
		}
		return false, false
	}

	// v2 format: v2$salt$hash (100K iterations — upgrade to v3)
	if len(parts) == 3 && parts[0] == "v2" {
		salt, err := hex.DecodeString(parts[1])
		if err != nil {
			return false, false
		}
		expected, err := hex.DecodeString(parts[2])
		if err != nil {
			return false, false
		}
		derived := deriveKey([]byte(apiKey), salt, apiKeyHashIterationsLegacy)
		if subtle.ConstantTimeCompare(derived, expected) == 1 {
			return true, true // upgrade to v3
		}
		return false, false
	}

	// v1 format: salt$hash (single-pass salted SHA256)
	if len(parts) == 2 {
		salt, err := hex.DecodeString(parts[0])
		if err != nil {
			return false, false
		}
		hash := sha256.Sum256(append(salt, []byte(apiKey)...))
		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(hex.EncodeToString(hash[:]))) == 1 {
			return true, true // matched but should rehash to v2
		}
		return false, false
	}

	// Legacy unsalted SHA256
	expected := sha256.Sum256([]byte(apiKey))
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hex.EncodeToString(expected[:]))) == 1 {
		return true, true // matched but should rehash to v2
	}
	return false, false
}

func matchWildcard(domain, pattern string) bool {
	// Simple wildcard matching: *.example.com matches sub.example.com
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:] // Remove leading *
		return len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix
	}
	return domain == pattern
}

// RulesManager returns the tenant rules manager.
func (m *Manager) RulesManager() *TenantRulesManager {
	return m.rulesManager
}

// ClusterSync defines the interface for cluster synchronization.
type ClusterSync interface {
	BroadcastEvent(entityType, entityID, action string, data map[string]any) error
}

// SetClusterSync sets the cluster sync manager.
func (m *Manager) SetClusterSync(cs ClusterSync) {
	m.clusterSyncMu.Lock()
	m.clusterSync = cs
	m.clusterSyncMu.Unlock()
}

// broadcast sends an event to the cluster if cluster sync is enabled.
func (m *Manager) broadcast(entityType, entityID, action string, data map[string]any) {
	m.clusterSyncMu.RLock()
	cs := m.clusterSync
	m.clusterSyncMu.RUnlock()
	if cs == nil {
		return
	}
	m.broadcastMu.Lock()
	if m.broadcastClosed {
		m.broadcastMu.Unlock()
		return
	}
	select {
	case m.broadcastSem <- struct{}{}:
		m.broadcastWG.Add(1)
		m.broadcastMu.Unlock()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					m.log.Warn("broadcast goroutine panic", "panic", r)
				}
			}()
			defer m.broadcastWG.Done()
			defer func() { <-m.broadcastSem }()
			if err := cs.BroadcastEvent(entityType, entityID, action, data); err != nil {
				m.log.Warn("failed to broadcast event", "err", err)
			}
		}()
	default:
		m.broadcastMu.Unlock()
		m.log.Warn("broadcast semaphore full, dropping event", "entityType", entityType, "action", action)
	}
}

func waitForTenantBroadcast(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DeleteTenant deletes a tenant and cleans up all associated resources.
func (m *Manager) DeleteTenantWithCleanup(id string) error {
	// Delete tenant rules
	if m.rulesManager != nil {
		m.rulesManager.DeleteTenantRules(id)
	}

	// Delete tenant
	return m.DeleteTenant(id)
}

// GetTenantRules returns all rules for a tenant.
func (m *Manager) GetTenantRules(tenantID string) []any {
	if m.rulesManager == nil {
		return nil
	}
	rules := m.rulesManager.GetTenantRules(tenantID)
	result := make([]any, len(rules))
	for i, r := range rules {
		result[i] = r
	}
	return result
}

// AddTenantRule adds a rule to a tenant.
func (m *Manager) AddTenantRule(tenantID string, rule map[string]any) error {
	if m.rulesManager == nil {
		return fmt.Errorf("rules manager not enabled")
	}

	// Get tenant to check quota
	tenant := m.GetTenant(tenantID)
	if tenant == nil {
		return fmt.Errorf("tenant not found")
	}

	// Convert map to Rule
	name, _ := rule["name"].(string)
	if name == "" {
		return fmt.Errorf("rule name is required")
	}
	ruleID, err := generateTenantID(name)
	if err != nil {
		return err
	}
	r := rules.Rule{
		ID:      ruleID,
		Enabled: true,
	}
	if v, ok := rule["name"].(string); ok {
		r.Name = v
	}
	if v, ok := rule["priority"].(float64); ok {
		r.Priority = int(v)
	}
	if v, ok := rule["action"].(string); ok {
		r.Action = v
	}
	if v, ok := rule["score"].(float64); ok {
		r.Score = int(v)
	}
	if conds, ok := rule["conditions"].([]any); ok {
		for _, c := range conds {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			cond := rules.Condition{
				Field: "",
				Op:    "equals",
			}
			if v, ok := cm["field"].(string); ok {
				cond.Field = v
			}
			if v, ok := cm["op"].(string); ok {
				cond.Op = v
			}
			cond.Value = cm["value"]
			r.Conditions = append(r.Conditions, cond)
		}
	}

	return m.rulesManager.AddTenantRule(tenantID, r, tenant.Quota.MaxRules)
}

// GetTenantRule returns a specific rule for a tenant.
func (m *Manager) GetTenantRule(tenantID, ruleID string) any {
	if m.rulesManager == nil {
		return nil
	}
	// rulesManager.GetTenantRule returns a *rules.Rule; a missing rule yields a
	// nil pointer. Return an untyped nil so callers' `rule == nil` checks succeed
	// (otherwise the typed nil wrapped in `any` is non-nil and a missing rule
	// would 200-with-null instead of 404).
	rule := m.rulesManager.GetTenantRule(tenantID, ruleID)
	if rule == nil {
		return nil
	}
	return rule
}

// UpdateTenantRule updates a rule for a tenant.
func (m *Manager) UpdateTenantRule(tenantID string, rule map[string]any) error {
	if m.rulesManager == nil {
		return fmt.Errorf("rules manager not enabled")
	}

	// Get rule ID
	ruleID, ok := rule["id"].(string)
	if !ok || ruleID == "" {
		return fmt.Errorf("rule id is required")
	}

	// Get existing rule and update. Partial-update semantics: fields absent
	// from the update map keep their current values — rules.Layer.UpdateRule
	// replaces the stored rule wholesale, so building the rule from scratch
	// here would wipe Enabled/Conditions/Action on every partial update.
	existing := m.rulesManager.GetTenantRule(tenantID, ruleID)
	if existing == nil {
		return fmt.Errorf("rule not found")
	}
	r := *existing
	if v, ok := rule["name"].(string); ok {
		r.Name = v
	}
	if v, ok := rule["enabled"].(bool); ok {
		r.Enabled = v
	}
	if v, ok := rule["priority"].(float64); ok {
		r.Priority = int(v)
	}
	if v, ok := rule["action"].(string); ok {
		r.Action = v
	}
	if v, ok := rule["score"].(float64); ok {
		r.Score = int(v)
	}
	if conds, ok := rule["conditions"].([]any); ok {
		// A provided conditions array REPLACES the existing one; without the
		// reset the merge above would append onto the copied slice header.
		r.Conditions = nil
		for _, c := range conds {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			cond := rules.Condition{
				Field: "",
				Op:    "equals",
			}
			if v, ok := cm["field"].(string); ok {
				cond.Field = v
			}
			if v, ok := cm["op"].(string); ok {
				cond.Op = v
			}
			cond.Value = cm["value"]
			r.Conditions = append(r.Conditions, cond)
		}
	}

	if !m.rulesManager.UpdateTenantRule(tenantID, r) {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// RemoveTenantRule removes a rule from a tenant.
func (m *Manager) RemoveTenantRule(tenantID, ruleID string) error {
	if m.rulesManager == nil {
		return fmt.Errorf("rules manager not enabled")
	}
	if !m.rulesManager.RemoveTenantRule(tenantID, ruleID) {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// ToggleTenantRule enables/disables a rule for a tenant.
func (m *Manager) ToggleTenantRule(tenantID, ruleID string, enabled bool) error {
	if m.rulesManager == nil {
		return fmt.Errorf("rules manager not enabled")
	}
	if !m.rulesManager.ToggleTenantRule(tenantID, ruleID, enabled) {
		return fmt.Errorf("rule not found")
	}
	return nil
}
