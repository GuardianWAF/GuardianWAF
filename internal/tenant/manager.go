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

	// Tenant-specific rules
	rulesManager *TenantRulesManager

	// Billing
	billingManager *BillingManager

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
		tenants:        make(map[string]*Tenant),
		domains:        make(map[string]string),
		maxTenants:     maxTenants,
		rateLimiter:    NewTenantRateLimiter(time.Minute),
		rulesManager:   NewTenantRulesManager(100),
		billingManager: NewBillingManager(""),
		alertManager:   NewAlertManager(),
		store:          NewStore(storePath),
		broadcastSem:   make(chan struct{}, 16),
		log:            logging.NewLogger("tenant"),
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

// SaveTenant persists a tenant to storage.
func (m *Manager) SaveTenant(tenant *Tenant) error {
	if m.store == nil || tenant == nil {
		return nil
	}
	tenant.UpdatedAt = time.Now()
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

	// Check domain uniqueness
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

	// Persist tenant to storage
	if err := m.SaveTenant(tenant); err != nil {
		// Non-fatal: log but don't fail
		m.log.Warn("failed to persist tenant", "err", err)
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

	// Try wildcard match
	for d, tenantID := range m.domains {
		if matchWildcard(domain, d) {
			return m.tenants[tenantID]
		}
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

	cacheKey := fastKeyHash(apiKey)

	// Fast path: consult the memoized result and skip PBKDF2 entirely.
	m.apiKeyCacheMu.Lock()
	if m.apiKeyCache != nil {
		if tenantID, ok := m.apiKeyCache[cacheKey]; ok {
			m.apiKeyCacheMu.Unlock()
			if tenantID == "" {
				return nil // cached negative result
			}
			m.mu.RLock()
			tenant := m.tenants[tenantID]
			m.mu.RUnlock()
			if tenant != nil {
				return tenant
			}
			// Tenant vanished (deleted without a cache clear); fall through.
		}
	}
	m.apiKeyCacheMu.Unlock()

	// Slow path: verify against each tenant (expensive PBKDF2).
	m.mu.RLock()
	var found *Tenant
	for _, tenant := range m.tenants {
		if matched, legacy := verifyAPIKey(tenant.APIKeyHash, apiKey); matched {
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
	m.mu.RUnlock()

	m.cacheAPIKeyResult(cacheKey, found)
	return found
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

	if updates.Name != "" {
		tenant.Name = updates.Name
	}
	if updates.Description != "" {
		tenant.Description = updates.Description
	}
	if updates.Active != nil {
		tenant.Active = *updates.Active
	}
	if updates.Quota != nil {
		tenant.Quota = *updates.Quota
	}
	if updates.Config != nil {
		// Config update uses its own lock for fine-grained concurrency
		tenant.mu.Lock()
		tenant.Config = updates.Config
		tenant.mu.Unlock()
	}

	// Update domains — this is part of the same atomic operation under m.mu
	if len(updates.Domains) > 0 {
		// Check new domains before touching the index so a rejected update
		// cannot leave the mappings inconsistent with tenant.Domains.
		for _, domain := range updates.Domains {
			if existingID, exists := m.domains[domainKey(domain)]; exists && existingID != id {
				return fmt.Errorf("domain %s already assigned to tenant %s", domain, existingID)
			}
		}

		// Remove old domain mappings
		for _, oldDomain := range tenant.Domains {
			delete(m.domains, domainKey(oldDomain))
		}

		// Set new domains
		tenant.Domains = updates.Domains
		for _, domain := range updates.Domains {
			m.domains[domainKey(domain)] = id
		}
	}

	tenant.UpdatedAt = time.Now()

	// Persist updated tenant
	if err := m.SaveTenant(tenant); err != nil {
		// Non-fatal: log but don't fail
		m.log.Warn("failed to persist tenant update", "err", err)
	}

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

	// Delete from persistent storage
	if m.store != nil {
		if err := m.store.DeleteTenant(id); err != nil {
			// Non-fatal: log but don't fail
			m.log.Warn("failed to delete tenant from storage", "err", err)
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
	tenant.APIKeyHash = newHash
	tenant.UpdatedAt = time.Now()
	// The old key must stop resolving and the new one must resolve.
	m.invalidateAPIKeyCache()

	// Persist updated tenant
	if err := m.SaveTenant(tenant); err != nil {
		// Non-fatal: log but don't fail
		m.log.Warn("failed to persist API key update", "err", err)
	}

	return newKey, nil
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

	// Record for billing
	if m.billingManager != nil {
		m.billingManager.RecordUsage(tenant.ID, 1, bytes, 0)
	}

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

	// Record for billing (security value)
	if m.billingManager != nil {
		m.billingManager.RecordUsage(tenant.ID, 0, 0, 1)
	}
}

// BillingManager returns the billing manager.
func (m *Manager) BillingManager() *BillingManager {
	return m.billingManager
}

// AlertManager returns the alert manager.
func (m *Manager) AlertManager() *AlertManager {
	return m.alertManager
}

// SetBillingStorePath sets the storage path for billing data.
func (m *Manager) SetBillingStorePath(path string) {
	if m.billingManager != nil {
		// Note: This won't change the path for existing billing manager
		// Should be set before first use
		_ = path // unused - billing path is set at initialization
	}
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

	// Get current rate limiter count
	var requestsPerMinute int64
	if m.rateLimiter != nil {
		requestsPerMinute = m.rateLimiter.Count(tenantID)
	}

	tenant.mu.RLock()
	stats := &UsageStats{
		TenantID:          tenantID,
		Name:              tenant.Name,
		Active:            tenant.Active,
		RequestsPerMinute: requestsPerMinute,
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
	// apiKeyHashIterations is the current iteration count (600K), matching
	// OWASP 2023+ guidance for PBKDF2-HMAC-SHA256.
	apiKeyHashIterations = 600000
)

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

	// Get existing rule and update
	r := rules.Rule{ID: ruleID}
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
