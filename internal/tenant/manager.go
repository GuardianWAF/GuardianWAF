// Package tenant provides multi-tenancy support with namespace isolation.
// Each tenant has isolated configurations, rules, rate limits, and event storage.
package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
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
	mu          sync.RWMutex
	RequestCount   int64
	ByteCount      int64
	BlockedCount   int64
	LastRequestAt  time.Time
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

	// Global limits
	maxTenants int
}

// NewManager creates a new tenant manager.
func NewManager(maxTenants int) *Manager {
	return &Manager{
		tenants:   make(map[string]*Tenant),
		domains:   make(map[string]string),
		maxTenants: maxTenants,
	}
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
	id := generateTenantID(name)

	// Check if tenant exists
	if _, exists := m.tenants[id]; exists {
		return nil, fmt.Errorf("tenant with ID %s already exists", id)
	}

	// Check domain uniqueness
	for _, domain := range domains {
		if existingID, exists := m.domains[domain]; exists {
			return nil, fmt.Errorf("domain %s already assigned to tenant %s", domain, existingID)
		}
	}

	// Generate API key
	apiKey := generateAPIKey()
	apiKeyHash := hashAPIKey(apiKey)

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

	// Register domains
	for _, domain := range domains {
		m.domains[domain] = id
	}

	// Set as default if first tenant
	if len(m.tenants) == 1 {
		m.defaultTenantID = id
	}

	return tenant, nil
}

// GetTenant returns a tenant by ID.
func (m *Manager) GetTenant(id string) *Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenants[id]
}

// GetTenantByDomain returns the tenant for a given domain.
func (m *Manager) GetTenantByDomain(domain string) *Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

// GetTenantByAPIKey returns the tenant for a given API key.
func (m *Manager) GetTenantByAPIKey(apiKey string) *Tenant {
	if apiKey == "" {
		return nil
	}

	hash := hashAPIKey(apiKey)

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, tenant := range m.tenants {
		if tenant.APIKeyHash == hash {
			return tenant
		}
	}

	return nil
}

// ResolveTenant determines the tenant for an incoming request.
// Priority: API Key header > Domain > Default tenant
func (m *Manager) ResolveTenant(r *http.Request) *Tenant {
	// 1. Try API key
	apiKey := r.Header.Get("X-GuardianWAF-Tenant-Key")
	if apiKey != "" {
		if tenant := m.GetTenantByAPIKey(apiKey); tenant != nil {
			return tenant
		}
	}

	// 2. Try domain
	domain := r.Host
	if domain != "" {
		if tenant := m.GetTenantByDomain(domain); tenant != nil {
			return tenant
		}
	}

	// 3. Return default tenant
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tenants[m.defaultTenantID]
}

// UpdateTenant updates a tenant's configuration.
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
		tenant.Config = updates.Config
	}

	// Update domains
	if len(updates.Domains) > 0 {
		// Remove old domain mappings
		for _, oldDomain := range tenant.Domains {
			delete(m.domains, oldDomain)
		}

		// Check new domains
		for _, domain := range updates.Domains {
			if existingID, exists := m.domains[domain]; exists && existingID != id {
				return fmt.Errorf("domain %s already assigned to tenant %s", domain, existingID)
			}
		}

		// Set new domains
		tenant.Domains = updates.Domains
		for _, domain := range updates.Domains {
			m.domains[domain] = id
		}
	}

	tenant.UpdatedAt = time.Now()
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
		delete(m.domains, domain)
	}

	delete(m.tenants, id)

	// Update default tenant if needed
	if m.defaultTenantID == id {
		m.defaultTenantID = ""
		for tid := range m.tenants {
			m.defaultTenantID = tid
			break
		}
	}

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

	newKey := generateAPIKey()
	tenant.APIKeyHash = hashAPIKey(newKey)
	tenant.UpdatedAt = time.Now()

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

	// Check requests per minute
	if tenant.Quota.MaxRequestsPerMinute > 0 {
		// In a real implementation, track per-minute windows
		if tenant.RequestCount > tenant.Quota.MaxRequestsPerMinute {
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
	defer tenant.mu.Unlock()

	tenant.RequestCount++
	tenant.ByteCount += bytes
	tenant.LastRequestAt = time.Now()
}

// RecordBlocked records a blocked request for a tenant.
func (m *Manager) RecordBlocked(tenant *Tenant) {
	if tenant == nil {
		return
	}

	tenant.mu.Lock()
	defer tenant.mu.Unlock()

	tenant.BlockedCount++
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

func generateTenantID(name string) string {
	// Generate ID from name + timestamp
	hash := sha256.Sum256([]byte(name + time.Now().String()))
	return hex.EncodeToString(hash[:8])
}

func generateAPIKey() string {
	// Generate random API key
	hash := sha256.Sum256([]byte(time.Now().String() + "apikey"))
	return "gwaf_" + hex.EncodeToString(hash[:16])
}

func hashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(hash[:])
}

func matchWildcard(domain, pattern string) bool {
	// Simple wildcard matching: *.example.com matches sub.example.com
	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:] // Remove leading *
		return len(domain) > len(suffix) && domain[len(domain)-len(suffix):] == suffix
	}
	return domain == pattern
}
