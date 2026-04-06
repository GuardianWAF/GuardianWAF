package tenant

import (
	"errors"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

// ErrQuotaExceeded is returned when a tenant exceeds their rule quota.
var ErrQuotaExceeded = errors.New("rule quota exceeded for tenant")

// TenantRulesManager manages per-tenant rule sets.
type TenantRulesManager struct {
	mu       sync.RWMutex
	ruleSets map[string]*rules.Layer // key: tenant ID
	maxRules int                     // default max rules per tenant
}

// NewTenantRulesManager creates a new tenant rules manager.
func NewTenantRulesManager(maxRulesPerTenant int) *TenantRulesManager {
	if maxRulesPerTenant <= 0 {
		maxRulesPerTenant = 100
	}
	return &TenantRulesManager{
		ruleSets: make(map[string]*rules.Layer),
		maxRules: maxRulesPerTenant,
	}
}

// GetRulesLayer returns the rules layer for a tenant, creating if necessary.
func (trm *TenantRulesManager) GetRulesLayer(tenantID string, maxRules int) *rules.Layer {
	trm.mu.RLock()
	layer, exists := trm.ruleSets[tenantID]
	trm.mu.RUnlock()

	if exists {
		return layer
	}

	// Create new rules layer for tenant
	trm.mu.Lock()
	defer trm.mu.Unlock()

	// Double-check after locking
	if layer, exists = trm.ruleSets[tenantID]; exists {
		return layer
	}

	if maxRules <= 0 {
		maxRules = trm.maxRules
	}

	// Create isolated rules layer
	cfg := &rules.Config{
		Enabled: true,
		Rules:   make([]rules.Rule, 0, maxRules),
	}

	layer = rules.NewLayer(cfg, nil)
	trm.ruleSets[tenantID] = layer

	return layer
}

// GetTenantRules returns all rules for a tenant.
func (trm *TenantRulesManager) GetTenantRules(tenantID string) []rules.Rule {
	trm.mu.RLock()
	defer trm.mu.RUnlock()

	layer, exists := trm.ruleSets[tenantID]
	if !exists {
		return nil
	}

	return layer.Rules()
}

// GetTenantRule returns a specific rule for a tenant.
func (trm *TenantRulesManager) GetTenantRule(tenantID, ruleID string) *rules.Rule {
	trm.mu.RLock()
	defer trm.mu.RUnlock()

	layer, exists := trm.ruleSets[tenantID]
	if !exists {
		return nil
	}

	for _, rule := range layer.Rules() {
		if rule.ID == ruleID {
			return &rule
		}
	}
	return nil
}

// AddTenantRule adds a rule to a tenant's rule set.
func (trm *TenantRulesManager) AddTenantRule(tenantID string, rule rules.Rule, maxRules int) error {
	// Check quota
	currentRules := trm.GetTenantRules(tenantID)
	if len(currentRules) >= maxRules && maxRules > 0 {
		return ErrQuotaExceeded
	}

	layer := trm.GetRulesLayer(tenantID, maxRules)

	// Add rule through layer
	layer.AddRule(rule)
	return nil
}

// UpdateTenantRule updates a rule for a tenant.
func (trm *TenantRulesManager) UpdateTenantRule(tenantID string, rule rules.Rule) bool {
	trm.mu.RLock()
	layer, exists := trm.ruleSets[tenantID]
	trm.mu.RUnlock()

	if !exists {
		return false
	}

	return layer.UpdateRule(rule)
}

// RemoveTenantRule removes a rule from a tenant.
func (trm *TenantRulesManager) RemoveTenantRule(tenantID, ruleID string) bool {
	trm.mu.RLock()
	layer, exists := trm.ruleSets[tenantID]
	trm.mu.RUnlock()

	if !exists {
		return false
	}

	return layer.RemoveRule(ruleID)
}

// ToggleTenantRule enables/disables a tenant rule.
func (trm *TenantRulesManager) ToggleTenantRule(tenantID, ruleID string, enabled bool) bool {
	trm.mu.RLock()
	layer, exists := trm.ruleSets[tenantID]
	trm.mu.RUnlock()

	if !exists {
		return false
	}

	return layer.ToggleRule(ruleID, enabled)
}

// DeleteTenantRules removes all rules for a tenant.
func (trm *TenantRulesManager) DeleteTenantRules(tenantID string) {
	trm.mu.Lock()
	defer trm.mu.Unlock()

	delete(trm.ruleSets, tenantID)
}

// GetRuleCount returns the number of rules for a tenant.
func (trm *TenantRulesManager) GetRuleCount(tenantID string) int {
	return len(trm.GetTenantRules(tenantID))
}

// CheckRuleQuota checks if a tenant can add more rules.
func (trm *TenantRulesManager) CheckRuleQuota(tenantID string, maxRules int) bool {
	if maxRules <= 0 {
		return true // Unlimited
	}
	return trm.GetRuleCount(tenantID) < maxRules
}
