package main

import (
	"fmt"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

// tenantManagerAdapter adapts *tenant.Manager to dashboard.tenantManagerInterface.
type tenantManagerAdapter struct {
	mgr *tenant.Manager
}

func (a *tenantManagerAdapter) ListTenants() []any {
	tenants := a.mgr.ListTenants()
	result := make([]any, len(tenants))
	for i, t := range tenants {
		result[i] = t
	}
	return result
}

func (a *tenantManagerAdapter) GetTenant(id string) any {
	// Return an untyped nil when the tenant is missing. a.mgr.GetTenant returns a
	// nil *tenant.Tenant for unknown IDs; returning it directly would wrap a typed
	// nil in the `any` result, so the handler's `tenant == nil` check would be
	// false and a missing tenant would 200-with-null instead of 404.
	t := a.mgr.GetTenant(id)
	if t == nil {
		return nil
	}
	return t
}

func (a *tenantManagerAdapter) CreateTenant(name, description string, domains []string, quota any) (any, error) {
	var tQuota *tenant.ResourceQuota
	if q, ok := quota.(*tenant.ResourceQuota); ok {
		tQuota = q
	} else if q, ok := quotaFromAny(quota); ok {
		tQuota = q
	}
	return a.mgr.CreateTenant(name, description, domains, tQuota)
}

func (a *tenantManagerAdapter) UpdateTenant(id string, update any) error {
	if u, ok := update.(*tenant.TenantUpdate); ok {
		return a.mgr.UpdateTenant(id, u)
	}
	if m, ok := update.(map[string]any); ok {
		tu := &tenant.TenantUpdate{}
		if v, ok := m["name"].(string); ok {
			tu.Name = v
		}
		if v, ok := m["description"].(string); ok {
			tu.Description = v
		}
		if v, ok := stringSlice(m["domains"]); ok {
			tu.Domains = v
		}
		if v, ok := m["active"].(bool); ok {
			tu.Active = &v
		} else if v, ok := m["enabled"].(bool); ok {
			tu.Active = &v
		}
		if q, ok := quotaFromAny(m["quota"]); ok {
			tu.Quota = q
		}
		return a.mgr.UpdateTenant(id, tu)
	}
	return fmt.Errorf("unsupported update type")
}

func stringSlice(v any) ([]string, bool) {
	switch typed := v.(type) {
	case []string:
		return typed, true
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func quotaFromAny(v any) (*tenant.ResourceQuota, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	q := tenant.DefaultQuota()
	if value, ok := int64Field(m, "max_requests_per_minute"); ok {
		q.MaxRequestsPerMinute = value
	}
	if value, ok := int64Field(m, "max_requests_per_hour"); ok {
		q.MaxRequestsPerHour = value
	}
	if value, ok := intField(m, "max_bandwidth_mbps"); ok {
		q.MaxBandwidthMbps = value
	}
	if value, ok := intField(m, "max_rules"); ok {
		q.MaxRules = value
	}
	if value, ok := intField(m, "max_rate_limit_rules"); ok {
		q.MaxRateLimitRules = value
	}
	if value, ok := intField(m, "max_ip_acls"); ok {
		q.MaxIPACLs = value
	}
	return &q, true
}

func intField(m map[string]any, key string) (int, bool) {
	switch v := m[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}

func int64Field(m map[string]any, key string) (int64, bool) {
	if v, ok := intField(m, key); ok {
		return int64(v), true
	}
	return 0, false
}

func (a *tenantManagerAdapter) DeleteTenant(id string) error {
	return a.mgr.DeleteTenant(id)
}

func (a *tenantManagerAdapter) RegenerateAPIKey(id string) (string, error) {
	return a.mgr.RegenerateAPIKey(id)
}

func (a *tenantManagerAdapter) Stats() any {
	return a.mgr.Stats()
}

func (a *tenantManagerAdapter) BillingManager() dashboard.BillingManagerInterface {
	return &billingManagerAdapter{bm: a.mgr.BillingManager()}
}

func (a *tenantManagerAdapter) AlertManager() dashboard.AlertManagerInterface {
	return &alertManagerAdapter{am: a.mgr.AlertManager()}
}

func (a *tenantManagerAdapter) GetAllUsage() []any {
	usage := a.mgr.GetAllUsage()
	result := make([]any, len(usage))
	for i, u := range usage {
		result[i] = u
	}
	return result
}

func (a *tenantManagerAdapter) GetTenantUsage(tenantID string) any {
	// Normalize a missing tenant's nil *UsageStats to an untyped nil so handlers'
	// `usage == nil` checks succeed (avoids 200-with-null instead of 404).
	u := a.mgr.GetTenantUsage(tenantID)
	if u == nil {
		return nil
	}
	return u
}

func (a *tenantManagerAdapter) GetTenantRules(tenantID string) []any {
	return a.mgr.GetTenantRules(tenantID)
}

func (a *tenantManagerAdapter) AddTenantRule(tenantID string, rule map[string]any) error {
	return a.mgr.AddTenantRule(tenantID, rule)
}

func (a *tenantManagerAdapter) GetTenantRule(tenantID, ruleID string) any {
	return a.mgr.GetTenantRule(tenantID, ruleID)
}

func (a *tenantManagerAdapter) UpdateTenantRule(tenantID string, rule map[string]any) error {
	return a.mgr.UpdateTenantRule(tenantID, rule)
}

func (a *tenantManagerAdapter) RemoveTenantRule(tenantID, ruleID string) error {
	return a.mgr.RemoveTenantRule(tenantID, ruleID)
}

func (a *tenantManagerAdapter) ToggleTenantRule(tenantID, ruleID string, enabled bool) error {
	return a.mgr.ToggleTenantRule(tenantID, ruleID, enabled)
}

// billingManagerAdapter adapts tenant.BillingManager to dashboard interface.
type billingManagerAdapter struct {
	bm *tenant.BillingManager
}

func (a *billingManagerAdapter) GetAllInvoices() []any {
	if a.bm == nil {
		return nil
	}
	invoices := a.bm.GetAllInvoices()
	result := make([]any, len(invoices))
	for i, inv := range invoices {
		result[i] = inv
	}
	return result
}

func (a *billingManagerAdapter) GetInvoices(tenantID string) []any {
	if a.bm == nil {
		return nil
	}
	invoices := a.bm.GetInvoices(tenantID)
	result := make([]any, len(invoices))
	for i, inv := range invoices {
		result[i] = inv
	}
	return result
}

func (a *billingManagerAdapter) GetCurrentUsage(tenantID string) any {
	if a.bm == nil {
		return nil
	}
	return a.bm.GetCurrentUsage(tenantID)
}

func (a *billingManagerAdapter) GenerateInvoice(tenantID, tenantName string, plan string, periodStart, periodEnd time.Time) (any, error) {
	if a.bm == nil {
		return nil, fmt.Errorf("billing not enabled")
	}
	return a.bm.GenerateInvoice(tenantID, tenantName, tenant.BillingPlan(plan), periodStart, periodEnd)
}

// alertManagerAdapter adapts tenant.AlertManager to dashboard interface.
type alertManagerAdapter struct {
	am *tenant.AlertManager
}

func (a *alertManagerAdapter) GetRecentAlerts(since time.Duration) []any {
	if a.am == nil {
		return nil
	}
	alerts := a.am.GetRecentAlerts(since)
	result := make([]any, len(alerts))
	for i, alert := range alerts {
		result[i] = alert
	}
	return result
}
