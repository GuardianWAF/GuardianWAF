package main

import (
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

const (
	defaultTenantMaxTenants = 100
	defaultTenantStorePath  = "data/tenants"
)

func setupTenantRuntime(
	cfg *config.Config,
	eng *engine.Engine,
	dash *dashboard.Dashboard,
	upstreamHandler *atomic.Value,
	tenantMWPtr *atomic.Pointer[tenant.Middleware],
) (*tenant.Manager, *tenant.Middleware) {
	if cfg == nil || eng == nil || !cfg.Tenant.Enabled {
		return nil, nil
	}

	tenantManager := tenant.NewManagerWithStore(
		tenantMaxTenants(cfg.Tenant.MaxTenants),
		tenantStorePath(cfg.Tenant.StorePath),
	)
	if err := tenantManager.Init(); err != nil {
		eng.Logs.Warnf("Failed to load persisted tenants: %v", err)
	} else {
		eng.Logs.Infof("Loaded %d tenants from persistence", len(tenantManager.ListTenants()))
	}

	for _, t := range cfg.Tenant.Tenants {
		_, _ = tenantManager.CreateTenant(t.Name, t.Description, t.Domains, tenantResourceQuota(t.Quota)) // nolint:errcheck // error already logged by tenant manager
	}

	if dash != nil {
		dash.SetTenantManager(&tenantManagerAdapter{mgr: tenantManager})
	}

	tenantMiddleware := tenant.NewMiddleware(tenantManager)
	if originalHandler := loadHTTPHandler(upstreamHandler); originalHandler != nil {
		upstreamHandler.Store(tenantMiddleware.Handler(originalHandler))
	}
	// Publish the middleware so proxy-rebuild paths (dashboard/Docker) can
	// re-apply the tenant wrap instead of dropping tenant isolation.
	if tenantMWPtr != nil {
		tenantMWPtr.Store(tenantMiddleware)
	}

	eng.Logs.Infof("Multi-tenant mode enabled (%d tenants configured)", len(cfg.Tenant.Tenants))
	return tenantManager, tenantMiddleware
}

func tenantMaxTenants(value int) int {
	if value <= 0 {
		return defaultTenantMaxTenants
	}
	return value
}

func tenantStorePath(value string) string {
	if value == "" {
		return defaultTenantStorePath
	}
	return value
}

func tenantResourceQuota(quota config.ResourceQuotaConfig) *tenant.ResourceQuota {
	return &tenant.ResourceQuota{
		MaxRequestsPerMinute: quota.MaxRequestsPerMinute,
		MaxRequestsPerHour:   quota.MaxRequestsPerHour,
		MaxBandwidthMbps:     quota.MaxBandwidthMbps,
		MaxRules:             quota.MaxRules,
		MaxRateLimitRules:    quota.MaxRateLimitRules,
		MaxIPACLs:            quota.MaxIPACLs,
	}
}
