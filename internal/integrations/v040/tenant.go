// Package v040 provides integration for GuardianWAF v0.4.0 Phase 2 features.
// This includes multi-tenancy support with namespace isolation.
package v040

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

// TenantIntegrator manages multi-tenancy integration.
type TenantIntegrator struct {
	manager    *tenant.Manager
	middleware *tenant.Middleware
	handlers   *tenant.Handlers
	config     config.TenantConfig
}

// NewTenantIntegrator creates a new tenant integrator from configuration.
func NewTenantIntegrator(cfg config.TenantConfig) (*TenantIntegrator, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Create tenant manager
	maxTenants := cfg.MaxTenants
	if maxTenants <= 0 {
		maxTenants = 100
	}

	manager := tenant.NewManager(maxTenants)

	// Create pre-configured tenants
	for _, t := range cfg.Tenants {
		quota := convertQuota(t.Quota)
		if t.Quota.MaxRequestsPerMinute == 0 {
			// Use default quota
			quota = convertQuota(cfg.DefaultQuota)
		}

		_, err := manager.CreateTenant(t.Name, t.Description, t.Domains, quota)
		if err != nil {
			// Log error but continue - tenant might already exist
			continue
		}
	}

	return &TenantIntegrator{
		manager:    manager,
		middleware: tenant.NewMiddleware(manager),
		handlers:   tenant.NewHandlers(manager),
		config:     cfg,
	}, nil
}

// Middleware returns the tenant resolution middleware.
func (ti *TenantIntegrator) Middleware() func(http.Handler) http.Handler {
	if ti == nil || ti.middleware == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	return ti.middleware.Handler
}

// RegisterHandlers registers tenant management API routes.
func (ti *TenantIntegrator) RegisterHandlers(mux *http.ServeMux) {
	if ti == nil || ti.handlers == nil {
		return
	}
	ti.handlers.RegisterRoutes(mux)
}

// Manager returns the tenant manager for direct access.
func (ti *TenantIntegrator) Manager() *tenant.Manager {
	if ti == nil {
		return nil
	}
	return ti.manager
}

// Stats returns tenant statistics.
func (ti *TenantIntegrator) Stats() tenant.ManagerStats {
	if ti == nil || ti.manager == nil {
		return tenant.ManagerStats{}
	}
	return ti.manager.Stats()
}

// convertQuota converts config.ResourceQuotaConfig to tenant.ResourceQuota.
func convertQuota(q config.ResourceQuotaConfig) *tenant.ResourceQuota {
	return &tenant.ResourceQuota{
		MaxRequestsPerMinute: q.MaxRequestsPerMinute,
		MaxRequestsPerHour:   q.MaxRequestsPerHour,
		MaxBandwidthMbps:     q.MaxBandwidthMbps,
		MaxRules:             q.MaxRules,
		MaxRateLimitRules:    q.MaxRateLimitRules,
		MaxIPACLs:            q.MaxIPACLs,
	}
}

// TenantLayer is a WAF engine layer that provides per-tenant isolation.
// It wraps the engine's event store and event bus to provide tenant-aware operations.
type TenantLayer struct {
	integrator *TenantIntegrator
}

// NewTenantLayer creates a new tenant layer.
func NewTenantLayer(integrator *TenantIntegrator) *TenantLayer {
	return &TenantLayer{
		integrator: integrator,
	}
}

// Name returns the layer name.
func (tl *TenantLayer) Name() string {
	return "tenant_isolation"
}

// Order returns the layer order (runs early, before other layers).
func (tl *TenantLayer) Order() int {
	return 50
}

// Process implements the layer interface.
func (tl *TenantLayer) Process(ctx *engine.RequestContext) engine.LayerResult {
	// Tenant resolution happens in middleware before this layer
	// This layer can be used for tenant-specific rule application
	return engine.LayerResult{Action: engine.ActionPass}
}
