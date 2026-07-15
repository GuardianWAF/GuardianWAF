package dashboard

import "net/http/pprof"

// registerRoutes registers all HTTP routes on the dashboard mux.
// Routes are grouped by function: login, health, API v1, admin, debug.
func (d *Dashboard) registerRoutes() {
	// Login/logout (always accessible)
	d.mux.HandleFunc("GET /login", d.handleLoginPage)
	d.mux.HandleFunc("POST /login", d.handleLoginSubmit)
	d.mux.HandleFunc("POST /logout", d.handleLogout)
	d.mux.HandleFunc("POST /api/v1/rotate-key", d.authWrap(d.handleRotateKey))

	// Health check (always accessible, no sensitive data)
	d.mux.HandleFunc("GET /health", d.handleHealth)
	d.mux.HandleFunc("GET /healthz", d.handleHealth)
	d.mux.HandleFunc("GET /livez", d.handleHealth)
	d.mux.HandleFunc("GET /readyz", d.handleHealth)
	d.mux.HandleFunc("GET /api/v1/health", d.handleHealth)
	d.mux.HandleFunc("GET /api/v1/version", d.handleVersion)

	// Domain-based API v1 route groups
	d.registerStats(d.mux)
	d.registerConfig(d.mux)
	d.registerRouting(d.mux)
	d.registerACL(d.mux)
	d.registerRules(d.mux)
	d.registerAI(d.mux)
	d.registerAlerting(d.mux)
	d.registerDocker(d.mux)
	d.registerCompliance(d.mux)
	d.registerAnalytics(d.mux)
	d.registerCluster(d.mux)
	d.registerTenantCompatibility(d.mux)

	// Tenant admin handler
	d.tenantAdminHandler = NewTenantAdminHandler(d, nil)
	d.tenantAdminHandler.RegisterRoutes(d.mux)

	// Per-layer management APIs
	NewCRSHandler(d).RegisterRoutes(d.mux)
	NewDLPHandler(d).RegisterRoutes(d.mux)
	NewClientSideHandler(d).RegisterRoutes(d.mux)
	NewAPIValidationHandler(d).RegisterRoutes(d.mux)
	NewVirtualPatchHandler(d).RegisterRoutes(d.mux)

	// SPA static file serving
	d.registerSPA(d.mux)

	// Debug pprof endpoints — localhost-only, sensitive runtime data
	d.mux.HandleFunc("GET /debug/pprof/", d.pprofWrap(pprof.Index))
	d.mux.HandleFunc("GET /debug/pprof/cmdline", d.pprofWrap(pprof.Cmdline))
	d.mux.HandleFunc("GET /debug/pprof/profile", d.pprofWrap(pprof.Profile))
	d.mux.HandleFunc("GET /debug/pprof/symbol", d.pprofWrap(pprof.Symbol))
	d.mux.HandleFunc("GET /debug/pprof/trace", d.pprofWrap(pprof.Trace))
}
