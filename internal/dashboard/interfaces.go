package dashboard

import "github.com/guardianwaf/guardianwaf/internal/config"

// RoutingControllerFuncs is a struct-of-funcs that implements RoutingController.
// This is the preferred wiring method for cmd/guardianwaf code.
type RoutingControllerFuncs struct {
	RebuildFn func() error
	SaveFn    func() error
}

// AtomicRoutingController prepares and commits a complete routing update. The
// implementation must leave the old engine config and proxy active on error.
type AtomicRoutingController interface {
	RoutingController
	Apply(oldCfg, newCfg *config.Config) error
}

// AtomicRoutingControllerFuncs wires an atomic apply function while retaining
// the rebuild/save operations used by the general config endpoints.
type AtomicRoutingControllerFuncs struct {
	RoutingControllerFuncs
	ApplyFn func(oldCfg, newCfg *config.Config) error
}

func (r AtomicRoutingControllerFuncs) Apply(oldCfg, newCfg *config.Config) error {
	return r.ApplyFn(oldCfg, newCfg)
}

func (r RoutingControllerFuncs) Rebuild() error { return r.RebuildFn() }
func (r RoutingControllerFuncs) Save() error    { return r.SaveFn() }

// RoutingController manages routing configuration and proxy rebuild lifecycle.
type RoutingController interface {
	// Rebuild recreates the proxy after a routing configuration change.
	Rebuild() error
	// Save persists the current routing configuration to disk.
	Save() error
}

// UpstreamStatusProvider returns the health status of all upstreams.
type UpstreamStatusProvider interface {
	// GetUpstreamStatus returns upstream health information for the dashboard.
	GetUpstreamStatus() any
}

// CertificateProvider returns SSL/TLS certificate status information.
type CertificateProvider interface {
	// GetCertificateStatus returns certificate status for the dashboard.
	GetCertificateStatus() any
}

// AlertingStatsProvider returns alerting subsystem statistics.
type AlertingStatsProvider interface {
	// GetAlertingStats returns alerting statistics for the dashboard.
	GetAlertingStats() any
}

// RuleStore manages the WAF rule engine — CRUD operations for rules.
type RuleStore interface {
	// GetRules returns all active rules in a serializable form.
	GetRules() any
	// AddRule adds a new rule to the engine.
	AddRule(raw map[string]any) error
	// UpdateRule updates an existing rule identified by id.
	UpdateRule(id string, raw map[string]any) error
	// RemoveRule deletes a rule by id. Returns false if not found.
	RemoveRule(id string) bool
	// ToggleRule enables or disables a rule by id. Returns false if not found.
	ToggleRule(id string, enabled bool) bool
}

// GeoLookup resolves an IP address to a country code and name.
type GeoLookup interface {
	// Lookup returns (country_code, country_name) for the given IP.
	// Returns ("", "GeoIP not loaded") if GeoIP is not configured.
	// Returns ("", "invalid IP") if the IP cannot be parsed.
	Lookup(ip string) (code string, name string)
}
