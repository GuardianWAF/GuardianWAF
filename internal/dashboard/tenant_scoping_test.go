package dashboard

import "testing"

// TestTenantKeyScoping_FailClosed locks in the fail-closed authorization for
// tenant-scoped API keys: only the explicit read-only allow-list is reachable,
// every admin/mutating endpoint is denied, and crucially a hypothetical NEW
// endpoint is denied by default (the regression the old deny-list allowed).
func TestTenantKeyScoping_FailClosed(t *testing.T) {
	allowed := []string{
		"/api/v1/stats",
		"/api/v1/events",
		"/api/v1/events/export",
		"/api/v1/events/evt-123", // sub-path
		"/api/v1/sse",
		"/api/v1/ssl",
		"/api/v1/upstreams",
		"/api/v1/docker/services",
		"/api/v1/geoip/lookup",
		"/api/v1/cwv",
		"/api/v1/alerting/status",
		"/api/v1/ai/providers",
		"/api/v1/ai/stats",
	}
	for _, p := range allowed {
		if !tenantKeyAllows(p) {
			t.Errorf("tenant key should be allowed for %q, but was denied", p)
		}
	}

	denied := []string{
		// admin / mutating endpoints
		"/api/v1/config",
		"/api/v1/routing",
		"/api/v1/ipacl",
		"/api/v1/bans",
		"/api/v1/rules",
		"/api/v1/rules/r1",
		"/api/v1/ai/config",
		"/api/v1/ai/analyze",
		"/api/v1/ai/test",
		// not tenant-partitioned → must be denied to tenant keys
		"/api/v1/logs",
		"/api/v1/ai/history",
		"/api/v1/alerting/webhooks",
		"/api/v1/alerting/emails",
		"/api/v1/alerting/test",
		"/api/v1/compliance",
		"/api/v1/compliance/controls",
		// fail-closed: a brand-new endpoint must NOT be reachable by default
		"/api/v1/secrets",
		"/api/v1/admin-thing",
		// prefix-boundary safety: must not match via naive HasPrefix
		"/api/v1/statsified",
		"/api/v1/ssl-private-keys",
	}
	for _, p := range denied {
		if tenantKeyAllows(p) {
			t.Errorf("tenant key must be DENIED for %q, but was allowed (fail-open)", p)
		}
	}
}
