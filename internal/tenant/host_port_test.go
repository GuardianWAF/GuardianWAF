package tenant

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Regression tests: ResolveTenant must match the registered domain owner
// regardless of the port in r.Host. r.Host carries "host:port" for every
// request to a non-default port — including GuardianWAF's own default :9443
// listen — and ResolveTenant used to match r.Host verbatim against bare
// domain keys, so domain-based tenant resolution silently failed:
// RejectUnmatched=true returned nil (middleware 503 for all port-bearing
// traffic) and RejectUnmatched=false fell back to the DEFAULT tenant
// (cross-tenant isolation failure). Mirrors the proxy virtual-host router,
// which strips the port via netutil.StripPort.

func resolveSetup(t *testing.T) (*Manager, *Tenant, *Tenant) {
	t.Helper()
	m := NewManager(10)
	// First tenant becomes the default tenant.
	tenantA, err := m.CreateTenant("Acme", "default tenant", []string{"acme.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(acme): %v", err)
	}
	tenantB, err := m.CreateTenant("Other", "non-default tenant", []string{"other.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(other): %v", err)
	}
	return m, tenantA, tenantB
}

func TestResolveTenantHostWithPort(t *testing.T) {
	m, tenantA, tenantB := resolveSetup(t)

	portReq := httptest.NewRequest("GET", "http://other.example.com:9443/", nil)

	// Strict mode: nil here means the middleware 503s the request.
	m.RejectUnmatched = true
	if got := m.ResolveTenant(portReq); got == nil || got.ID != tenantB.ID {
		t.Fatalf("FAIL: Host with port did not resolve to tenant B in strict mode (got %v)", got)
	}

	// Permissive mode: must resolve to the domain owner, never fall back to
	// the default tenant A.
	m.RejectUnmatched = false
	if got := m.ResolveTenant(portReq); got == nil || got.ID != tenantB.ID {
		t.Fatalf("FAIL: Host with port resolved to the wrong tenant (got %v, want %s; default is %s)", got, tenantB.ID, tenantA.ID)
	}
}

// Control: behavior for hosts without a port must be unchanged.
func TestResolveTenantBareAndUnknownHosts(t *testing.T) {
	m, _, tenantB := resolveSetup(t)

	m.RejectUnmatched = true
	if got := m.ResolveTenant(httptest.NewRequest("GET", "http://other.example.com/", nil)); got == nil || got.ID != tenantB.ID {
		t.Fatalf("bare host did not resolve to tenant B (got %v)", got)
	}
	if got := m.ResolveTenant(httptest.NewRequest("GET", "http://unknown.example.com/", nil)); got != nil {
		t.Fatalf("unknown domain resolved in strict mode (got %v)", got)
	}
	m.RejectUnmatched = false
	if got := m.ResolveTenant(httptest.NewRequest("GET", "http://unknown.example.com/", nil)); got == nil {
		t.Fatal("unknown domain did not fall back to the default tenant in permissive mode")
	}
}

// Boundaries: IPv6 literal hosts (bracketed, with and without port) and an
// empty port must never panic and must not accidentally match a domain.
func TestResolveTenantHostBoundaries(t *testing.T) {
	m, _, _ := resolveSetup(t)
	m.RejectUnmatched = true

	cases := []struct {
		host string
		url  string
	}{
		{"[::1]:9443", "http://[::1]:9443/"},
		{"[::1]", "http://[::1]/"},
		{"::1", "http://[::1]/"}, // direct field set below; URL form brackets it
	}
	reqs := []*http.Request{
		httptest.NewRequest("GET", "http://[::1]:9443/", nil),
		httptest.NewRequest("GET", "http://[::1]/", nil),
	}
	bareIPv6 := httptest.NewRequest("GET", "http://[::1]/", nil)
	bareIPv6.Host = "::1" // no brackets, no port — SplitHostPort must fail closed
	reqs = append(reqs, bareIPv6)

	for i, req := range reqs {
		if req.Host != cases[i].host {
			t.Fatalf("setup: request %d Host = %q, want %q", i, req.Host, cases[i].host)
		}
		if got := m.ResolveTenant(req); got != nil {
			t.Fatalf("literal host %q resolved to %v in strict mode", req.Host, got)
		}
	}

	// Empty port ("host:") is legal Host syntax and must strip to the domain.
	m.RejectUnmatched = false
	emptyPort := httptest.NewRequest("GET", "http://other.example.com/", nil)
	emptyPort.Host = "other.example.com:"
	if got := m.ResolveTenant(emptyPort); got == nil || got.ID != tenantBID(m) {
		t.Fatalf("empty-port host did not resolve to the domain owner (got %v)", got)
	}
}

// tenantBID fetches the ID of the tenant owning other.example.com without
// re-creating tenants — keeps the boundary test independent of create order.
func tenantBID(m *Manager) string {
	if t := m.GetTenantByDomain("other.example.com"); t != nil {
		return t.ID
	}
	return ""
}
