package tenant

import (
	"net/http/httptest"
	"testing"
)

// Regression tests: the tenant domain index must be case-insensitive. DNS
// names are case-insensitive, but the index used raw strings for both keys
// and lookups: a request with Host "ACME.Example.COM" never matched a tenant
// registered as "acme.example.com", and the raw uniqueness checks allowed two
// tenants to register case-variant spellings of the same domain. Index keys
// are now normalized via domainKey at every write/read/delete seam, while
// tenant.Domains keeps the operator's authored spelling for display/API.
// Mirrors internal/proxy/router.go, which lowercases keys and lookups.

func caseSetup(t *testing.T) (*Manager, *Tenant, *Tenant) {
	t.Helper()
	m := NewManager(10)
	m.RejectUnmatched = true
	tenantA, err := m.CreateTenant("Acme", "", []string{"acme.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(acme): %v", err)
	}
	if _, err := m.CreateTenant("Other", "", []string{"other.example.com"}, nil); err != nil {
		t.Fatalf("CreateTenant(other): %v", err)
	}
	return m, tenantA, nil
}

func TestResolveTenantDomainCaseInsensitive(t *testing.T) {
	m, tenantA, _ := caseSetup(t)

	// Read side: uppercase Host resolves the lowercase-registered domain.
	req := httptest.NewRequest("GET", "http://ACME.Example.COM/", nil)
	if got := m.ResolveTenant(req); got == nil || got.ID != tenantA.ID {
		t.Fatalf("FAIL: uppercase Host %q did not resolve to its tenant (got %v)", req.Host, got)
	}

	// Write side: uppercase-registered domain resolves a lowercase request.
	tenantC, err := m.CreateTenant("Mixed", "", []string{"MIXED.Example.net"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(mixed): %v", err)
	}
	if got := m.ResolveTenant(httptest.NewRequest("GET", "http://mixed.example.net/", nil)); got == nil || got.ID != tenantC.ID {
		t.Fatalf("FAIL: lowercase request for uppercase-registered domain did not resolve (got %v)", got)
	}
}

func TestCreateTenantDomainUniquenessCaseInsensitive(t *testing.T) {
	m, _, _ := caseSetup(t)
	if _, err := m.CreateTenant("Sneak", "", []string{"OTHER.example.com"}, nil); err == nil {
		t.Fatal("FAIL: case-variant of an already-assigned domain was accepted — two tenants own the same DNS name")
	}
}

func TestUpdateDeleteDomainCaseNormalization(t *testing.T) {
	m, _, _ := caseSetup(t)
	tenantD, err := m.CreateTenant("D", "", []string{"OLD.Example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(d): %v", err)
	}

	// Update to a new domain set: the old domain (any case) must stop resolving.
	if err := m.UpdateTenant(tenantD.ID, &TenantUpdate{Domains: []string{"new.example.com"}}); err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	if got := m.GetTenantByDomain("old.example.com"); got != nil {
		t.Fatalf("old domain still resolves after update (got %v)", got)
	}
	if got := m.GetTenantByDomain("NEW.Example.com"); got == nil || got.ID != tenantD.ID {
		t.Fatalf("new domain (case-variant request) did not resolve after update (got %v)", got)
	}

	// Delete: the domain must be immediately re-registrable, even spelled
	// with a different case.
	if err := m.DeleteTenant(tenantD.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := m.CreateTenant("D2", "", []string{"NEW.example.com"}, nil); err != nil {
		t.Fatalf("domain not freed after tenant deletion: %v", err)
	}
}

func TestWildcardDomainCaseInsensitive(t *testing.T) {
	m, _, _ := caseSetup(t)
	if _, err := m.CreateTenant("Wild", "", []string{"*.wild.example"}, nil); err != nil {
		t.Fatalf("CreateTenant(wild): %v", err)
	}
	got := m.GetTenantByDomain("SUB.WILD.EXAMPLE")
	if got == nil || got.Name != "Wild" {
		t.Fatalf("FAIL: uppercase request against wildcard pattern *.wild.example did not resolve (got %v)", got)
	}
}

// The index normalizes; tenant.Domains must keep the authored spelling for
// display and the API.
func TestTenantDomainsKeepsAuthoredSpelling(t *testing.T) {
	m, _, _ := caseSetup(t)
	tenantC, err := m.CreateTenant("Mixed", "", []string{"MIXED.Example.net"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(mixed): %v", err)
	}
	if len(tenantC.Domains) != 1 || tenantC.Domains[0] != "MIXED.Example.net" {
		t.Fatalf("FAIL: tenant.Domains was rewritten (got %v)", tenantC.Domains)
	}
	_ = m
}
