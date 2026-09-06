package tenant

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

// Regression tests: a rejected UpdateTenant domain change must not corrupt
// the in-memory domain index. UpdateTenant used to delete the tenant's old
// domain mappings BEFORE validating the new set, so a validation error
// (requested domain already owned by another tenant) returned after the old
// mappings were gone: the index no longer resolved the domains that
// tenant.Domains (and persisted state) still claimed, and the tenant's
// traffic silently fell to the default tenant or was rejected with 503 until
// the next successful update or a restart. Validation now runs before any
// index mutation.

func atomicitySetup(t *testing.T) (*Manager, *Tenant, *Tenant, *Tenant) {
	t.Helper()
	m := NewManager(10)
	m.RejectUnmatched = true
	tenantA, err := m.CreateTenant("A", "", []string{"a.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(a): %v", err)
	}
	tenantB, err := m.CreateTenant("B", "", []string{"b.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(b): %v", err)
	}
	tenantD, err := m.CreateTenant("D", "", []string{"d.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(d): %v", err)
	}
	return m, tenantA, tenantB, tenantD
}

func TestUpdateTenantRejectedUpdateKeepsOldDomains(t *testing.T) {
	m, _, tenantB, tenantD := atomicitySetup(t)

	// Rejected update: the new set claims a domain owned by tenant B.
	err := m.UpdateTenant(tenantD.ID, &TenantUpdate{Domains: []string{"newd.example.com", "b.example.com"}})
	if err == nil {
		t.Fatal("conflicting domain update unexpectedly succeeded")
	}

	// The tenant's OLD domain must still resolve after the failed update.
	if got := m.GetTenantByDomain("d.example.com"); got == nil || got.ID != tenantD.ID {
		t.Fatalf("FAIL: after a rejected domain update the tenant's existing domain no longer resolves (got %v)", got)
	}

	// tenant.Domains (what the API reports and persists) must match the index.
	current := m.GetTenant(tenantD.ID)
	if current == nil || !reflect.DeepEqual(current.Domains, []string{"d.example.com"}) {
		t.Fatalf("FAIL: tenant.Domains changed after a rejected update (got %v)", current.Domains)
	}
	if got := m.ResolveTenant(httptest.NewRequest("GET", "http://d.example.com:9443/", nil)); got == nil || got.ID != tenantD.ID {
		t.Fatalf("FAIL: request for the still-owned domain does not resolve after the failed update (got %v)", got)
	}

	// The conflicting domain must still belong to B.
	if got := m.GetTenantByDomain("b.example.com"); got == nil || got.ID != tenantB.ID {
		t.Fatalf("FAIL: tenant B lost its domain after a rejected update on D (got %v)", got)
	}
}

func TestUpdateTenantValidUpdateSwapsDomains(t *testing.T) {
	m, _, _, tenantD := atomicitySetup(t)

	if err := m.UpdateTenant(tenantD.ID, &TenantUpdate{Domains: []string{"d2.example.com"}}); err != nil {
		t.Fatalf("valid domain update returned an error: %v", err)
	}
	if got := m.GetTenantByDomain("d2.example.com"); got == nil || got.ID != tenantD.ID {
		t.Fatal("valid update did not register the new domain")
	}
	if got := m.GetTenantByDomain("d.example.com"); got != nil {
		t.Fatalf("old domain still resolves after a successful update (got %v)", got)
	}
}

// Re-claiming the tenant's own domain (case-variant included) is not a
// conflict and must succeed.
func TestUpdateTenantSelfOwnedCaseVariantNoFalseConflict(t *testing.T) {
	m, _, _, tenantD := atomicitySetup(t)

	if err := m.UpdateTenant(tenantD.ID, &TenantUpdate{Domains: []string{"d.example.com", "D.EXAMPLE.com"}}); err != nil {
		t.Fatalf("self-owned case-variant domain falsely rejected as conflict: %v", err)
	}
	if got := m.GetTenantByDomain("d.EXAMPLE.com"); got == nil || got.ID != tenantD.ID {
		t.Fatalf("self-owned domain no longer resolves after re-claim (got %v)", got)
	}
}
