package tenant

import "testing"

// Regression tests: tenant domains must be normalized at the index-write
// seams (CreateTenant / UpdateTenant). They were stored raw, so
// port-suffixed, whitespace-padded, and empty values registered index keys
// that could never match a request — ResolveTenant strips the port from Host
// (netutil.StripPort) and Host headers cannot carry whitespace, meaning an
// operator who entered "example.com:9443" (what the browser shows) got a
// tenant that silently never routed. normalizeDomain trims whitespace,
// strips ports, and preserves case for display (the index lowercases keys
// via domainKey); entries that are empty after normalization are rejected.

func TestManager_CreateTenant_NormalizesDomains(t *testing.T) {
	m := NewManager(10)

	// Port-suffixed domain: normalized at the write seam, resolves by bare host.
	portTenant, err := m.CreateTenant("Port", "", []string{"example.com:9443"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(port-suffixed): %v", err)
	}
	if got := portTenant.Domains[0]; got != "example.com" {
		t.Fatalf("stored domain = %q, want normalized %q", got, "example.com")
	}
	if got := m.GetTenantByDomain("example.com"); got == nil || got.ID != portTenant.ID {
		t.Fatalf("example.com returned %v; want port tenant %s", got, portTenant.ID)
	}

	// Whitespace-padded domain: trimmed at the write seam.
	padTenant, err := m.CreateTenant("Padded", "", []string{" padded.example.com "}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(padded): %v", err)
	}
	if got := padTenant.Domains[0]; got != "padded.example.com" {
		t.Fatalf("stored domain = %q, want trimmed %q", got, "padded.example.com")
	}
	if got := m.GetTenantByDomain("padded.example.com"); got == nil || got.ID != padTenant.ID {
		t.Fatalf("padded.example.com returned %v; want padded tenant %s", got, padTenant.ID)
	}

	// Empty domain: rejected — it would register an unmatchable index key.
	if _, err := m.CreateTenant("Blank", "", []string{""}, nil); err == nil {
		t.Fatal("CreateTenant accepted an empty domain; want rejection")
	}
	if _, err := m.CreateTenant("Spaces", "", []string{"   "}, nil); err == nil {
		t.Fatal("CreateTenant accepted a whitespace-only domain; want rejection")
	}

	// Uniqueness holds after normalization: the same host via an alternate
	// port/case spelling is a duplicate.
	if _, err := m.CreateTenant("Dup", "", []string{"Example.COM:8443"}, nil); err == nil {
		t.Fatal("CreateTenant accepted a duplicate host via alternate port/case spelling; want rejection")
	}

	// Case-display contract: mixed-case spelling is stored as authored and
	// resolves case-insensitively.
	caseTenant, err := m.CreateTenant("CaseKeep", "", []string{"CaseKeep.Example.NET"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(mixed-case): %v", err)
	}
	if got := caseTenant.Domains[0]; got != "CaseKeep.Example.NET" {
		t.Fatalf("stored domain = %q, want authored spelling preserved", got)
	}
	if got := m.GetTenantByDomain("casekeep.example.net"); got == nil || got.ID != caseTenant.ID {
		t.Fatalf("casekeep.example.net returned %v; want mixed-case tenant %s", got, caseTenant.ID)
	}
}

func TestManager_UpdateTenant_NormalizesDomains(t *testing.T) {
	m := NewManager(10)
	tenantA, err := m.CreateTenant("A", "", []string{"a.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(A): %v", err)
	}

	// Padded/ported update values are normalized and stay resolvable.
	if err := m.UpdateTenant(tenantA.ID, &TenantUpdate{Domains: []string{" a.example.com:80 "}}); err != nil {
		t.Fatalf("UpdateTenant(padded/ported): %v", err)
	}
	if got := tenantA.Domains[0]; got != "a.example.com" {
		t.Fatalf("stored domain = %q, want normalized %q", got, "a.example.com")
	}
	if got := m.GetTenantByDomain("a.example.com"); got == nil || got.ID != tenantA.ID {
		t.Fatalf("a.example.com returned %v; want tenant A after update", got)
	}

	// Empty domain in an update is rejected without corrupting state.
	if err := m.UpdateTenant(tenantA.ID, &TenantUpdate{Domains: []string{""}}); err == nil {
		t.Fatal("UpdateTenant accepted an empty domain; want rejection")
	}
	if got := m.GetTenantByDomain("a.example.com"); got == nil || got.ID != tenantA.ID {
		t.Fatalf("a.example.com returned %v after rejected update; tenant state must be unchanged", got)
	}
}
