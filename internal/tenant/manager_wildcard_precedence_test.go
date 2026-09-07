package tenant

import "testing"

// Regression tests: tenant resolution must be deterministic when multiple
// wildcard patterns match one host. GetTenantByDomain fell back to iterating
// the m.domains map and returning on the FIRST matchWildcard hit; Go map
// iteration order is randomized and matchWildcard is pure suffix matching, so
// with *.example.com (tenant A) and *.sub.example.com (tenant B), the host
// shop.sub.example.com matched both and resolution flapped between tenants
// per request and across restarts. Standard DNS wildcard semantics now apply:
// the longest (most-specific) suffix wins. Two distinct equal-length patterns
// cannot both suffix-match one host, so longest-pattern alone is fully
// deterministic.

func TestManager_GetTenantByDomain_WildcardPrecedence(t *testing.T) {
	m := NewManager(10)
	broad, err := m.CreateTenant("Broad", "", []string{"*.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(broad): %v", err)
	}
	specific, err := m.CreateTenant("Specific", "", []string{"*.sub.example.com"}, nil)
	if err != nil {
		t.Fatalf("CreateTenant(specific): %v", err)
	}

	// The regression: every resolution must deterministically return the
	// most-specific (longest suffix) wildcard tenant.
	for i := 0; i < 200; i++ {
		got := m.GetTenantByDomain("shop.sub.example.com")
		if got == nil || got.ID != specific.ID {
			t.Fatalf("resolution %d: shop.sub.example.com returned %v; want most-specific wildcard tenant %s", i+1, got, specific.ID)
		}
	}

	// Secondary branches.
	if got := m.GetTenantByDomain("app.example.com"); got == nil || got.ID != broad.ID {
		t.Fatalf("app.example.com returned %v; want broad wildcard tenant %s", got, broad.ID)
	}
	if got := m.GetTenantByDomain("SHOP.SUB.EXAMPLE.COM"); got == nil || got.ID != specific.ID {
		t.Fatalf("uppercase host returned %v; want specific wildcard tenant (case-insensitive index) %s", got, specific.ID)
	}
	if got := m.GetTenantByDomain("a.b.sub.example.com"); got == nil || got.ID != specific.ID {
		t.Fatalf("deep subdomain returned %v; want specific wildcard tenant %s", got, specific.ID)
	}
	if got := m.GetTenantByDomain("example.com"); got != nil {
		t.Fatalf("bare apex returned %v; want nil (wildcards must not match their own apex)", got)
	}
}
