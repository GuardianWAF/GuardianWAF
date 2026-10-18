package config

// Regression: FindVirtualHost must be case-insensitive, like every other vhost
// matcher in the codebase.
//
// Host headers and DNS names are case-insensitive. The proxy router lower-cases
// the registered key and the incoming Host (internal/proxy/router.go:77,83,227)
// and the duplicate-domain validator keys on strings.ToLower(domain)
// (internal/config/validate.go:1716) precisely so validator and runtime cannot
// diverge. FindVirtualHost compared `domain == host` with no normalisation on
// either side.
//
// This matters beyond tidiness: internal/engine/engine.go:558 uses this matcher
// to choose ctx.TenantWAFConfig, and falls back to the tenant BASE config when
// it misses:
//
//	if vh := config.FindVirtualHost(tenantCtx.VirtualHosts, r.Host); vh != nil && vh.WAF != nil {
//	    ctx.TenantWAFConfig = vh.WAF
//	} else {
//	    ctx.TenantWAFConfig = tenantCtx.WAFConfig
//	}
//
// So a case-variant Host silently discarded the operator's per-vhost WAF
// override (stricter rate limits, extra detection, custom exclusions) and
// evaluated the request under the tenant's base config — fail-open on a
// security control.

import "testing"

func TestFindVirtualHostIsCaseInsensitive(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"Example.com"}, WAF: &WAFConfig{}},
		{Domains: []string{"*.Shop.Example.ORG"}},
	}

	t.Run("exact_domain_case_variants_all_match", func(t *testing.T) {
		for _, host := range []string{"Example.com", "example.com", "EXAMPLE.COM", "ExAmPlE.cOm"} {
			if vh := FindVirtualHost(vhosts, host); vh == nil {
				t.Errorf("Host %q did not match configured domain %q; the router matches "+
					"all of these, so validator and runtime diverge and the per-vhost "+
					"WAF override is silently discarded.", host, "Example.com")
			}
		}
	})

	t.Run("wildcard_case_variants_match", func(t *testing.T) {
		for _, host := range []string{"a.Shop.Example.org", "a.shop.example.org"} {
			if vh := FindVirtualHost(vhosts, host); vh == nil {
				t.Errorf("Host %q did not match wildcard %q", host, "*.Shop.Example.ORG")
			}
		}
	})

	t.Run("port_suffix_and_case_combined", func(t *testing.T) {
		for _, host := range []string{"example.com:8443", "EXAMPLE.com:8443", "ExAmPlE.CoM:443"} {
			if vh := FindVirtualHost(vhosts, host); vh == nil {
				t.Errorf("Host %q did not match after case folding + port stripping", host)
			}
		}
	})
}

// Controls: normalisation must not widen matching. An unconfigured host must
// still miss, the apex must still not satisfy a "*.<domain>" wildcard (the
// pre-existing single-label, nginx-vhost-consistent rule), and an empty input
// must still return nil.
func TestFindVirtualHostCaseFixDoesNotWidenMatching(t *testing.T) {
	vhosts := []VirtualHostConfig{
		{Domains: []string{"Example.com"}},
		{Domains: []string{"*.Shop.Example.ORG"}},
	}

	t.Run("unrelated_hosts_still_miss", func(t *testing.T) {
		for _, host := range []string{
			"attacker.example", "example.com.evil.test", "shop.example.org",
			"notexample.com", "xexample.com",
		} {
			if vh := FindVirtualHost(vhosts, host); vh != nil {
				t.Errorf("Host %q wrongly matched a configured vhost", host)
			}
		}
	})

	t.Run("apex_still_does_not_satisfy_wildcard", func(t *testing.T) {
		// "shop.example.org" is the apex of "*.Shop.Example.ORG" and must not match.
		if vh := FindVirtualHost(vhosts, "Shop.Example.ORG"); vh != nil {
			t.Errorf("apex domain matched a *.<domain> wildcard")
		}
	})

	t.Run("empty_host_still_nil", func(t *testing.T) {
		if vh := FindVirtualHost(vhosts, ""); vh != nil {
			t.Errorf("empty host matched a vhost")
		}
	})

	t.Run("empty_vhost_list_still_nil", func(t *testing.T) {
		if vh := FindVirtualHost(nil, "example.com"); vh != nil {
			t.Errorf("empty vhost list matched")
		}
	})
}

// The selected vhost must actually be the right one after folding — not merely
// non-nil. Exact matches still take precedence over wildcards.
func TestFindVirtualHostSelectsCorrectVHostAfterFolding(t *testing.T) {
	exact := &WAFConfig{}
	wild := &WAFConfig{}
	vhosts := []VirtualHostConfig{
		{Domains: []string{"*.Example.com"}, WAF: wild},
		{Domains: []string{"API.Example.com"}, WAF: exact},
	}

	t.Run("exact_wins_over_wildcard_across_case", func(t *testing.T) {
		vh := FindVirtualHost(vhosts, "api.EXAMPLE.com")
		if vh == nil {
			t.Fatalf("exact domain did not match")
		}
		if vh.WAF != exact {
			t.Errorf("wildcard vhost selected for the exact domain; precedence changed")
		}
	})

	t.Run("wildcard_selected_for_others", func(t *testing.T) {
		vh := FindVirtualHost(vhosts, "www.example.com")
		if vh == nil {
			t.Fatalf("wildcard did not match")
		}
		if vh.WAF != wild {
			t.Errorf("expected the wildcard vhost, got the exact one")
		}
	})
}
