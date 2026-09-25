package config

// Regression (round 2026-09-25-r7-vhost-case-dup): validateVirtualHosts
// detected duplicate vhost domains with an exact-string map key, while the
// proxy's vhost router registers domains lowercased
// (exactHosts[strings.ToLower(domain)]) and lowercases the incoming Host
// before lookup. Case-variant duplicates ("Example.com" vs "example.com")
// passed validation as distinct, then collapsed at runtime into a single
// router entry — the later-registered vhost silently replaced the earlier
// one and its routes became unreachable. Post-fix the duplicate detection
// keys on the router's own normalization (strings.ToLower), so the
// validation contract matches the runtime's case-insensitive resolution.

import (
	"strings"
	"testing"
)

func vhostCaseDupConfig(vhosts []VirtualHostConfig) *Config {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.Listen = "127.0.0.1:8080"
	cfg.Upstreams = []UpstreamConfig{{
		Name:    "u1",
		Targets: []TargetConfig{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}}
	cfg.VirtualHosts = vhosts
	return cfg
}

func TestValidateVirtualHostsCaseVariantDuplicateDomains(t *testing.T) {
	// Control: genuinely distinct domains validate cleanly.
	distinct := vhostCaseDupConfig([]VirtualHostConfig{
		{Domains: []string{"shop.example.com"}, Routes: []RouteConfig{{Path: "/a", Upstream: "u1"}}},
		{Domains: []string{"example.com"}, Routes: []RouteConfig{{Path: "/b", Upstream: "u1"}}},
	})
	if err := Validate(distinct); err != nil {
		t.Fatalf("control: distinct vhost domains rejected: %v", err)
	}

	// Existing behavior: exact duplicates are rejected.
	exact := vhostCaseDupConfig([]VirtualHostConfig{
		{Domains: []string{"example.com"}, Routes: []RouteConfig{{Path: "/a", Upstream: "u1"}}},
		{Domains: []string{"example.com"}, Routes: []RouteConfig{{Path: "/b", Upstream: "u1"}}},
	})
	err := Validate(exact)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("exact duplicate vhost domains not rejected: %v", err)
	}

	// The fixed defect: case-variant duplicates collapse to one
	// case-insensitive router entry at runtime — they must be rejected
	// exactly like exact duplicates.
	caseVariant := vhostCaseDupConfig([]VirtualHostConfig{
		{Domains: []string{"Example.com"}, Routes: []RouteConfig{{Path: "/a", Upstream: "u1"}}},
		{Domains: []string{"example.com"}, Routes: []RouteConfig{{Path: "/b", Upstream: "u1"}}},
	})
	if err := Validate(caseVariant); err == nil {
		t.Fatalf("case-variant duplicate vhost domains accepted — they collapse to one router entry at runtime")
	}

	// Secondary branch: case-variant duplicates within a SINGLE vhost's
	// domain list are rejected too.
	withinOne := vhostCaseDupConfig([]VirtualHostConfig{
		{Domains: []string{"Example.com", "example.com"}, Routes: []RouteConfig{{Path: "/a", Upstream: "u1"}}},
	})
	if err := Validate(withinOne); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("within-vhost case-variant duplicate not rejected: %v", err)
	}
}
