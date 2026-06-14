package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowedUpstreamCIDRsPopulateValidateAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "guardianwaf.yaml")
	data := []byte(`mode: enforce
allowed_upstream_cidrs:
  - "10.42.0.0/16"
  - "127.0.0.1"
upstreams:
  - name: backend
    targets:
      - url: "http://10.42.1.10:8080"
routes:
  - path: /
    upstream: backend
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got := cfg.AllowedUpstreamCIDRs; len(got) != 2 || got[0] != "10.42.0.0/16" || got[1] != "127.0.0.1" {
		t.Fatalf("AllowedUpstreamCIDRs = %v", got)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	t.Setenv("GWAF_ALLOWED_UPSTREAM_CIDRS", "10.0.0.0/8, 192.168.10.5 ,,")
	LoadEnv(cfg)
	if got := cfg.AllowedUpstreamCIDRs; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.10.5" {
		t.Fatalf("AllowedUpstreamCIDRs from env = %v", got)
	}
}

func TestValidateAllowedUpstreamCIDRsRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		cidrs []string
	}{
		{name: "invalid", cidrs: []string{"not-a-cidr"}},
		{name: "all ipv4", cidrs: []string{"0.0.0.0/0"}},
		{name: "all ipv6", cidrs: []string{"::/0"}},
		{name: "unspecified ip", cidrs: []string{"0.0.0.0"}},
		{name: "unspecified cidr", cidrs: []string{"0.0.0.0/32"}},
		{name: "multicast", cidrs: []string{"224.0.0.0/4"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AllowedUpstreamCIDRs = tt.cidrs
			err := Validate(cfg)
			if err == nil {
				t.Fatal("Validate() error = nil, want validation error")
			}
		})
	}
}
