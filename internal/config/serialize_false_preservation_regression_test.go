package config

import (
	"path/filepath"
	"testing"
)

func TestMarshalYAMLRetainsExplicitFalse(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := DefaultConfig()
		cfg.Dashboard.Enabled = enabled
		cfg.TLS.HTTPRedirect = enabled
		cfg.WAF.Sanitizer.Enabled = enabled
		cfg.WAF.Sanitizer.BlockNullBytes = enabled
		cfg.WAF.Detection.Detectors["sqli"] = DetectorConfig{Enabled: enabled, Multiplier: 1}
		cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{"ordinary.example.com"}, WAF: &WAFConfig{Sanitizer: SanitizerConfig{Enabled: enabled, MaxURLLength: 100}}}}
		path := filepath.Join(t.TempDir(), "config.yaml")
		for range 2 {
			if err := SaveFile(path, cfg); err != nil {
				t.Fatal(err)
			}
			got, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []bool{got.Dashboard.Enabled, got.TLS.HTTPRedirect, got.WAF.Sanitizer.Enabled, got.WAF.Sanitizer.BlockNullBytes, got.WAF.Detection.Detectors["sqli"].Enabled, got.VirtualHosts[0].WAF.Sanitizer.Enabled} {
				if value != enabled {
					t.Fatalf("got=%v want=%v", value, enabled)
				}
			}
			cfg = got
		}
	}
	cfg := DefaultConfig()
	cfg.WAF.Sanitizer = SanitizerConfig{}
	node, err := Parse([]byte(MarshalYAML(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	flag := node.GetPath("waf", "sanitizer", "enabled")
	if flag == nil || flag.String() != "false" {
		t.Fatal("zero section dropped its explicit false")
	}
}
