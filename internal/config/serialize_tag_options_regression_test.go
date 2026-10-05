package config

import (
	"path/filepath"
	"testing"
)

func TestMarshalYAMLUsesTagNamesWithoutOptions(t *testing.T) {
	for _, waf := range []*WAFConfig{nil, {}, {Sanitizer: SanitizerConfig{Enabled: true, MaxURLLength: 100}}, {Detection: DetectionConfig{Enabled: false, Threshold: ThresholdConfig{Block: 60, Log: 20}}}} {
		cfg := DefaultConfig()
		cfg.VirtualHosts = []VirtualHostConfig{{Domains: []string{"ordinary.example.com"}, WAF: waf}}
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := SaveFile(path, cfg); err != nil {
			t.Fatal(err)
		}
		got, err := LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if (got.VirtualHosts[0].WAF == nil) != (waf == nil) {
			t.Fatal("pointer presence changed")
		}
		if waf != nil && got.VirtualHosts[0].WAF.Sanitizer.MaxURLLength != waf.Sanitizer.MaxURLLength {
			t.Fatal("nested value changed")
		}
	}
}
