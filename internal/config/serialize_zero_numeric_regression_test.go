package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMarshalYAMLRetainsZeroNumericOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	control := DefaultConfig()
	control.WAF.IPACL.AutoBan.MaxAutoBanEntries = 17
	if err := SaveFile(path, control); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WAF.IPACL.AutoBan.MaxAutoBanEntries != 17 {
		t.Fatal("unaffected nonzero control failed")
	}
	t.Log("CONTROL: nonzero override survives save/load")
	cfg := DefaultConfig()
	cfg.WAF.IPACL.AutoBan.MaxAutoBanEntries = 0
	cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge = 0
	cfg.WAF.AIAnalysis.BatchInterval = 0 * time.Second
	if err = SaveFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("EXPECTED: entries=0 max_age=0 batch_interval=0; ACTUAL: entries=%d max_age=%d batch_interval=%s", got.WAF.IPACL.AutoBan.MaxAutoBanEntries, got.WAF.Response.SecurityHeaders.HSTS.MaxAge, got.WAF.AIAnalysis.BatchInterval)
	if got.WAF.IPACL.AutoBan.MaxAutoBanEntries != 0 || got.WAF.Response.SecurityHeaders.HSTS.MaxAge != 0 || got.WAF.AIAnalysis.BatchInterval != 0 {
		t.Fatal("PROBLEM CONFIRMED")
	}
	t.Log("FIX VERIFIED")
}

func TestMarshalYAMLRetainsZeroNumericOverridesEdges(t *testing.T) {
	for _, n := range []int{0, 1, 100000} {
		cfg := DefaultConfig()
		cfg.WAF.IPACL.AutoBan.MaxAutoBanEntries = n
		cfg.Tracing.SamplingRate = float64(n % 2)
		cfg.WAF.AIAnalysis.BatchInterval = time.Duration(n) * time.Second
		path := filepath.Join(t.TempDir(), "config.yaml")
		for range 2 {
			if err := SaveFile(path, cfg); err != nil {
				t.Fatal(err)
			}
			got, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.WAF.IPACL.AutoBan.MaxAutoBanEntries != n || got.Tracing.SamplingRate != float64(n%2) || got.WAF.AIAnalysis.BatchInterval != time.Duration(n)*time.Second {
				t.Fatal("numeric roundtrip changed")
			}
			node, err := Parse([]byte(MarshalYAML(got)))
			if err != nil {
				t.Fatal(err)
			}
			if node.GetPath("tracing", "sampling_rate") == nil {
				t.Fatal("explicit sampling rate omitted")
			}
			cfg = got
		}
	}
}
