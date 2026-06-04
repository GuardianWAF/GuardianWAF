package config

import (
	"strings"
	"testing"
)

// TestPopulate_FailsLoudOnMalformedScalar locks in the hardening that turns
// silently-dropped type-conversion errors into loud config-load failures: a
// typo such as `strict_mode: yess` previously parsed to the zero value and the
// operator's intent was silently discarded. An absent or empty value must still
// fall back to the default (no error), and a valid value must apply.
func TestPopulate_FailsLoudOnMalformedScalar(t *testing.T) {
	reject := []struct {
		name string
		yaml string
		want string // substring expected in the error
	}{
		{"bad bool", "waf:\n  cors:\n    strict_mode: yess\n", "strict_mode"},
		{"bad int", "waf:\n  crs:\n    paranoia_level: abc\n", "paranoia_level"},
		{"bad nested bool", "waf:\n  threat_intel:\n    ip_reputation:\n      block_malicious: ture\n", "block_malicious"},
		{"bad geoip bool", "waf:\n  geoip:\n    auto_download: nope\n", "auto_download"},
		{"bad api_validation int", "waf:\n  api_validation:\n    cache_size: lots\n", "cache_size"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = PopulateFromNode(DefaultConfig(), node)
			if err == nil {
				t.Fatalf("expected load error for %s; got nil (silent drop regression)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got: %v", tc.want, err)
			}
		})
	}

	// Empty/absent values must keep the default (no error).
	t.Run("accept/empty keeps default", func(t *testing.T) {
		node, err := Parse([]byte("waf:\n  cors:\n    strict_mode:\n    enabled: true\n"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		cfg := DefaultConfig()
		if err := PopulateFromNode(cfg, node); err != nil {
			t.Fatalf("empty value should keep default, got error: %v", err)
		}
		if !cfg.WAF.CORS.Enabled {
			t.Fatal("valid sibling field (enabled: true) was not applied")
		}
	})

	// A valid value must apply.
	t.Run("accept/valid applies", func(t *testing.T) {
		node, err := Parse([]byte("waf:\n  cors:\n    strict_mode: true\n"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		cfg := DefaultConfig()
		if err := PopulateFromNode(cfg, node); err != nil {
			t.Fatalf("valid value should not error: %v", err)
		}
		if !cfg.WAF.CORS.StrictMode {
			t.Fatal("strict_mode: true was not applied")
		}
	})
}
