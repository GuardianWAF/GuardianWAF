package config

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalYAML_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	out := MarshalYAML(cfg)
	if out == "" {
		t.Fatal("expected non-empty YAML output")
	}
	if !strings.Contains(out, "mode:") {
		t.Error("expected 'mode:' in output")
	}
	if !strings.Contains(out, "listen:") {
		t.Error("expected 'listen:' in output")
	}
}

func TestMarshalYAML_Roundtrip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.Listen = ":9090"
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Threshold.Block = 60
	cfg.WAF.Detection.Threshold.Log = 30
	cfg.WAF.Detection.Detectors = map[string]DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.5},
		"xss":  {Enabled: true, Multiplier: 1.0},
	}
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{ID: "global", Scope: "ip", Limit: 100, Window: time.Minute, Action: "block"},
	}

	yamlStr := MarshalYAML(cfg)

	// Parse back
	node, err := Parse([]byte(yamlStr))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	cfg2 := DefaultConfig()
	if err := PopulateFromNode(cfg2, node); err != nil {
		t.Fatalf("PopulateFromNode error: %v", err)
	}

	if cfg2.Mode != "enforce" {
		t.Errorf("mode: got %q, want %q", cfg2.Mode, "enforce")
	}
	if cfg2.Listen != ":9090" {
		t.Errorf("listen: got %q, want %q", cfg2.Listen, ":9090")
	}
	if cfg2.WAF.Detection.Threshold.Block != 60 {
		t.Errorf("block threshold: got %d, want 60", cfg2.WAF.Detection.Threshold.Block)
	}
}

func TestMarshalYAML_Duration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{ID: "test", Scope: "ip", Limit: 10, Window: 30 * time.Second, Action: "block"},
	}

	out := MarshalYAML(cfg)
	if !strings.Contains(out, "30s") {
		t.Errorf("expected '30s' duration in output, got:\n%s", out)
	}
}

func TestMarshalYAML_StringSlice(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.AllowedMethods = []string{"GET", "POST", "PUT"}

	out := MarshalYAML(cfg)
	if !strings.Contains(out, "GET") {
		t.Error("expected GET in output")
	}
}

func TestMarshalYAML_NestedStruct(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.Listen = ":8443"
	cfg.TLS.CertFile = "/etc/ssl/cert.pem"
	cfg.TLS.KeyFile = "/etc/ssl/key.pem"

	out := MarshalYAML(cfg)
	if !strings.Contains(out, "tls:") {
		t.Error("expected 'tls:' section in output")
	}
	if !strings.Contains(out, "cert_file:") {
		t.Error("expected 'cert_file:' in output")
	}
}

func TestMarshalYAML_MapDetectors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Detectors = map[string]DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.0},
	}

	out := MarshalYAML(cfg)
	if !strings.Contains(out, "detectors:") {
		t.Error("expected 'detectors:' in output")
	}
	if !strings.Contains(out, "sqli:") {
		t.Error("expected 'sqli:' in output")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{30 * time.Second, "30s"},
		{time.Minute, "1m"},
		{5 * time.Minute, "5m"},
		{time.Hour, "1h"},
		{24 * time.Hour, "24h"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
