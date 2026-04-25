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

// TestMarshalYAML_UpstreamTargets verifies that Upstreams with nested Targets
// and HealthCheck are fully serialized and survive a roundtrip.
// Covers Bug 2 (struct slice in inline context) and Bug 1 (nested struct indentation).
func TestMarshalYAML_UpstreamTargets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstreams = []UpstreamConfig{
		{
			Name: "backend",
			Targets: []TargetConfig{
				{URL: "http://localhost:3000", Weight: 1},
			},
			HealthCheck: HealthCheckConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
				Path:     "/health",
			},
			LoadBalancer: "round_robin",
		},
	}

	out := MarshalYAML(cfg)

	if !strings.Contains(out, "targets:") {
		t.Errorf("expected 'targets:' in output (Bug 2 regression); got:\n%s", out)
	}
	if !strings.Contains(out, "http://localhost:3000") {
		t.Errorf("expected target URL in output; got:\n%s", out)
	}
	if !strings.Contains(out, "health_check:") {
		t.Errorf("expected 'health_check:' in output; got:\n%s", out)
	}

	// Roundtrip: parse back and verify values (also catches Bug 1 indentation)
	node, err := Parse([]byte(out))
	if err != nil {
		t.Fatalf("Parse error after marshal: %v\nYAML:\n%s", err, out)
	}
	cfg2 := DefaultConfig()
	if err := PopulateFromNode(cfg2, node); err != nil {
		t.Fatalf("PopulateFromNode error: %v", err)
	}
	if len(cfg2.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream after roundtrip, got %d", len(cfg2.Upstreams))
	}
	if len(cfg2.Upstreams[0].Targets) != 1 {
		t.Fatalf("expected 1 target after roundtrip, got %d", len(cfg2.Upstreams[0].Targets))
	}
	if cfg2.Upstreams[0].Targets[0].URL != "http://localhost:3000" {
		t.Errorf("target URL: got %q, want %q", cfg2.Upstreams[0].Targets[0].URL, "http://localhost:3000")
	}
	if !cfg2.Upstreams[0].HealthCheck.Enabled {
		t.Error("expected health_check.enabled=true after roundtrip (Bug 1 regression)")
	}
}

// TestMarshalYAML_VirtualHostRoutes verifies that VirtualHosts with nested
// Routes are fully serialized and survive a roundtrip.
// Covers Bug 2 (struct slice in inline context).
func TestMarshalYAML_VirtualHostRoutes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstreams = []UpstreamConfig{
		{Name: "backend", Targets: []TargetConfig{{URL: "http://localhost:3000"}}},
	}
	cfg.VirtualHosts = []VirtualHostConfig{
		{
			Domains: []string{"api.example.com"},
			Routes: []RouteConfig{
				{Path: "/api", Upstream: "backend", Methods: []string{"GET", "POST"}},
			},
		},
	}

	out := MarshalYAML(cfg)

	if !strings.Contains(out, "virtual_hosts:") {
		t.Errorf("expected 'virtual_hosts:' in output; got:\n%s", out)
	}
	if !strings.Contains(out, "routes:") {
		t.Errorf("expected 'routes:' in output (Bug 2 regression); got:\n%s", out)
	}
	if !strings.Contains(out, "/api") {
		t.Errorf("expected route path '/api' in output; got:\n%s", out)
	}

	node, err := Parse([]byte(out))
	if err != nil {
		t.Fatalf("Parse error: %v\nYAML:\n%s", err, out)
	}
	cfg2 := DefaultConfig()
	if err := PopulateFromNode(cfg2, node); err != nil {
		t.Fatalf("PopulateFromNode error: %v", err)
	}
	if len(cfg2.VirtualHosts) != 1 {
		t.Fatalf("expected 1 virtual host after roundtrip, got %d", len(cfg2.VirtualHosts))
	}
	if len(cfg2.VirtualHosts[0].Routes) != 1 {
		t.Fatalf("expected 1 route after roundtrip, got %d", len(cfg2.VirtualHosts[0].Routes))
	}
	if cfg2.VirtualHosts[0].Routes[0].Path != "/api" {
		t.Errorf("route path: got %q, want %q", cfg2.VirtualHosts[0].Routes[0].Path, "/api")
	}
}

// TestMarshalYAML_VirtualHostWAFPointer verifies that the *WAFConfig pointer
// field on VirtualHostConfig is serialized correctly.
// Covers Bug 3 (missing reflect.Ptr case in marshalInlineField).
func TestMarshalYAML_VirtualHostWAFPointer(t *testing.T) {
	cfg := DefaultConfig()
	perHostWAF := WAFConfig{}
	perHostWAF.RateLimit.Enabled = true
	perHostWAF.RateLimit.Rules = []RateLimitRule{
		{ID: "vhost-limit", Scope: "ip", Limit: 50, Window: time.Minute, Action: "block"},
	}
	cfg.VirtualHosts = []VirtualHostConfig{
		{
			Domains: []string{"secure.example.com"},
			WAF:     &perHostWAF,
		},
	}

	out := MarshalYAML(cfg)

	if !strings.Contains(out, "waf:") {
		t.Errorf("expected 'waf:' block inside virtual_hosts entry (Bug 3 regression); got:\n%s", out)
	}
	if !strings.Contains(out, "vhost-limit") {
		t.Errorf("expected rate limit rule id 'vhost-limit' in output; got:\n%s", out)
	}
}
