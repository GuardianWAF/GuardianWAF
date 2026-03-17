package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Top-level
	if cfg.Mode != "enforce" {
		t.Fatalf("expected mode 'enforce', got %q", cfg.Mode)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("expected listen ':8080', got %q", cfg.Listen)
	}

	// TLS defaults
	if cfg.TLS.Listen != ":8443" {
		t.Fatalf("expected TLS listen ':8443', got %q", cfg.TLS.Listen)
	}
	if cfg.TLS.Enabled {
		t.Fatal("expected TLS disabled by default")
	}
	if cfg.TLS.ACME.CacheDir != "/var/lib/guardianwaf/acme" {
		t.Fatalf("expected ACME cache dir, got %q", cfg.TLS.ACME.CacheDir)
	}

	// WAF IPACL
	if !cfg.WAF.IPACL.Enabled {
		t.Fatal("expected IPACL enabled")
	}
	if !cfg.WAF.IPACL.AutoBan.Enabled {
		t.Fatal("expected AutoBan enabled")
	}
	if cfg.WAF.IPACL.AutoBan.DefaultTTL != 1*time.Hour {
		t.Fatalf("expected DefaultTTL 1h, got %v", cfg.WAF.IPACL.AutoBan.DefaultTTL)
	}
	if cfg.WAF.IPACL.AutoBan.MaxTTL != 24*time.Hour {
		t.Fatalf("expected MaxTTL 24h, got %v", cfg.WAF.IPACL.AutoBan.MaxTTL)
	}

	// WAF RateLimit
	if !cfg.WAF.RateLimit.Enabled {
		t.Fatal("expected RateLimit enabled")
	}
	if len(cfg.WAF.RateLimit.Rules) != 1 {
		t.Fatalf("expected 1 default rate limit rule, got %d", len(cfg.WAF.RateLimit.Rules))
	}
	rule := cfg.WAF.RateLimit.Rules[0]
	if rule.ID != "global" {
		t.Fatalf("expected rule ID 'global', got %q", rule.ID)
	}
	if rule.Scope != "ip" {
		t.Fatalf("expected rule scope 'ip', got %q", rule.Scope)
	}
	if rule.Limit != 1000 {
		t.Fatalf("expected rule limit 1000, got %d", rule.Limit)
	}
	if rule.Window != 1*time.Minute {
		t.Fatalf("expected rule window 1m, got %v", rule.Window)
	}
	if rule.Burst != 50 {
		t.Fatalf("expected rule burst 50, got %d", rule.Burst)
	}
	if rule.Action != "block" {
		t.Fatalf("expected rule action 'block', got %q", rule.Action)
	}

	// WAF Sanitizer
	if !cfg.WAF.Sanitizer.Enabled {
		t.Fatal("expected Sanitizer enabled")
	}
	if cfg.WAF.Sanitizer.MaxURLLength != 8192 {
		t.Fatalf("expected MaxURLLength 8192, got %d", cfg.WAF.Sanitizer.MaxURLLength)
	}
	if cfg.WAF.Sanitizer.MaxBodySize != 10*1024*1024 {
		t.Fatalf("expected MaxBodySize 10MB, got %d", cfg.WAF.Sanitizer.MaxBodySize)
	}
	if !cfg.WAF.Sanitizer.BlockNullBytes {
		t.Fatal("expected BlockNullBytes true")
	}
	if len(cfg.WAF.Sanitizer.AllowedMethods) != 7 {
		t.Fatalf("expected 7 allowed methods, got %d", len(cfg.WAF.Sanitizer.AllowedMethods))
	}

	// WAF Detection
	if !cfg.WAF.Detection.Enabled {
		t.Fatal("expected Detection enabled")
	}
	if cfg.WAF.Detection.Threshold.Block != 50 {
		t.Fatalf("expected block threshold 50, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.WAF.Detection.Threshold.Log != 25 {
		t.Fatalf("expected log threshold 25, got %d", cfg.WAF.Detection.Threshold.Log)
	}
	expectedDetectors := []string{"sqli", "xss", "lfi", "cmdi", "xxe", "ssrf"}
	if len(cfg.WAF.Detection.Detectors) != len(expectedDetectors) {
		t.Fatalf("expected %d detectors, got %d", len(expectedDetectors), len(cfg.WAF.Detection.Detectors))
	}
	for _, name := range expectedDetectors {
		d, ok := cfg.WAF.Detection.Detectors[name]
		if !ok {
			t.Fatalf("missing detector %q", name)
		}
		if !d.Enabled {
			t.Fatalf("expected detector %q enabled", name)
		}
		if d.Multiplier != 1.0 {
			t.Fatalf("expected detector %q multiplier 1.0, got %f", name, d.Multiplier)
		}
	}

	// WAF BotDetection
	if !cfg.WAF.BotDetection.Enabled {
		t.Fatal("expected BotDetection enabled")
	}
	if cfg.WAF.BotDetection.Mode != "monitor" {
		t.Fatalf("expected BotDetection mode 'monitor', got %q", cfg.WAF.BotDetection.Mode)
	}
	if !cfg.WAF.BotDetection.TLSFingerprint.Enabled {
		t.Fatal("expected TLSFingerprint enabled")
	}
	if cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction != "block" {
		t.Fatalf("expected KnownBotsAction 'block', got %q", cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction)
	}
	if !cfg.WAF.BotDetection.UserAgent.BlockEmpty {
		t.Fatal("expected BlockEmpty true")
	}
	if cfg.WAF.BotDetection.Behavior.Window != 5*time.Minute {
		t.Fatalf("expected behavior window 5m, got %v", cfg.WAF.BotDetection.Behavior.Window)
	}
	if cfg.WAF.BotDetection.Behavior.RPSThreshold != 10 {
		t.Fatalf("expected RPSThreshold 10, got %d", cfg.WAF.BotDetection.Behavior.RPSThreshold)
	}

	// WAF Response
	if !cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Fatal("expected SecurityHeaders enabled")
	}
	if !cfg.WAF.Response.SecurityHeaders.HSTS.Enabled {
		t.Fatal("expected HSTS enabled")
	}
	if cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge != 31536000 {
		t.Fatalf("expected HSTS max_age 31536000, got %d", cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
	}
	if cfg.WAF.Response.SecurityHeaders.XFrameOptions != "SAMEORIGIN" {
		t.Fatalf("expected XFrameOptions 'SAMEORIGIN', got %q", cfg.WAF.Response.SecurityHeaders.XFrameOptions)
	}
	if !cfg.WAF.Response.DataMasking.Enabled {
		t.Fatal("expected DataMasking enabled")
	}
	if !cfg.WAF.Response.DataMasking.MaskCreditCards {
		t.Fatal("expected MaskCreditCards true")
	}
	if cfg.WAF.Response.ErrorPages.Mode != "production" {
		t.Fatalf("expected ErrorPages mode 'production', got %q", cfg.WAF.Response.ErrorPages.Mode)
	}

	// Dashboard
	if !cfg.Dashboard.Enabled {
		t.Fatal("expected Dashboard enabled")
	}
	if cfg.Dashboard.Listen != ":9443" {
		t.Fatalf("expected Dashboard listen ':9443', got %q", cfg.Dashboard.Listen)
	}
	if !cfg.Dashboard.TLS {
		t.Fatal("expected Dashboard TLS true")
	}

	// MCP
	if !cfg.MCP.Enabled {
		t.Fatal("expected MCP enabled")
	}
	if cfg.MCP.Transport != "stdio" {
		t.Fatalf("expected MCP transport 'stdio', got %q", cfg.MCP.Transport)
	}

	// Logging
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected logging level 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Fatalf("expected logging format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "stdout" {
		t.Fatalf("expected logging output 'stdout', got %q", cfg.Logging.Output)
	}
	if cfg.Logging.LogAllowed {
		t.Fatal("expected LogAllowed false")
	}
	if !cfg.Logging.LogBlocked {
		t.Fatal("expected LogBlocked true")
	}

	// Events
	if cfg.Events.Storage != "memory" {
		t.Fatalf("expected events storage 'memory', got %q", cfg.Events.Storage)
	}
	if cfg.Events.MaxEvents != 100000 {
		t.Fatalf("expected max_events 100000, got %d", cfg.Events.MaxEvents)
	}
	if cfg.Events.FilePath != "/var/log/guardianwaf/events.jsonl" {
		t.Fatalf("expected events file_path, got %q", cfg.Events.FilePath)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1s", 1 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", 1 * time.Hour},
		{"24h", 24 * time.Hour},
		{"100ms", 100 * time.Millisecond},
		{"1m30s", 1*time.Minute + 30*time.Second},
		{"500us", 500 * time.Microsecond},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := parseDuration(tt.input)
			if err != nil {
				t.Fatalf("parseDuration(%q) error: %v", tt.input, err)
			}
			if d != tt.expected {
				t.Fatalf("parseDuration(%q) = %v, want %v", tt.input, d, tt.expected)
			}
		})
	}

	// Error cases
	_, err := parseDuration("invalid")
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
}

func TestPopulateFromNode_Nil(t *testing.T) {
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, nil)
	if err != nil {
		t.Fatalf("expected no error for nil node, got: %v", err)
	}
	// Should be unchanged
	if cfg.Mode != "enforce" {
		t.Fatalf("expected mode unchanged, got %q", cfg.Mode)
	}
}

func TestPopulateFromNode_TopLevel(t *testing.T) {
	yaml := `mode: monitor
listen: ":9090"`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if cfg.Mode != "monitor" {
		t.Fatalf("expected mode 'monitor', got %q", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected listen ':9090', got %q", cfg.Listen)
	}
	// Unchanged defaults
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected logging level unchanged, got %q", cfg.Logging.Level)
	}
}

func TestPopulateFromNode_TLS(t *testing.T) {
	yaml := `tls:
  enabled: true
  listen: ":443"
  cert_file: /etc/ssl/cert.pem
  key_file: /etc/ssl/key.pem
  acme:
    enabled: true
    email: admin@example.com
    domains:
      - example.com
      - www.example.com
    cache_dir: /tmp/acme`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if !cfg.TLS.Enabled {
		t.Fatal("expected TLS enabled")
	}
	if cfg.TLS.Listen != ":443" {
		t.Fatalf("expected TLS listen ':443', got %q", cfg.TLS.Listen)
	}
	if cfg.TLS.CertFile != "/etc/ssl/cert.pem" {
		t.Fatalf("expected cert_file, got %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/ssl/key.pem" {
		t.Fatalf("expected key_file, got %q", cfg.TLS.KeyFile)
	}
	if !cfg.TLS.ACME.Enabled {
		t.Fatal("expected ACME enabled")
	}
	if cfg.TLS.ACME.Email != "admin@example.com" {
		t.Fatalf("expected email, got %q", cfg.TLS.ACME.Email)
	}
	if len(cfg.TLS.ACME.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(cfg.TLS.ACME.Domains))
	}
	if cfg.TLS.ACME.CacheDir != "/tmp/acme" {
		t.Fatalf("expected cache_dir, got %q", cfg.TLS.ACME.CacheDir)
	}
}

func TestPopulateFromNode_Upstreams(t *testing.T) {
	yaml := `upstreams:
  - name: backend
    load_balancer: round_robin
    targets:
      - url: http://localhost:3000
        weight: 3
      - url: http://localhost:3001
        weight: 1
    health_check:
      enabled: true
      interval: 30s
      timeout: 5s
      path: /health`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if len(cfg.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
	u := cfg.Upstreams[0]
	if u.Name != "backend" {
		t.Fatalf("expected name 'backend', got %q", u.Name)
	}
	if u.LoadBalancer != "round_robin" {
		t.Fatalf("expected load_balancer 'round_robin', got %q", u.LoadBalancer)
	}
	if len(u.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(u.Targets))
	}
	if u.Targets[0].URL != "http://localhost:3000" {
		t.Fatalf("expected target URL, got %q", u.Targets[0].URL)
	}
	if u.Targets[0].Weight != 3 {
		t.Fatalf("expected weight 3, got %d", u.Targets[0].Weight)
	}
	if !u.HealthCheck.Enabled {
		t.Fatal("expected health check enabled")
	}
	if u.HealthCheck.Interval != 30*time.Second {
		t.Fatalf("expected interval 30s, got %v", u.HealthCheck.Interval)
	}
	if u.HealthCheck.Path != "/health" {
		t.Fatalf("expected path '/health', got %q", u.HealthCheck.Path)
	}
}

func TestPopulateFromNode_Routes(t *testing.T) {
	yaml := `routes:
  - path: /api
    upstream: backend
    strip_prefix: true
    methods: [GET, POST]
  - path: /static
    upstream: cdn
    strip_prefix: false`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if len(cfg.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(cfg.Routes))
	}
	r := cfg.Routes[0]
	if r.Path != "/api" {
		t.Fatalf("expected path '/api', got %q", r.Path)
	}
	if r.Upstream != "backend" {
		t.Fatalf("expected upstream 'backend', got %q", r.Upstream)
	}
	if !r.StripPrefix {
		t.Fatal("expected strip_prefix true")
	}
	if len(r.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(r.Methods))
	}
	if r.Methods[0] != "GET" || r.Methods[1] != "POST" {
		t.Fatalf("expected [GET, POST], got %v", r.Methods)
	}
}

func TestPopulateFromNode_WAF(t *testing.T) {
	yaml := `waf:
  ip_acl:
    enabled: false
    whitelist:
      - 10.0.0.0/8
      - 192.168.0.0/16
    blacklist:
      - 1.2.3.4
    auto_ban:
      enabled: false
      default_ttl: 30m
      max_ttl: 12h
  rate_limit:
    enabled: true
    rules:
      - id: api
        scope: ip+path
        paths:
          - /api
        limit: 100
        window: 1m
        burst: 20
        action: log
        auto_ban_after: 5
  sanitizer:
    enabled: true
    max_url_length: 4096
    max_body_size: 5242880
    allowed_methods: [GET, POST]
    path_overrides:
      - path: /upload
        max_body_size: 104857600
  detection:
    enabled: true
    threshold:
      block: 75
      log: 30
    detectors:
      sqli:
        enabled: true
        multiplier: 1.5
      xss:
        enabled: false
        multiplier: 0.5
    exclusions:
      - path: /webhook
        detectors: [sqli, xss]
        reason: trusted endpoint
  bot_detection:
    enabled: false
    mode: enforce
    tls_fingerprint:
      enabled: false
      known_bots_action: log
    user_agent:
      enabled: false
      block_empty: false
    behavior:
      enabled: false
      window: 10m
      rps_threshold: 50
      error_rate_threshold: 50
  response:
    security_headers:
      enabled: false
      hsts:
        enabled: false
        max_age: 86400
        include_subdomains: false
      x_content_type_options: false
      x_frame_options: DENY
      referrer_policy: no-referrer
      permissions_policy: ""
    data_masking:
      enabled: false
    error_pages:
      enabled: false
      mode: development`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	// IPACL
	if cfg.WAF.IPACL.Enabled {
		t.Fatal("expected IPACL disabled")
	}
	if len(cfg.WAF.IPACL.Whitelist) != 2 {
		t.Fatalf("expected 2 whitelist, got %d", len(cfg.WAF.IPACL.Whitelist))
	}
	if cfg.WAF.IPACL.Whitelist[0] != "10.0.0.0/8" {
		t.Fatalf("expected whitelist entry, got %q", cfg.WAF.IPACL.Whitelist[0])
	}
	if len(cfg.WAF.IPACL.Blacklist) != 1 {
		t.Fatalf("expected 1 blacklist, got %d", len(cfg.WAF.IPACL.Blacklist))
	}
	if cfg.WAF.IPACL.AutoBan.Enabled {
		t.Fatal("expected AutoBan disabled")
	}
	if cfg.WAF.IPACL.AutoBan.DefaultTTL != 30*time.Minute {
		t.Fatalf("expected DefaultTTL 30m, got %v", cfg.WAF.IPACL.AutoBan.DefaultTTL)
	}
	if cfg.WAF.IPACL.AutoBan.MaxTTL != 12*time.Hour {
		t.Fatalf("expected MaxTTL 12h, got %v", cfg.WAF.IPACL.AutoBan.MaxTTL)
	}

	// RateLimit
	if len(cfg.WAF.RateLimit.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.WAF.RateLimit.Rules))
	}
	rlRule := cfg.WAF.RateLimit.Rules[0]
	if rlRule.ID != "api" {
		t.Fatalf("expected rule ID 'api', got %q", rlRule.ID)
	}
	if rlRule.Scope != "ip+path" {
		t.Fatalf("expected scope 'ip+path', got %q", rlRule.Scope)
	}
	if len(rlRule.Paths) != 1 || rlRule.Paths[0] != "/api" {
		t.Fatalf("expected paths [/api], got %v", rlRule.Paths)
	}
	if rlRule.Limit != 100 {
		t.Fatalf("expected limit 100, got %d", rlRule.Limit)
	}
	if rlRule.Window != 1*time.Minute {
		t.Fatalf("expected window 1m, got %v", rlRule.Window)
	}
	if rlRule.AutoBanAfter != 5 {
		t.Fatalf("expected auto_ban_after 5, got %d", rlRule.AutoBanAfter)
	}

	// Sanitizer
	if cfg.WAF.Sanitizer.MaxURLLength != 4096 {
		t.Fatalf("expected MaxURLLength 4096, got %d", cfg.WAF.Sanitizer.MaxURLLength)
	}
	if cfg.WAF.Sanitizer.MaxBodySize != 5242880 {
		t.Fatalf("expected MaxBodySize 5242880, got %d", cfg.WAF.Sanitizer.MaxBodySize)
	}
	if len(cfg.WAF.Sanitizer.AllowedMethods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(cfg.WAF.Sanitizer.AllowedMethods))
	}
	if len(cfg.WAF.Sanitizer.PathOverrides) != 1 {
		t.Fatalf("expected 1 path override, got %d", len(cfg.WAF.Sanitizer.PathOverrides))
	}
	if cfg.WAF.Sanitizer.PathOverrides[0].Path != "/upload" {
		t.Fatalf("expected path '/upload', got %q", cfg.WAF.Sanitizer.PathOverrides[0].Path)
	}
	if cfg.WAF.Sanitizer.PathOverrides[0].MaxBodySize != 104857600 {
		t.Fatalf("expected MaxBodySize 104857600, got %d", cfg.WAF.Sanitizer.PathOverrides[0].MaxBodySize)
	}

	// Detection
	if cfg.WAF.Detection.Threshold.Block != 75 {
		t.Fatalf("expected block threshold 75, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.WAF.Detection.Threshold.Log != 30 {
		t.Fatalf("expected log threshold 30, got %d", cfg.WAF.Detection.Threshold.Log)
	}
	sqli := cfg.WAF.Detection.Detectors["sqli"]
	if !sqli.Enabled {
		t.Fatal("expected sqli enabled")
	}
	if sqli.Multiplier != 1.5 {
		t.Fatalf("expected sqli multiplier 1.5, got %f", sqli.Multiplier)
	}
	xss := cfg.WAF.Detection.Detectors["xss"]
	if xss.Enabled {
		t.Fatal("expected xss disabled")
	}
	if xss.Multiplier != 0.5 {
		t.Fatalf("expected xss multiplier 0.5, got %f", xss.Multiplier)
	}
	if len(cfg.WAF.Detection.Exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(cfg.WAF.Detection.Exclusions))
	}
	if cfg.WAF.Detection.Exclusions[0].Path != "/webhook" {
		t.Fatalf("expected exclusion path '/webhook', got %q", cfg.WAF.Detection.Exclusions[0].Path)
	}
	if len(cfg.WAF.Detection.Exclusions[0].Detectors) != 2 {
		t.Fatalf("expected 2 excluded detectors, got %d", len(cfg.WAF.Detection.Exclusions[0].Detectors))
	}
	if cfg.WAF.Detection.Exclusions[0].Reason != "trusted endpoint" {
		t.Fatalf("expected reason 'trusted endpoint', got %q", cfg.WAF.Detection.Exclusions[0].Reason)
	}

	// BotDetection
	if cfg.WAF.BotDetection.Enabled {
		t.Fatal("expected BotDetection disabled")
	}
	if cfg.WAF.BotDetection.Mode != "enforce" {
		t.Fatalf("expected mode 'enforce', got %q", cfg.WAF.BotDetection.Mode)
	}
	if cfg.WAF.BotDetection.TLSFingerprint.Enabled {
		t.Fatal("expected TLSFingerprint disabled")
	}
	if cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction != "log" {
		t.Fatalf("expected known_bots_action 'log', got %q", cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction)
	}
	if cfg.WAF.BotDetection.Behavior.Window != 10*time.Minute {
		t.Fatalf("expected behavior window 10m, got %v", cfg.WAF.BotDetection.Behavior.Window)
	}
	if cfg.WAF.BotDetection.Behavior.RPSThreshold != 50 {
		t.Fatalf("expected RPSThreshold 50, got %d", cfg.WAF.BotDetection.Behavior.RPSThreshold)
	}

	// Response
	if cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Fatal("expected SecurityHeaders disabled")
	}
	if cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge != 86400 {
		t.Fatalf("expected HSTS max_age 86400, got %d", cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
	}
	if cfg.WAF.Response.SecurityHeaders.XFrameOptions != "DENY" {
		t.Fatalf("expected XFrameOptions 'DENY', got %q", cfg.WAF.Response.SecurityHeaders.XFrameOptions)
	}
	if cfg.WAF.Response.SecurityHeaders.ReferrerPolicy != "no-referrer" {
		t.Fatalf("expected referrer_policy 'no-referrer', got %q", cfg.WAF.Response.SecurityHeaders.ReferrerPolicy)
	}
	if cfg.WAF.Response.ErrorPages.Mode != "development" {
		t.Fatalf("expected error_pages mode 'development', got %q", cfg.WAF.Response.ErrorPages.Mode)
	}
}

func TestPopulateFromNode_Logging(t *testing.T) {
	yaml := `logging:
  level: debug
  format: text
  output: /var/log/waf.log
  log_allowed: true
  log_blocked: false
  log_body: true`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if cfg.Logging.Level != "debug" {
		t.Fatalf("expected level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Fatalf("expected format 'text', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/waf.log" {
		t.Fatalf("expected output path, got %q", cfg.Logging.Output)
	}
	if !cfg.Logging.LogAllowed {
		t.Fatal("expected log_allowed true")
	}
	if cfg.Logging.LogBlocked {
		t.Fatal("expected log_blocked false")
	}
	if !cfg.Logging.LogBody {
		t.Fatal("expected log_body true")
	}
}

func TestPopulateFromNode_Events(t *testing.T) {
	yaml := `events:
  storage: file
  max_events: 50000
  file_path: /tmp/events.jsonl`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if cfg.Events.Storage != "file" {
		t.Fatalf("expected storage 'file', got %q", cfg.Events.Storage)
	}
	if cfg.Events.MaxEvents != 50000 {
		t.Fatalf("expected max_events 50000, got %d", cfg.Events.MaxEvents)
	}
	if cfg.Events.FilePath != "/tmp/events.jsonl" {
		t.Fatalf("expected file_path, got %q", cfg.Events.FilePath)
	}
}

func TestPopulateFromNode_Dashboard(t *testing.T) {
	yaml := `dashboard:
  enabled: false
  listen: ":8443"
  api_key: secret123
  tls: false`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if cfg.Dashboard.Enabled {
		t.Fatal("expected dashboard disabled")
	}
	if cfg.Dashboard.Listen != ":8443" {
		t.Fatalf("expected listen ':8443', got %q", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.APIKey != "secret123" {
		t.Fatalf("expected api_key 'secret123', got %q", cfg.Dashboard.APIKey)
	}
	if cfg.Dashboard.TLS {
		t.Fatal("expected TLS false")
	}
}

func TestPopulateFromNode_MCP(t *testing.T) {
	yaml := `mcp:
  enabled: false
  transport: sse`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if cfg.MCP.Enabled {
		t.Fatal("expected MCP disabled")
	}
	if cfg.MCP.Transport != "sse" {
		t.Fatalf("expected transport 'sse', got %q", cfg.MCP.Transport)
	}
}

func TestPopulateFromNode_FullConfig(t *testing.T) {
	// Test a realistic full configuration similar to what guardianwaf.yaml would contain
	yaml := `mode: monitor
listen: ":80"
tls:
  enabled: true
  listen: ":443"
  cert_file: /etc/ssl/cert.pem
  key_file: /etc/ssl/key.pem
upstreams:
  - name: api
    load_balancer: least_conn
    targets:
      - url: http://api1:8080
        weight: 2
      - url: http://api2:8080
        weight: 1
    health_check:
      enabled: true
      interval: 10s
      timeout: 3s
      path: /healthz
routes:
  - path: /api
    upstream: api
    strip_prefix: true
    methods: [GET, POST, PUT, DELETE]
waf:
  detection:
    enabled: true
    threshold:
      block: 100
      log: 50
logging:
  level: warn
  format: json
  output: stderr
events:
  storage: file
  max_events: 200000
  file_path: /var/log/guardianwaf/events.jsonl`

	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	// Check overridden values
	if cfg.Mode != "monitor" {
		t.Fatalf("expected mode 'monitor', got %q", cfg.Mode)
	}
	if cfg.Listen != ":80" {
		t.Fatalf("expected listen ':80', got %q", cfg.Listen)
	}
	if !cfg.TLS.Enabled {
		t.Fatal("expected TLS enabled")
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(cfg.Upstreams))
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.WAF.Detection.Threshold.Block != 100 {
		t.Fatalf("expected block threshold 100, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.Logging.Level != "warn" {
		t.Fatalf("expected logging level 'warn', got %q", cfg.Logging.Level)
	}
	if cfg.Events.MaxEvents != 200000 {
		t.Fatalf("expected max_events 200000, got %d", cfg.Events.MaxEvents)
	}

	// Check that non-overridden defaults are preserved
	if !cfg.WAF.Sanitizer.Enabled {
		t.Fatal("expected sanitizer still enabled (default)")
	}
	if cfg.WAF.Sanitizer.MaxURLLength != 8192 {
		t.Fatalf("expected MaxURLLength 8192 (default), got %d", cfg.WAF.Sanitizer.MaxURLLength)
	}
	if !cfg.Dashboard.Enabled {
		t.Fatal("expected dashboard still enabled (default)")
	}
	if !cfg.MCP.Enabled {
		t.Fatal("expected MCP still enabled (default)")
	}
}

func TestNodeStringSlice_SingleScalar(t *testing.T) {
	// When a YAML value is a single scalar, nodeStringSlice should treat it as
	// a single-element slice for convenience.
	n := &Node{Kind: ScalarNode, Value: "GET"}
	result := nodeStringSlice(n)
	if len(result) != 1 || result[0] != "GET" {
		t.Fatalf("expected [GET], got %v", result)
	}
}

func TestNodeStringSlice_Nil(t *testing.T) {
	result := nodeStringSlice(nil)
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}
