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
	if cfg.Listen != ":8088" {
		t.Fatalf("expected listen ':8088', got %q", cfg.Listen)
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
      - url: http://api1:8088
        weight: 2
      - url: http://api2:8088
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

// --- Additional tests for uncovered PopulateFromNode paths ---

func TestPopulateFromNode_NonMapRoot(t *testing.T) {
	// If root node is a scalar, PopulateFromNode should return nil (no error)
	node := &Node{Kind: ScalarNode, Value: "hello"}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err != nil {
		t.Fatalf("expected no error for scalar root node, got: %v", err)
	}
}

func TestPopulateFromNode_SanitizerFull(t *testing.T) {
	yaml := `waf:
  sanitizer:
    enabled: true
    max_url_length: 2048
    max_header_size: 4096
    max_header_count: 50
    max_body_size: 1048576
    max_cookie_size: 2048
    block_null_bytes: false
    normalize_encoding: false
    strip_hop_by_hop: false
    allowed_methods: [GET, POST, PUT]
    path_overrides:
      - path: /upload
        max_body_size: 52428800
      - path: /large
        max_body_size: 104857600`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	if cfg.WAF.Sanitizer.MaxURLLength != 2048 {
		t.Fatalf("expected MaxURLLength 2048, got %d", cfg.WAF.Sanitizer.MaxURLLength)
	}
	if cfg.WAF.Sanitizer.MaxHeaderSize != 4096 {
		t.Fatalf("expected MaxHeaderSize 4096, got %d", cfg.WAF.Sanitizer.MaxHeaderSize)
	}
	if cfg.WAF.Sanitizer.MaxHeaderCount != 50 {
		t.Fatalf("expected MaxHeaderCount 50, got %d", cfg.WAF.Sanitizer.MaxHeaderCount)
	}
	if cfg.WAF.Sanitizer.MaxBodySize != 1048576 {
		t.Fatalf("expected MaxBodySize 1048576, got %d", cfg.WAF.Sanitizer.MaxBodySize)
	}
	if cfg.WAF.Sanitizer.MaxCookieSize != 2048 {
		t.Fatalf("expected MaxCookieSize 2048, got %d", cfg.WAF.Sanitizer.MaxCookieSize)
	}
	if cfg.WAF.Sanitizer.BlockNullBytes {
		t.Fatal("expected BlockNullBytes false")
	}
	if cfg.WAF.Sanitizer.NormalizeEncoding {
		t.Fatal("expected NormalizeEncoding false")
	}
	if cfg.WAF.Sanitizer.StripHopByHop {
		t.Fatal("expected StripHopByHop false")
	}
	if len(cfg.WAF.Sanitizer.AllowedMethods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(cfg.WAF.Sanitizer.AllowedMethods))
	}
	if len(cfg.WAF.Sanitizer.PathOverrides) != 2 {
		t.Fatalf("expected 2 path overrides, got %d", len(cfg.WAF.Sanitizer.PathOverrides))
	}
}

func TestPopulateFromNode_DataMaskingFull(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      enabled: true
      mask_credit_cards: false
      mask_ssn: false
      mask_api_keys: false
      strip_stack_traces: false`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	if !cfg.WAF.Response.DataMasking.Enabled {
		t.Fatal("expected DataMasking enabled")
	}
	if cfg.WAF.Response.DataMasking.MaskCreditCards {
		t.Fatal("expected MaskCreditCards false")
	}
	if cfg.WAF.Response.DataMasking.MaskSSN {
		t.Fatal("expected MaskSSN false")
	}
	if cfg.WAF.Response.DataMasking.MaskAPIKeys {
		t.Fatal("expected MaskAPIKeys false")
	}
	if cfg.WAF.Response.DataMasking.StripStackTraces {
		t.Fatal("expected StripStackTraces false")
	}
}

func TestPopulateFromNode_SecurityHeadersFull(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 7200
        include_subdomains: true
      x_content_type_options: true
      x_frame_options: DENY
      referrer_policy: no-referrer
      permissions_policy: "camera=()"`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	if !cfg.WAF.Response.SecurityHeaders.Enabled {
		t.Fatal("expected SecurityHeaders enabled")
	}
	if cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge != 7200 {
		t.Fatalf("expected HSTS max_age 7200, got %d", cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
	}
	if cfg.WAF.Response.SecurityHeaders.PermissionsPolicy != "camera=()" {
		t.Fatalf("expected permissions_policy, got %q", cfg.WAF.Response.SecurityHeaders.PermissionsPolicy)
	}
}

func TestPopulateFromNode_BotDetectionUserAgentAll(t *testing.T) {
	yaml := `waf:
  bot_detection:
    enabled: true
    mode: monitor
    user_agent:
      enabled: true
      block_empty: false
      block_known_scanners: false
    tls_fingerprint:
      enabled: true
      known_bots_action: block
      unknown_action: pass
      mismatch_action: block
    behavior:
      enabled: true
      window: 2m
      rps_threshold: 20
      error_rate_threshold: 40`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	if cfg.WAF.BotDetection.UserAgent.BlockEmpty {
		t.Fatal("expected block_empty false")
	}
	if cfg.WAF.BotDetection.UserAgent.BlockKnownScanners {
		t.Fatal("expected block_known_scanners false")
	}
	if cfg.WAF.BotDetection.TLSFingerprint.UnknownAction != "pass" {
		t.Fatalf("expected unknown_action 'pass', got %q", cfg.WAF.BotDetection.TLSFingerprint.UnknownAction)
	}
	if cfg.WAF.BotDetection.TLSFingerprint.MismatchAction != "block" {
		t.Fatalf("expected mismatch_action 'block', got %q", cfg.WAF.BotDetection.TLSFingerprint.MismatchAction)
	}
	if cfg.WAF.BotDetection.Behavior.ErrorRateThreshold != 40 {
		t.Fatalf("expected error_rate_threshold 40, got %d", cfg.WAF.BotDetection.Behavior.ErrorRateThreshold)
	}
}

// --- Node conversion helper edge cases ---

func TestNodeBool_Null(t *testing.T) {
	b, err := nodeBool(nil)
	if err != nil {
		t.Fatalf("expected no error for nil nodeBool, got: %v", err)
	}
	if b {
		t.Fatal("expected false for nil nodeBool")
	}

	n := &Node{Kind: ScalarNode, IsNull: true}
	b, err = nodeBool(n)
	if err != nil {
		t.Fatalf("expected no error for null nodeBool, got: %v", err)
	}
	if b {
		t.Fatal("expected false for null nodeBool")
	}
}

func TestNodeInt_Null(t *testing.T) {
	i, err := nodeInt(nil)
	if err != nil {
		t.Fatalf("expected no error for nil nodeInt, got: %v", err)
	}
	if i != 0 {
		t.Fatalf("expected 0 for nil nodeInt, got %d", i)
	}

	n := &Node{Kind: ScalarNode, IsNull: true}
	i, err = nodeInt(n)
	if err != nil {
		t.Fatalf("expected no error for null nodeInt, got: %v", err)
	}
	if i != 0 {
		t.Fatalf("expected 0 for null nodeInt, got %d", i)
	}
}

func TestNodeInt64_Null(t *testing.T) {
	i, err := nodeInt64(nil)
	if err != nil {
		t.Fatalf("expected no error for nil nodeInt64, got: %v", err)
	}
	if i != 0 {
		t.Fatalf("expected 0 for nil nodeInt64, got %d", i)
	}

	n := &Node{Kind: ScalarNode, IsNull: true}
	i, err = nodeInt64(n)
	if err != nil {
		t.Fatalf("expected no error for null nodeInt64, got: %v", err)
	}
	if i != 0 {
		t.Fatalf("expected 0 for null nodeInt64, got %d", i)
	}
}

func TestNodeInt64_NonScalar(t *testing.T) {
	n := &Node{Kind: MapNode}
	_, err := nodeInt64(n)
	if err == nil {
		t.Fatal("expected error for non-scalar nodeInt64")
	}
}

func TestNodeFloat64_Null(t *testing.T) {
	f, err := nodeFloat64(nil)
	if err != nil {
		t.Fatalf("expected no error for nil nodeFloat64, got: %v", err)
	}
	if f != 0 {
		t.Fatalf("expected 0 for nil nodeFloat64, got %f", f)
	}

	n := &Node{Kind: ScalarNode, IsNull: true}
	f, err = nodeFloat64(n)
	if err != nil {
		t.Fatalf("expected no error for null nodeFloat64, got: %v", err)
	}
	if f != 0 {
		t.Fatalf("expected 0 for null nodeFloat64, got %f", f)
	}
}

func TestNodeStringSlice_NullScalar(t *testing.T) {
	// Scalar with empty value should return nil
	n := &Node{Kind: ScalarNode, Value: "", IsNull: true}
	result := nodeStringSlice(n)
	if result != nil {
		t.Fatalf("expected nil for null scalar, got %v", result)
	}
}

func TestNodeStringSlice_EmptyScalar(t *testing.T) {
	// Scalar with empty string but not null
	n := &Node{Kind: ScalarNode, Value: ""}
	result := nodeStringSlice(n)
	if result != nil {
		t.Fatalf("expected nil for empty scalar, got %v", result)
	}
}

func TestPopulateFromNode_WAFNonMap(t *testing.T) {
	// WAF section that is a scalar instead of a map
	yaml := `waf: disabled`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	// Should not error - populateWAF returns nil for non-map
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPopulateFromNode_TLSNonMap(t *testing.T) {
	yaml := `tls: disabled`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Error path tests for populate functions ---

func TestPopulateFromNode_TLSError(t *testing.T) {
	// enabled is not a valid bool
	node := &Node{Kind: MapNode, MapKeys: []string{"tls"}, MapItems: map[string]*Node{
		"tls": {Kind: MapNode, MapKeys: []string{"enabled"}, MapItems: map[string]*Node{
			"enabled": {Kind: ScalarNode, Value: "notabool"},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid TLS enabled value")
	}
}

func TestPopulateFromNode_UpstreamsError(t *testing.T) {
	// weight is not a valid int
	node := &Node{Kind: MapNode, MapKeys: []string{"upstreams"}, MapItems: map[string]*Node{
		"upstreams": {Kind: SequenceNode, Items: []*Node{
			{Kind: MapNode, MapKeys: []string{"name", "targets"}, MapItems: map[string]*Node{
				"name": {Kind: ScalarNode, Value: "test"},
				"targets": {Kind: SequenceNode, Items: []*Node{
					{Kind: MapNode, MapKeys: []string{"url", "weight"}, MapItems: map[string]*Node{
						"url":    {Kind: ScalarNode, Value: "http://localhost"},
						"weight": {Kind: ScalarNode, Value: "notanint"},
					}},
				}},
			}},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid upstream weight")
	}
}

func TestPopulateFromNode_RoutesError(t *testing.T) {
	// strip_prefix is not a valid bool
	node := &Node{Kind: MapNode, MapKeys: []string{"routes"}, MapItems: map[string]*Node{
		"routes": {Kind: SequenceNode, Items: []*Node{
			{Kind: MapNode, MapKeys: []string{"path", "upstream", "strip_prefix"}, MapItems: map[string]*Node{
				"path":         {Kind: ScalarNode, Value: "/api"},
				"upstream":     {Kind: ScalarNode, Value: "backend"},
				"strip_prefix": {Kind: ScalarNode, Value: "notabool"},
			}},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid route strip_prefix value")
	}
}

func TestPopulateFromNode_WAFError(t *testing.T) {
	// ip_acl enabled is not a valid bool
	node := &Node{Kind: MapNode, MapKeys: []string{"waf"}, MapItems: map[string]*Node{
		"waf": {Kind: MapNode, MapKeys: []string{"ip_acl"}, MapItems: map[string]*Node{
			"ip_acl": {Kind: MapNode, MapKeys: []string{"enabled"}, MapItems: map[string]*Node{
				"enabled": {Kind: ScalarNode, Value: "notabool"},
			}},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid WAF ip_acl enabled")
	}
}

func TestPopulateFromNode_DashboardError(t *testing.T) {
	node := &Node{Kind: MapNode, MapKeys: []string{"dashboard"}, MapItems: map[string]*Node{
		"dashboard": {Kind: MapNode, MapKeys: []string{"enabled"}, MapItems: map[string]*Node{
			"enabled": {Kind: ScalarNode, Value: "notabool"},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid dashboard enabled")
	}
}

func TestPopulateFromNode_MCPError(t *testing.T) {
	node := &Node{Kind: MapNode, MapKeys: []string{"mcp"}, MapItems: map[string]*Node{
		"mcp": {Kind: MapNode, MapKeys: []string{"enabled"}, MapItems: map[string]*Node{
			"enabled": {Kind: ScalarNode, Value: "notabool"},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid mcp enabled")
	}
}

func TestPopulateFromNode_LoggingError(t *testing.T) {
	node := &Node{Kind: MapNode, MapKeys: []string{"logging"}, MapItems: map[string]*Node{
		"logging": {Kind: MapNode, MapKeys: []string{"log_allowed"}, MapItems: map[string]*Node{
			"log_allowed": {Kind: ScalarNode, Value: "notabool"},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid logging log_allowed")
	}
}

func TestPopulateFromNode_EventsError(t *testing.T) {
	node := &Node{Kind: MapNode, MapKeys: []string{"events"}, MapItems: map[string]*Node{
		"events": {Kind: MapNode, MapKeys: []string{"max_events"}, MapItems: map[string]*Node{
			"max_events": {Kind: ScalarNode, Value: "notanint"},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid events max_events")
	}
}

func TestPopulateFromNode_RateLimitError(t *testing.T) {
	// Rule with invalid limit
	yaml := `waf:
  rate_limit:
    enabled: true
    rules:
      - id: test
        scope: ip
        limit: notanumber
        window: 1m
        action: block`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid rate limit")
	}
}

func TestPopulateFromNode_DetectionError(t *testing.T) {
	// Detector with invalid multiplier
	yaml := `waf:
  detection:
    enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid detection enabled")
	}
}

func TestPopulateFromNode_BotDetectionError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid bot_detection enabled")
	}
}

func TestPopulateFromNode_ResponseError(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid response security_headers enabled")
	}
}

func TestPopulateFromNode_HealthCheckError(t *testing.T) {
	yaml := `upstreams:
  - name: test
    targets:
      - url: http://localhost:3000
        weight: 1
    health_check:
      interval: invalid_duration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid health_check interval")
	}
}

func TestPopulateFromNode_ACMEError(t *testing.T) {
	node := &Node{Kind: MapNode, MapKeys: []string{"tls"}, MapItems: map[string]*Node{
		"tls": {Kind: MapNode, MapKeys: []string{"acme"}, MapItems: map[string]*Node{
			"acme": {Kind: MapNode, MapKeys: []string{"enabled"}, MapItems: map[string]*Node{
				"enabled": {Kind: ScalarNode, Value: "notabool"},
			}},
		}},
	}}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid acme enabled")
	}
}

func TestPopulateFromNode_SanitizerError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    max_url_length: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer max_url_length")
	}
}

func TestPopulateFromNode_IPACLAutobanError(t *testing.T) {
	yaml := `waf:
  ip_acl:
    auto_ban:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid auto_ban enabled")
	}
}

func TestPopulateFromNode_DataMaskingError(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid data_masking enabled")
	}
}

func TestPopulateFromNode_ErrorPagesError(t *testing.T) {
	yaml := `waf:
  response:
    error_pages:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid error_pages enabled")
	}
}

func TestPopulateFromNode_HealthCheckTimeoutError(t *testing.T) {
	yaml := `upstreams:
  - name: test
    targets:
      - url: http://localhost:3000
        weight: 1
    health_check:
      timeout: bad_duration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid health_check timeout")
	}
}

func TestPopulateFromNode_RateLimitBurstError(t *testing.T) {
	yaml := `waf:
  rate_limit:
    rules:
      - id: test
        scope: ip
        limit: 100
        window: 1m
        burst: notanint
        action: block`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid burst")
	}
}

func TestPopulateFromNode_RateLimitWindowError(t *testing.T) {
	yaml := `waf:
  rate_limit:
    rules:
      - id: test
        scope: ip
        limit: 100
        window: bad_duration
        action: block`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid window duration")
	}
}

func TestPopulateFromNode_RateLimitAutobanError(t *testing.T) {
	yaml := `waf:
  rate_limit:
    rules:
      - id: test
        scope: ip
        limit: 100
        window: 1m
        action: block
        auto_ban_after: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid auto_ban_after")
	}
}

func TestPopulateFromNode_DetectionDetectorError(t *testing.T) {
	yaml := `waf:
  detection:
    detectors:
      sqli:
        enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid detector enabled")
	}
}

func TestPopulateFromNode_DetectionMultiplierError(t *testing.T) {
	yaml := `waf:
  detection:
    detectors:
      sqli:
        enabled: true
        multiplier: notafloat`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid detector multiplier")
	}
}

func TestPopulateFromNode_DetectionThresholdError(t *testing.T) {
	yaml := `waf:
  detection:
    threshold:
      block: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid detection threshold block")
	}
}

func TestPopulateFromNode_BotDetectionBehaviorWindowError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    behavior:
      window: bad_duration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid behavior window")
	}
}

func TestPopulateFromNode_BotDetectionBehaviorRPSError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    behavior:
      rps_threshold: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid behavior rps_threshold")
	}
}

func TestPopulateFromNode_BotDetectionBehaviorErrorRateError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    behavior:
      error_rate_threshold: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid behavior error_rate_threshold")
	}
}

func TestPopulateFromNode_BotDetectionUAError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    user_agent:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid user_agent enabled")
	}
}

func TestPopulateFromNode_BotDetectionTLSError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    tls_fingerprint:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid tls_fingerprint enabled")
	}
}

func TestPopulateFromNode_SecurityHeadersHSTSError(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      hsts:
        enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid hsts enabled")
	}
}

func TestPopulateFromNode_SecurityHeadersXCTOError(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      x_content_type_options: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid x_content_type_options")
	}
}

func TestPopulateFromNode_DashboardTLSError(t *testing.T) {
	yaml := `dashboard:
  tls: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid dashboard tls")
	}
}

func TestPopulateFromNode_LoggingLogBlockedError(t *testing.T) {
	yaml := `logging:
  log_blocked: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid logging log_blocked")
	}
}

func TestPopulateFromNode_LoggingLogBodyError(t *testing.T) {
	yaml := `logging:
  log_body: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid logging log_body")
	}
}

func TestPopulateFromNode_IPACLAutobanDefaultTTLError(t *testing.T) {
	yaml := `waf:
  ip_acl:
    auto_ban:
      default_ttl: bad_duration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid auto_ban default_ttl")
	}
}

func TestPopulateFromNode_IPACLAutobanMaxTTLError(t *testing.T) {
	yaml := `waf:
  ip_acl:
    auto_ban:
      max_ttl: bad_duration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid auto_ban max_ttl")
	}
}

func TestPopulateFromNode_SanitizerMaxHeaderSizeError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    max_header_size: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer max_header_size")
	}
}

func TestPopulateFromNode_SanitizerMaxHeaderCountError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    max_header_count: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer max_header_count")
	}
}

func TestPopulateFromNode_SanitizerMaxBodySizeError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    max_body_size: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer max_body_size")
	}
}

func TestPopulateFromNode_SanitizerMaxCookieSizeError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    max_cookie_size: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer max_cookie_size")
	}
}

func TestPopulateFromNode_SanitizerBlockNullBytesError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    block_null_bytes: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer block_null_bytes")
	}
}

func TestPopulateFromNode_SanitizerNormalizeEncodingError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    normalize_encoding: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer normalize_encoding")
	}
}

func TestPopulateFromNode_SanitizerStripHopByHopError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    strip_hop_by_hop: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer strip_hop_by_hop")
	}
}

func TestPopulateFromNode_SanitizerPathOverrideError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    path_overrides:
      - path: /upload
        max_body_size: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid path_override max_body_size")
	}
}

func TestPopulateFromNode_BotDetectionUABlockEmptyError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    user_agent:
      block_empty: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid user_agent block_empty")
	}
}

func TestPopulateFromNode_BotDetectionUABlockScannersError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    user_agent:
      block_known_scanners: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid user_agent block_known_scanners")
	}
}

func TestPopulateFromNode_SecurityHeadersHSTSMaxAgeError(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      hsts:
        max_age: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid hsts max_age")
	}
}

func TestPopulateFromNode_SecurityHeadersHSTSSubdomainsError(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      hsts:
        include_subdomains: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid hsts include_subdomains")
	}
}

func TestPopulateFromNode_DataMaskingCreditCardsError(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      mask_credit_cards: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid mask_credit_cards")
	}
}

func TestPopulateFromNode_DataMaskingSSNError(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      mask_ssn: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid mask_ssn")
	}
}

func TestPopulateFromNode_DataMaskingAPIKeysError(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      mask_api_keys: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid mask_api_keys")
	}
}

func TestPopulateFromNode_DataMaskingStripStackTracesError(t *testing.T) {
	yaml := `waf:
  response:
    data_masking:
      strip_stack_traces: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid strip_stack_traces")
	}
}

func TestPopulateFromNode_DetectionThresholdLogError(t *testing.T) {
	yaml := `waf:
  detection:
    threshold:
      log: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid detection threshold log")
	}
}

func TestPopulateFromNode_HealthCheckEnabledError(t *testing.T) {
	yaml := `upstreams:
  - name: test
    targets:
      - url: http://localhost:3000
        weight: 1
    health_check:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid health_check enabled")
	}
}

func TestPopulateFromNode_RateLimitEnabledError(t *testing.T) {
	yaml := `waf:
  rate_limit:
    enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid rate_limit enabled")
	}
}

func TestPopulateFromNode_SanitizerEnabledError(t *testing.T) {
	yaml := `waf:
  sanitizer:
    enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid sanitizer enabled")
	}
}

func TestPopulateFromNode_BotDetectionBehaviorEnabledError(t *testing.T) {
	yaml := `waf:
  bot_detection:
    behavior:
      enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid behavior enabled")
	}
}

// --- Coverage-targeted tests for populate* functions ---

func TestPopulateFromNode_ACMEAllFields(t *testing.T) {
	yaml := `tls:
  enabled: true
  listen: ":9443"
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
	if cfg.TLS.Listen != ":9443" {
		t.Fatalf("expected :9443, got %q", cfg.TLS.Listen)
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
		t.Fatalf("expected admin@example.com, got %q", cfg.TLS.ACME.Email)
	}
	if len(cfg.TLS.ACME.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(cfg.TLS.ACME.Domains))
	}
	if cfg.TLS.ACME.Domains[0] != "example.com" {
		t.Fatalf("expected example.com, got %q", cfg.TLS.ACME.Domains[0])
	}
	if cfg.TLS.ACME.CacheDir != "/tmp/acme" {
		t.Fatalf("expected /tmp/acme, got %q", cfg.TLS.ACME.CacheDir)
	}
}

func TestPopulateFromNode_MCPAllFields(t *testing.T) {
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

func TestPopulateFromNode_EventsFileStorage(t *testing.T) {
	yaml := `events:
  storage: file
  max_events: 50000
  file_path: /var/log/waf/events.jsonl`
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
		t.Fatalf("expected 50000, got %d", cfg.Events.MaxEvents)
	}
	if cfg.Events.FilePath != "/var/log/waf/events.jsonl" {
		t.Fatalf("expected file path, got %q", cfg.Events.FilePath)
	}
}

func TestPopulateFromNode_DashboardAllFields(t *testing.T) {
	yaml := `dashboard:
  enabled: true
  listen: ":9443"
  api_key: secret-key-123
  tls: true`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	if !cfg.Dashboard.Enabled {
		t.Fatal("expected dashboard enabled")
	}
	if cfg.Dashboard.Listen != ":9443" {
		t.Fatalf("expected :9443, got %q", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.APIKey != "secret-key-123" {
		t.Fatalf("expected api key, got %q", cfg.Dashboard.APIKey)
	}
	if !cfg.Dashboard.TLS {
		t.Fatal("expected dashboard TLS enabled")
	}
}

func TestPopulateFromNode_ResponseDataMaskingAndHSTS(t *testing.T) {
	yaml := `waf:
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 63072000
        include_subdomains: false
      x_content_type_options: true
      x_frame_options: DENY
      referrer_policy: no-referrer
      permissions_policy: "camera=(), microphone=()"
    data_masking:
      enabled: true
      mask_credit_cards: true
      mask_ssn: false
      mask_api_keys: true
      strip_stack_traces: false
    error_pages:
      enabled: true
      mode: development`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	// Security headers
	sh := cfg.WAF.Response.SecurityHeaders
	if !sh.Enabled {
		t.Fatal("expected security headers enabled")
	}
	if !sh.HSTS.Enabled {
		t.Fatal("expected HSTS enabled")
	}
	if sh.HSTS.MaxAge != 63072000 {
		t.Fatalf("expected 63072000, got %d", sh.HSTS.MaxAge)
	}
	if sh.HSTS.IncludeSubDomains {
		t.Fatal("expected include_subdomains false")
	}
	if !sh.XContentTypeOptions {
		t.Fatal("expected x_content_type_options true")
	}
	if sh.XFrameOptions != "DENY" {
		t.Fatalf("expected DENY, got %q", sh.XFrameOptions)
	}
	if sh.ReferrerPolicy != "no-referrer" {
		t.Fatalf("expected no-referrer, got %q", sh.ReferrerPolicy)
	}
	if sh.PermissionsPolicy != "camera=(), microphone=()" {
		t.Fatalf("expected permissions policy, got %q", sh.PermissionsPolicy)
	}
	// Data masking
	dm := cfg.WAF.Response.DataMasking
	if !dm.Enabled {
		t.Fatal("expected data masking enabled")
	}
	if !dm.MaskCreditCards {
		t.Fatal("expected mask_credit_cards true")
	}
	if dm.MaskSSN {
		t.Fatal("expected mask_ssn false")
	}
	if !dm.MaskAPIKeys {
		t.Fatal("expected mask_api_keys true")
	}
	if dm.StripStackTraces {
		t.Fatal("expected strip_stack_traces false")
	}
	// Error pages
	ep := cfg.WAF.Response.ErrorPages
	if !ep.Enabled {
		t.Fatal("expected error pages enabled")
	}
	if ep.Mode != "development" {
		t.Fatalf("expected development, got %q", ep.Mode)
	}
}

func TestPopulateFromNode_LoggingAllFields(t *testing.T) {
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
		t.Fatalf("expected debug, got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Fatalf("expected text, got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/waf.log" {
		t.Fatalf("expected file path, got %q", cfg.Logging.Output)
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

func TestPopulateFromNode_UpstreamsWithHealthCheck(t *testing.T) {
	yaml := `upstreams:
  - name: backend
    load_balancer: round_robin
    targets:
      - url: http://localhost:8081
        weight: 2
      - url: http://localhost:8082
        weight: 1
    health_check:
      enabled: true
      interval: 10s
      timeout: 5s
      path: /healthz`
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
		t.Fatalf("expected 'backend', got %q", u.Name)
	}
	if u.LoadBalancer != "round_robin" {
		t.Fatalf("expected round_robin, got %q", u.LoadBalancer)
	}
	if len(u.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(u.Targets))
	}
	if u.Targets[0].URL != "http://localhost:8081" {
		t.Fatalf("expected url, got %q", u.Targets[0].URL)
	}
	if u.Targets[0].Weight != 2 {
		t.Fatalf("expected weight 2, got %d", u.Targets[0].Weight)
	}
	if !u.HealthCheck.Enabled {
		t.Fatal("expected health check enabled")
	}
	if u.HealthCheck.Interval != 10*time.Second {
		t.Fatalf("expected 10s interval, got %v", u.HealthCheck.Interval)
	}
	if u.HealthCheck.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %v", u.HealthCheck.Timeout)
	}
	if u.HealthCheck.Path != "/healthz" {
		t.Fatalf("expected /healthz, got %q", u.HealthCheck.Path)
	}
}

func TestPopulateFromNode_RoutesWithMethods(t *testing.T) {
	yaml := `routes:
  - path: /api
    upstream: backend
    strip_prefix: true
    methods: [GET, POST, PUT]
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
		t.Fatalf("expected /api, got %q", r.Path)
	}
	if r.Upstream != "backend" {
		t.Fatalf("expected backend, got %q", r.Upstream)
	}
	if !r.StripPrefix {
		t.Fatal("expected strip_prefix true")
	}
	if len(r.Methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(r.Methods))
	}
	r2 := cfg.Routes[1]
	if r2.StripPrefix {
		t.Fatal("expected strip_prefix false")
	}
}

func TestPopulateFromNode_BotDetectionAllSubSections(t *testing.T) {
	yaml := `waf:
  bot_detection:
    enabled: true
    mode: enforce
    tls_fingerprint:
      enabled: true
      known_bots_action: block
      unknown_action: log
      mismatch_action: challenge
    user_agent:
      enabled: true
      block_empty: true
      block_known_scanners: false
    behavior:
      enabled: true
      window: 10m
      rps_threshold: 50
      error_rate_threshold: 40`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	bd := cfg.WAF.BotDetection
	if !bd.Enabled {
		t.Fatal("expected bot detection enabled")
	}
	if bd.Mode != "enforce" {
		t.Fatalf("expected enforce, got %q", bd.Mode)
	}
	// TLS fingerprint
	if !bd.TLSFingerprint.Enabled {
		t.Fatal("expected tls fingerprint enabled")
	}
	if bd.TLSFingerprint.KnownBotsAction != "block" {
		t.Fatalf("expected block, got %q", bd.TLSFingerprint.KnownBotsAction)
	}
	if bd.TLSFingerprint.UnknownAction != "log" {
		t.Fatalf("expected log, got %q", bd.TLSFingerprint.UnknownAction)
	}
	if bd.TLSFingerprint.MismatchAction != "challenge" {
		t.Fatalf("expected challenge, got %q", bd.TLSFingerprint.MismatchAction)
	}
	// User agent
	if !bd.UserAgent.Enabled {
		t.Fatal("expected user agent enabled")
	}
	if !bd.UserAgent.BlockEmpty {
		t.Fatal("expected block empty true")
	}
	if bd.UserAgent.BlockKnownScanners {
		t.Fatal("expected block known scanners false")
	}
	// Behavior
	if !bd.Behavior.Enabled {
		t.Fatal("expected behavior enabled")
	}
	if bd.Behavior.Window != 10*time.Minute {
		t.Fatalf("expected 10m, got %v", bd.Behavior.Window)
	}
	if bd.Behavior.RPSThreshold != 50 {
		t.Fatalf("expected 50, got %d", bd.Behavior.RPSThreshold)
	}
	if bd.Behavior.ErrorRateThreshold != 40 {
		t.Fatalf("expected 40, got %d", bd.Behavior.ErrorRateThreshold)
	}
}

func TestPopulateFromNode_DetectionExclusions(t *testing.T) {
	yaml := `waf:
  detection:
    enabled: true
    threshold:
      block: 60
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
        reason: trusted webhook`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	det := cfg.WAF.Detection
	if !det.Enabled {
		t.Fatal("expected detection enabled")
	}
	if det.Threshold.Block != 60 {
		t.Fatalf("expected block 60, got %d", det.Threshold.Block)
	}
	if det.Threshold.Log != 30 {
		t.Fatalf("expected log 30, got %d", det.Threshold.Log)
	}
	sqli := det.Detectors["sqli"]
	if !sqli.Enabled {
		t.Fatal("expected sqli enabled")
	}
	if sqli.Multiplier != 1.5 {
		t.Fatalf("expected 1.5, got %f", sqli.Multiplier)
	}
	xss := det.Detectors["xss"]
	if xss.Enabled {
		t.Fatal("expected xss disabled")
	}
	if xss.Multiplier != 0.5 {
		t.Fatalf("expected 0.5, got %f", xss.Multiplier)
	}
	if len(det.Exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(det.Exclusions))
	}
	ex := det.Exclusions[0]
	if ex.Path != "/webhook" {
		t.Fatalf("expected /webhook, got %q", ex.Path)
	}
	if len(ex.Detectors) != 2 {
		t.Fatalf("expected 2 detectors, got %d", len(ex.Detectors))
	}
	if ex.Reason != "trusted webhook" {
		t.Fatalf("expected reason, got %q", ex.Reason)
	}
}

func TestPopulateFromNode_IPACLWithLists(t *testing.T) {
	yaml := `waf:
  ip_acl:
    enabled: true
    whitelist:
      - 10.0.0.0/8
      - 192.168.1.0/24
    blacklist:
      - 1.2.3.4
    auto_ban:
      enabled: true
      default_ttl: 30m
      max_ttl: 12h`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	acl := cfg.WAF.IPACL
	if !acl.Enabled {
		t.Fatal("expected ip acl enabled")
	}
	if len(acl.Whitelist) != 2 {
		t.Fatalf("expected 2 whitelist, got %d", len(acl.Whitelist))
	}
	if len(acl.Blacklist) != 1 {
		t.Fatalf("expected 1 blacklist, got %d", len(acl.Blacklist))
	}
	if acl.AutoBan.DefaultTTL != 30*time.Minute {
		t.Fatalf("expected 30m, got %v", acl.AutoBan.DefaultTTL)
	}
	if acl.AutoBan.MaxTTL != 12*time.Hour {
		t.Fatalf("expected 12h, got %v", acl.AutoBan.MaxTTL)
	}
}

func TestPopulateFromNode_RateLimitWithPathsAndAutoBan(t *testing.T) {
	yaml := `waf:
  rate_limit:
    enabled: true
    rules:
      - id: api
        scope: ip+path
        paths:
          - /api/v1
          - /api/v2
        limit: 500
        window: 5m
        burst: 25
        action: block
        auto_ban_after: 3`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	rl := cfg.WAF.RateLimit
	if !rl.Enabled {
		t.Fatal("expected rate limit enabled")
	}
	if len(rl.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rl.Rules))
	}
	r := rl.Rules[0]
	if r.ID != "api" {
		t.Fatalf("expected api, got %q", r.ID)
	}
	if r.Scope != "ip+path" {
		t.Fatalf("expected ip+path, got %q", r.Scope)
	}
	if len(r.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(r.Paths))
	}
	if r.Limit != 500 {
		t.Fatalf("expected 500, got %d", r.Limit)
	}
	if r.Window != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", r.Window)
	}
	if r.Burst != 25 {
		t.Fatalf("expected 25, got %d", r.Burst)
	}
	if r.Action != "block" {
		t.Fatalf("expected block, got %q", r.Action)
	}
	if r.AutoBanAfter != 3 {
		t.Fatalf("expected 3, got %d", r.AutoBanAfter)
	}
}

func TestPopulateFromNode_SanitizerPathOverrides(t *testing.T) {
	yaml := `waf:
  sanitizer:
    enabled: true
    max_url_length: 4096
    max_header_size: 16384
    max_header_count: 50
    max_body_size: 5242880
    max_cookie_size: 8192
    block_null_bytes: true
    normalize_encoding: false
    strip_hop_by_hop: false
    allowed_methods: [GET, POST]
    path_overrides:
      - path: /upload
        max_body_size: 104857600`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	san := cfg.WAF.Sanitizer
	if !san.Enabled {
		t.Fatal("expected sanitizer enabled")
	}
	if san.MaxURLLength != 4096 {
		t.Fatalf("expected 4096, got %d", san.MaxURLLength)
	}
	if san.MaxHeaderSize != 16384 {
		t.Fatalf("expected 16384, got %d", san.MaxHeaderSize)
	}
	if san.MaxHeaderCount != 50 {
		t.Fatalf("expected 50, got %d", san.MaxHeaderCount)
	}
	if san.MaxBodySize != 5242880 {
		t.Fatalf("expected 5242880, got %d", san.MaxBodySize)
	}
	if san.MaxCookieSize != 8192 {
		t.Fatalf("expected 8192, got %d", san.MaxCookieSize)
	}
	if !san.BlockNullBytes {
		t.Fatal("expected block_null_bytes true")
	}
	if san.NormalizeEncoding {
		t.Fatal("expected normalize_encoding false")
	}
	if san.StripHopByHop {
		t.Fatal("expected strip_hop_by_hop false")
	}
	if len(san.AllowedMethods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(san.AllowedMethods))
	}
	if len(san.PathOverrides) != 1 {
		t.Fatalf("expected 1 path override, got %d", len(san.PathOverrides))
	}
	po := san.PathOverrides[0]
	if po.Path != "/upload" {
		t.Fatalf("expected /upload, got %q", po.Path)
	}
	if po.MaxBodySize != 104857600 {
		t.Fatalf("expected 104857600, got %d", po.MaxBodySize)
	}
}

func TestPopulateFromNode_NilNode(t *testing.T) {
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, nil)
	if err != nil {
		t.Fatalf("expected no error for nil node, got %v", err)
	}
}

func TestPopulateFromNode_NonMapNode(t *testing.T) {
	node := &Node{Kind: ScalarNode, Value: "test"}
	cfg := DefaultConfig()
	err := PopulateFromNode(cfg, node)
	if err != nil {
		t.Fatalf("expected no error for non-map node, got %v", err)
	}
}

func TestPopulateFromNode_FullConfigCoverage(t *testing.T) {
	// A comprehensive config that exercises most populate paths together
	yaml := `mode: monitor
listen: ":9080"
tls:
  enabled: true
  listen: ":9443"
  cert_file: /etc/certs/cert.pem
  key_file: /etc/certs/key.pem
  acme:
    enabled: true
    email: ops@example.com
    domains:
      - example.com
    cache_dir: /cache/acme
upstreams:
  - name: web
    load_balancer: weighted
    targets:
      - url: http://web1:8088
        weight: 3
      - url: http://web2:8088
        weight: 1
    health_check:
      enabled: true
      interval: 15s
      timeout: 3s
      path: /health
routes:
  - path: /
    upstream: web
    strip_prefix: false
    methods: [GET, POST]
waf:
  ip_acl:
    enabled: true
    whitelist:
      - 10.0.0.0/8
    blacklist:
      - 0.0.0.0/0
    auto_ban:
      enabled: true
      default_ttl: 1h
      max_ttl: 24h
  rate_limit:
    enabled: true
    rules:
      - id: global
        scope: ip
        limit: 2000
        window: 1m
        burst: 100
        action: block
  sanitizer:
    enabled: true
    max_url_length: 4096
    max_body_size: 5242880
    allowed_methods: [GET, POST, PUT]
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
    detectors:
      sqli:
        enabled: true
        multiplier: 1.0
  bot_detection:
    enabled: true
    mode: monitor
    tls_fingerprint:
      enabled: true
    user_agent:
      enabled: true
      block_empty: true
    behavior:
      enabled: true
      window: 5m
      rps_threshold: 20
  response:
    security_headers:
      enabled: true
      hsts:
        enabled: true
        max_age: 31536000
        include_subdomains: true
    data_masking:
      enabled: true
      mask_credit_cards: true
    error_pages:
      enabled: true
      mode: production
dashboard:
  enabled: true
  listen: ":9443"
  api_key: my-secret
  tls: true
mcp:
  enabled: true
  transport: stdio
logging:
  level: info
  format: json
  output: stdout
  log_allowed: false
  log_blocked: true
  log_body: false
events:
  storage: file
  max_events: 200000
  file_path: /var/log/waf/events.jsonl`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}
	// Spot-check some values
	if cfg.Mode != "monitor" {
		t.Fatalf("expected monitor, got %q", cfg.Mode)
	}
	if cfg.Listen != ":9080" {
		t.Fatalf("expected :9080, got %q", cfg.Listen)
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
	if cfg.Events.Storage != "file" {
		t.Fatalf("expected file storage, got %q", cfg.Events.Storage)
	}
	if cfg.Events.MaxEvents != 200000 {
		t.Fatalf("expected 200000, got %d", cfg.Events.MaxEvents)
	}
	if cfg.Dashboard.APIKey != "my-secret" {
		t.Fatalf("expected my-secret, got %q", cfg.Dashboard.APIKey)
	}
}

// --- VirtualHosts tests ---

func TestPopulateFromNode_VirtualHosts(t *testing.T) {
	yaml := `virtual_hosts:
  - domains:
      - api.example.com
      - www.api.example.com
    tls:
      cert_file: /etc/ssl/api.crt
      key_file: /etc/ssl/api.key
    routes:
      - path: /v1
        upstream: apiv1
        strip_prefix: true
        methods: [GET, POST]
  - domains:
      - static.example.com
    tls:
      cert_file: /etc/ssl/static.crt
      key_file: /etc/ssl/static.key
  - domains:
      - "*.wildcard.com"`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if len(cfg.VirtualHosts) != 3 {
		t.Fatalf("expected 3 virtual hosts, got %d", len(cfg.VirtualHosts))
	}

	vh1 := cfg.VirtualHosts[0]
	if len(vh1.Domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(vh1.Domains))
	}
	if vh1.Domains[0] != "api.example.com" {
		t.Fatalf("expected domain 'api.example.com', got %q", vh1.Domains[0])
	}
	if vh1.TLS.CertFile != "/etc/ssl/api.crt" {
		t.Fatalf("expected cert_file, got %q", vh1.TLS.CertFile)
	}
	if vh1.TLS.KeyFile != "/etc/ssl/api.key" {
		t.Fatalf("expected key_file, got %q", vh1.TLS.KeyFile)
	}
	if len(vh1.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(vh1.Routes))
	}
	if vh1.Routes[0].Path != "/v1" {
		t.Fatalf("expected route path '/v1', got %q", vh1.Routes[0].Path)
	}
	if !vh1.Routes[0].StripPrefix {
		t.Fatal("expected strip_prefix true")
	}

	vh2 := cfg.VirtualHosts[1]
	if len(vh2.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(vh2.Domains))
	}
	if vh2.Domains[0] != "static.example.com" {
		t.Fatalf("expected domain 'static.example.com', got %q", vh2.Domains[0])
	}

	vh3 := cfg.VirtualHosts[2]
	if vh3.Domains[0] != "*.wildcard.com" {
		t.Fatalf("expected wildcard domain, got %q", vh3.Domains[0])
	}
}

func TestPopulateFromNode_VirtualHostsNonMap(t *testing.T) {
	yaml := `virtual_hosts: disabled`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPopulateFromNode_VirtualHostsRoutesError(t *testing.T) {
	yaml := `virtual_hosts:
  - domains:
      - test.com
    routes:
      - path: /api
        strip_prefix: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid route strip_prefix in virtual host")
	}
}

func TestValidateVirtualHostsExported(t *testing.T) {
	// VirtualHostConfig validation - check the structure
	vhosts := []VirtualHostConfig{
		{Domains: []string{"example.com"}},
		{Domains: []string{}}, // Empty domains
	}
	ve := &ValidationError{}
	ValidateVirtualHostsExported(vhosts, []UpstreamConfig{}, ve)
	// Check if validation runs without panic
	_ = ve.HasErrors()
}

func TestValidateUpstreamsExported(t *testing.T) {
	upstreams := []UpstreamConfig{
		{Name: "api", Targets: []TargetConfig{{URL: "http://localhost:8088"}}, LoadBalancer: "round_robin"},
		{Name: "", Targets: []TargetConfig{{URL: "http://localhost:8081"}}}, // Invalid: empty name
	}
	ve := &ValidationError{}
	ValidateUpstreamsExported(upstreams, ve)
	if !ve.HasErrors() {
		t.Error("expected validation error for empty upstream name")
	}
}

func TestValidateRoutesExported(t *testing.T) {
	routes := []RouteConfig{
		{Path: "/api", Upstream: "backend"},
		{Path: "", Upstream: "backend"}, // Invalid: empty path
	}
	ve := &ValidationError{}
	ValidateRoutesExported(routes, []UpstreamConfig{}, ve)
	if !ve.HasErrors() {
		t.Error("expected validation error for empty route path")
	}
}

// --- Challenge tests ---

func TestPopulateFromNode_Challenge(t *testing.T) {
	yaml := `waf:
  challenge:
    enabled: true
    difficulty: 18
    cookie_ttl: 30m
    cookie_name: __custom_challenge
    secret_key: "my-secret-key-base64"`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("populate error: %v", err)
	}

	if !cfg.WAF.Challenge.Enabled {
		t.Fatal("expected challenge enabled")
	}
	if cfg.WAF.Challenge.Difficulty != 18 {
		t.Fatalf("expected difficulty 18, got %d", cfg.WAF.Challenge.Difficulty)
	}
	if cfg.WAF.Challenge.CookieTTL != 30*time.Minute {
		t.Fatalf("expected cookie_ttl 30m, got %v", cfg.WAF.Challenge.CookieTTL)
	}
	if cfg.WAF.Challenge.CookieName != "__custom_challenge" {
		t.Fatalf("expected cookie_name '__custom_challenge', got %q", cfg.WAF.Challenge.CookieName)
	}
	if cfg.WAF.Challenge.SecretKey != "my-secret-key-base64" {
		t.Fatalf("expected secret_key, got %q", cfg.WAF.Challenge.SecretKey)
	}
}

func TestPopulateFromNode_ChallengeError(t *testing.T) {
	yaml := `waf:
  challenge:
    enabled: notabool`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid challenge enabled")
	}
}

func TestPopulateFromNode_ChallengeDifficultyError(t *testing.T) {
	yaml := `waf:
  challenge:
    difficulty: notanint`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid challenge difficulty")
	}
}

func TestPopulateFromNode_ChallengeCookieTTLError(t *testing.T) {
	yaml := `waf:
  challenge:
    cookie_ttl: badduration`
	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	cfg := DefaultConfig()
	err = PopulateFromNode(cfg, node)
	if err == nil {
		t.Fatal("expected error for invalid challenge cookie_ttl")
	}
}
