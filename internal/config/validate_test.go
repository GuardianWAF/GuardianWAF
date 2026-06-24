package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadFile(t *testing.T) {
	// Create a temporary YAML config file
	dir := t.TempDir()
	path := filepath.Join(dir, "guardianwaf.yaml")

	yamlContent := `mode: monitor
listen: ":9090"
logging:
  level: debug
  format: text
  output: stderr
waf:
  geoip:
    enabled: true
    require_ready: true
  detection:
    enabled: true
    threshold:
      block: 80
      log: 30
events:
  storage: file
  max_events: 50000
  file_path: /tmp/events.jsonl
upstreams:
  - name: backend
    targets:
      - url: http://localhost:3000
        weight: 1
routes:
  - path: /api
    upstream: backend
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error: %v", err)
	}

	if cfg.Mode != "monitor" {
		t.Fatalf("expected mode 'monitor', got %q", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected listen ':9090', got %q", cfg.Listen)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("expected logging level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Fatalf("expected logging format 'text', got %q", cfg.Logging.Format)
	}
	if cfg.WAF.Detection.Threshold.Block != 80 {
		t.Fatalf("expected block threshold 80, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.WAF.Detection.Threshold.Log != 30 {
		t.Fatalf("expected log threshold 30, got %d", cfg.WAF.Detection.Threshold.Log)
	}
	if !cfg.WAF.GeoIP.Enabled || !cfg.WAF.GeoIP.RequireReady {
		t.Fatalf("expected GeoIP enabled with require_ready, got enabled=%v require_ready=%v", cfg.WAF.GeoIP.Enabled, cfg.WAF.GeoIP.RequireReady)
	}
	if cfg.Events.Storage != "file" {
		t.Fatalf("expected events storage 'file', got %q", cfg.Events.Storage)
	}
	if cfg.Events.MaxEvents != 50000 {
		t.Fatalf("expected max_events 50000, got %d", cfg.Events.MaxEvents)
	}
	// Verify defaults are preserved for fields not in the file
	if !cfg.WAF.Sanitizer.Enabled {
		t.Fatal("expected sanitizer enabled (default preserved)")
	}
	if cfg.WAF.Sanitizer.MaxURLLength != 8192 {
		t.Fatalf("expected MaxURLLength 8192 (default), got %d", cfg.WAF.Sanitizer.MaxURLLength)
	}
}

func TestLoadFile_NotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "reading config file") {
		t.Fatalf("expected reading config file error, got: %v", err)
	}
}

func TestLoadFile_RejectsNULPath(t *testing.T) {
	_, err := LoadFile("bad\x00.yaml")
	if err == nil {
		t.Fatal("expected error for NUL path")
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("expected NUL path error, got: %v", err)
	}
}

func TestConfigChildFile(t *testing.T) {
	dir := t.TempDir()

	path, err := configChildFile(dir, "safe.yaml", ".yaml")
	if err != nil {
		t.Fatalf("configChildFile valid: %v", err)
	}
	if path != filepath.Join(dir, "safe.yaml") {
		t.Fatalf("path: got %q, want %q", path, filepath.Join(dir, "safe.yaml"))
	}

	for _, name := range []string{"../escape.yaml", "nested/escape.yaml", `nested\escape.yaml`, "bad.txt", "bad\x00.yaml"} {
		t.Run(name, func(t *testing.T) {
			if _, err := configChildFile(dir, name, ".yaml"); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}

func TestLoadFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")

	// Write content that our parser will reject (e.g. invalid flow sequence)
	badYAML := `mode: enforce
listen: [invalid`
	if err := os.WriteFile(path, []byte(badYAML), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFile_UnknownTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.yaml")

	legacyYAML := `server:
  listen: ":8088"
  mode: enforce
upstreams:
  - name: backend
    targets:
      - url: http://localhost:3000
routes:
  - path: /
    upstream: backend
`
	if err := os.WriteFile(path, []byte(legacyYAML), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for unknown top-level key")
	}
	if !strings.Contains(err.Error(), "server: unknown top-level key") {
		t.Fatalf("expected unknown server key error, got: %v", err)
	}
}

func TestLoadFile_UnknownNestedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested-unknown.yaml")

	yamlContent := `mode: enforce
waf:
  detection:
    enabled: true
    threshold:
      block: 50
      typo: 25
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for unknown nested key")
	}
	if !strings.Contains(err.Error(), "waf.detection.threshold.typo: unknown key") {
		t.Fatalf("expected unknown nested key error, got: %v", err)
	}
}

func TestLoadFile_UnknownSequenceItemKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sequence-unknown.yaml")

	yamlContent := `mode: enforce
upstreams:
  - name: backend
    targets:
      - url: http://localhost:3000
        weight: 1
        typo: true
routes:
  - path: /
    upstream: backend
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for unknown sequence item key")
	}
	if !strings.Contains(err.Error(), "upstreams[0].targets[0].typo: unknown key") {
		t.Fatalf("expected unknown sequence item key error, got: %v", err)
	}
}

func TestLoadFile_DynamicMapKeysAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dynamic-map.yaml")

	yamlContent := `mode: enforce
features:
  experimental_rule_sync: true
waf:
  detection:
    detectors:
      custom_detector:
        enabled: true
        multiplier: 0.5
alerting:
  webhooks:
    - name: ops
      url: https://example.com/hook
      type: generic
      headers:
        X-Custom-Header: value
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	if _, err := LoadFile(path); err != nil {
		t.Fatalf("expected dynamic map keys to validate, got: %v", err)
	}
}

func TestLoadDir(t *testing.T) {
	// Create a directory structure with main config and subdirectory configs
	dir := t.TempDir()

	// Main config
	mainConfig := `mode: monitor
listen: ":9090"
waf:
  ip_acl:
    enabled: true
`
	if err := os.WriteFile(filepath.Join(dir, "guardianwaf.yaml"), []byte(mainConfig), 0o644); err != nil {
		t.Fatalf("failed to write main config: %v", err)
	}

	// Create rules.d directory and add a rules file
	rulesDir := filepath.Join(dir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("failed to create rules.d dir: %v", err)
	}

	rulesConfig := `custom_rules:
  - id: "block-scanners"
    name: "Block Known Scanners"
    priority: 10
    action: block
    score: 80
    conditions:
      - field: user_agent
        op: contains
        value: "sqlmap"
rate_limits:
  - id: "api-global"
    scope: ip
    limit: 100
    window: 1m
    burst: 20
    action: block
ipacl:
  blacklist:
    - "1.2.3.4"
    - "5.6.7.8/24"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "security.yaml"), []byte(rulesConfig), 0o644); err != nil {
		t.Fatalf("failed to write rules.d/security.yaml: %v", err)
	}

	// Create domains.d directory and add a domain config
	domainsDir := filepath.Join(dir, "domains.d")
	if err := os.MkdirAll(domainsDir, 0o755); err != nil {
		t.Fatalf("failed to create domains.d dir: %v", err)
	}

	domainConfig := `domains:
  - "example.com"
  - "*.example.com"
routes:
  - path: /api
    upstream: example-api
upstreams:
  - name: example-api
    targets:
      - url: http://localhost:8000
`
	if err := os.WriteFile(filepath.Join(domainsDir, "example.com.yaml"), []byte(domainConfig), 0o644); err != nil {
		t.Fatalf("failed to write domains.d/example.com.yaml: %v", err)
	}

	// Test LoadDir
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error: %v", err)
	}

	// Verify main config values are preserved
	if cfg.Mode != "monitor" {
		t.Errorf("expected mode 'monitor', got %q", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("expected listen ':9090', got %q", cfg.Listen)
	}
	if !cfg.WAF.IPACL.Enabled {
		t.Error("expected IPACL enabled")
	}

	// Verify rules were appended
	if len(cfg.WAF.CustomRules.Rules) != 1 {
		t.Errorf("expected 1 custom rule, got %d", len(cfg.WAF.CustomRules.Rules))
	}
	if cfg.WAF.CustomRules.Rules[0].ID != "block-scanners" {
		t.Errorf("expected rule id 'block-scanners', got %q", cfg.WAF.CustomRules.Rules[0].ID)
	}

	// Verify rate limit rules were appended (DefaultConfig has 1 rule, we add 1)
	if len(cfg.WAF.RateLimit.Rules) != 2 {
		t.Errorf("expected 2 rate limit rules (1 default + 1 appended), got %d", len(cfg.WAF.RateLimit.Rules))
	}

	// Verify IP ACL blacklist was appended
	if len(cfg.WAF.IPACL.Blacklist) != 2 {
		t.Errorf("expected 2 blacklist entries, got %d", len(cfg.WAF.IPACL.Blacklist))
	}

	// Verify virtual hosts were appended
	if len(cfg.VirtualHosts) != 1 {
		t.Errorf("expected 1 virtual host, got %d", len(cfg.VirtualHosts))
	}
	if len(cfg.VirtualHosts) > 0 && cfg.VirtualHosts[0].Domains[0] != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", cfg.VirtualHosts[0].Domains[0])
	}

	// Verify upstreams were appended
	if len(cfg.Upstreams) < 1 {
		t.Error("expected at least 1 upstream")
	}
}

func TestLoadEnv(t *testing.T) {
	cfg := DefaultConfig()

	// Set environment variables
	envVars := map[string]string{
		"GWAF_MODE":                          "monitor",
		"GWAF_LISTEN":                        ":9090",
		"GWAF_LOGGING_LEVEL":                 "debug",
		"GWAF_LOGGING_FORMAT":                "text",
		"GWAF_LOGGING_OUTPUT":                "/var/log/waf.log",
		"GWAF_WAF_DETECTION_THRESHOLD_BLOCK": "75",
		"GWAF_WAF_DETECTION_THRESHOLD_LOG":   "30",
		"GWAF_DASHBOARD_LISTEN":              ":8443",
		"GWAF_DASHBOARD_API_KEY":             "secret123",
		"GWAF_DASHBOARD_ADMIN_KEY":           "admin-secret-123456",
		"GWAF_EVENTS_STORAGE":                "file",
		"GWAF_EVENTS_FILE_PATH":              "/tmp/events.jsonl",
		"GWAF_EVENTS_MAX_EVENTS":             "50000",
	}
	for k, v := range envVars {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	LoadEnv(cfg)

	if cfg.Mode != "monitor" {
		t.Fatalf("expected mode 'monitor', got %q", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("expected listen ':9090', got %q", cfg.Listen)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("expected logging level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Fatalf("expected logging format 'text', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/waf.log" {
		t.Fatalf("expected logging output '/var/log/waf.log', got %q", cfg.Logging.Output)
	}
	if cfg.WAF.Detection.Threshold.Block != 75 {
		t.Fatalf("expected block threshold 75, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.WAF.Detection.Threshold.Log != 30 {
		t.Fatalf("expected log threshold 30, got %d", cfg.WAF.Detection.Threshold.Log)
	}
	if cfg.Dashboard.Listen != ":8443" {
		t.Fatalf("expected dashboard listen ':8443', got %q", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.APIKey != "secret123" {
		t.Fatalf("expected dashboard api_key 'secret123', got %q", cfg.Dashboard.APIKey)
	}
	if cfg.Dashboard.AdminKey != "admin-secret-123456" {
		t.Fatalf("expected dashboard admin_key 'admin-secret-123456', got %q", cfg.Dashboard.AdminKey)
	}
	if cfg.Events.Storage != "file" {
		t.Fatalf("expected events storage 'file', got %q", cfg.Events.Storage)
	}
	if cfg.Events.FilePath != "/tmp/events.jsonl" {
		t.Fatalf("expected events file_path '/tmp/events.jsonl', got %q", cfg.Events.FilePath)
	}
	if cfg.Events.MaxEvents != 50000 {
		t.Fatalf("expected events max_events 50000, got %d", cfg.Events.MaxEvents)
	}
}

func TestLoadEnv_EmptyVarsIgnored(t *testing.T) {
	cfg := DefaultConfig()
	// Ensure no GWAF_ vars are set
	os.Unsetenv("GWAF_MODE")
	os.Unsetenv("GWAF_LISTEN")

	LoadEnv(cfg)

	// Defaults should be preserved
	if cfg.Mode != "enforce" {
		t.Fatalf("expected mode 'enforce' (default), got %q", cfg.Mode)
	}
	if cfg.Listen != ":8088" {
		t.Fatalf("expected listen ':8088' (default), got %q", cfg.Listen)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no validation errors for DefaultConfig, got: %v", err)
	}
}

func TestValidate_DashboardTLSUnsupported(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.TLS = true

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for unsupported dashboard TLS termination")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	for _, fe := range ve.Errors {
		if fe.Field == "dashboard.tls" && strings.Contains(fe.Message, "reverse proxy") {
			return
		}
	}
	t.Fatalf("expected dashboard.tls reverse proxy validation error, got: %v", err)
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "invalid"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid mode")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "mode" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected error for field 'mode'")
	}
}

func TestValidate_InvalidThresholds(t *testing.T) {
	tests := []struct {
		name      string
		block     int
		log       int
		wantField string
	}{
		{
			name:      "block less than log",
			block:     10,
			log:       20,
			wantField: "waf.detection.threshold.block",
		},
		{
			name:      "block equals log",
			block:     25,
			log:       25,
			wantField: "waf.detection.threshold.block",
		},
		{
			name:      "negative block",
			block:     -1,
			log:       10,
			wantField: "waf.detection.threshold.block",
		},
		{
			name:      "negative log",
			block:     50,
			log:       -5,
			wantField: "waf.detection.threshold.log",
		},
		{
			name:      "zero block",
			block:     0,
			log:       10,
			wantField: "waf.detection.threshold.block",
		},
		{
			name:      "zero log",
			block:     50,
			log:       0,
			wantField: "waf.detection.threshold.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.WAF.Detection.Threshold.Block = tt.block
			cfg.WAF.Detection.Threshold.Log = tt.log

			err := Validate(cfg)
			if err == nil {
				t.Fatal("expected validation error")
			}
			ve, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("expected *ValidationError, got %T", err)
			}

			found := false
			for _, fe := range ve.Errors {
				if fe.Field == tt.wantField {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error for field %q, got errors: %v", tt.wantField, ve.Errors)
			}
		})
	}
}

func TestValidate_NegativeMultiplier(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Detection.Detectors["sqli"] = DetectorConfig{Enabled: true, Multiplier: -1.0}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for negative multiplier")
	}
	ve := err.(*ValidationError)
	found := false
	for _, fe := range ve.Errors {
		if strings.Contains(fe.Field, "sqli.multiplier") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for sqli.multiplier, got: %v", ve.Errors)
	}
}

func TestValidate_InvalidCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Whitelist = []string{"10.0.0.0/8", "not-an-ip", "192.168.1.0/33"}
	cfg.WAF.IPACL.Blacklist = []string{"999.999.999.999"}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid CIDR")
	}
	ve := err.(*ValidationError)

	// Should have errors for: whitelist[1], whitelist[2], blacklist[0]
	whitelistErrors := 0
	blacklistErrors := 0
	for _, fe := range ve.Errors {
		if strings.HasPrefix(fe.Field, "waf.ip_acl.whitelist") {
			whitelistErrors++
		}
		if strings.HasPrefix(fe.Field, "waf.ip_acl.blacklist") {
			blacklistErrors++
		}
	}
	if whitelistErrors != 2 {
		t.Fatalf("expected 2 whitelist errors, got %d; errors: %v", whitelistErrors, ve.Errors)
	}
	if blacklistErrors != 1 {
		t.Fatalf("expected 1 blacklist error, got %d; errors: %v", blacklistErrors, ve.Errors)
	}
}

func TestValidate_ValidIPAndCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Whitelist = []string{
		"10.0.0.0/8",
		"192.168.0.0/16",
		"172.16.0.0/12",
		"127.0.0.1",
		"::1",
		"fe80::/10",
	}
	cfg.WAF.IPACL.Blacklist = []string{
		"1.2.3.4",
		"10.0.0.0/24",
	}

	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no validation error for valid IPs/CIDRs, got: %v", err)
	}
}

func TestValidate_InvalidUpstream(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstreams = []UpstreamConfig{
		{
			Name:    "",  // empty name
			Targets: nil, // empty targets
		},
		{
			Name: "backend",
			Targets: []TargetConfig{
				{URL: "", Weight: 0},                       // empty URL, zero weight
				{URL: "http://localhost:3000", Weight: -1}, // negative weight
			},
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors for invalid upstreams")
	}
	ve := err.(*ValidationError)

	expectedFields := map[string]bool{
		"upstreams[0].name":              false,
		"upstreams[0].targets":           false,
		"upstreams[1].targets[0].url":    false,
		"upstreams[1].targets[0].weight": false,
		"upstreams[1].targets[1].weight": false,
	}

	for _, fe := range ve.Errors {
		if _, ok := expectedFields[fe.Field]; ok {
			expectedFields[fe.Field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			t.Errorf("expected error for field %q, not found in: %v", field, ve.Errors)
		}
	}
}

func TestValidate_InvalidRoutes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstreams = []UpstreamConfig{
		{
			Name:    "backend",
			Targets: []TargetConfig{{URL: "http://localhost:3000", Weight: 1}},
		},
	}
	cfg.Routes = []RouteConfig{
		{Path: "", Upstream: "backend"},         // empty path
		{Path: "no-slash", Upstream: "backend"}, // no leading /
		{Path: "/api", Upstream: "nonexistent"}, // unknown upstream
		{Path: "/health", Upstream: ""},         // empty upstream
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors for invalid routes")
	}
	ve := err.(*ValidationError)

	expectedFields := map[string]bool{
		"routes[0].path":     false,
		"routes[1].path":     false,
		"routes[2].upstream": false,
	}

	for _, fe := range ve.Errors {
		if _, ok := expectedFields[fe.Field]; ok {
			expectedFields[fe.Field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			t.Errorf("expected error for field %q, not found in: %v", field, ve.Errors)
		}
	}
}

func TestValidate_InvalidRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{
			ID:     "",        // empty id
			Scope:  "invalid", // invalid scope
			Limit:  0,         // zero limit
			Window: 0,         // zero window
			Action: "invalid", // invalid action
		},
		{
			ID:     "valid",
			Scope:  "ip",
			Limit:  -1,
			Window: -1 * time.Second,
			Action: "block",
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors for invalid rate limit")
	}
	ve := err.(*ValidationError)

	expectedFields := map[string]bool{
		"waf.rate_limit.rules[0].id":     false,
		"waf.rate_limit.rules[0].limit":  false,
		"waf.rate_limit.rules[0].window": false,
		"waf.rate_limit.rules[0].scope":  false,
		"waf.rate_limit.rules[0].action": false,
		"waf.rate_limit.rules[1].limit":  false,
		"waf.rate_limit.rules[1].window": false,
	}

	for _, fe := range ve.Errors {
		if _, ok := expectedFields[fe.Field]; ok {
			expectedFields[fe.Field] = true
		}
	}

	for field, found := range expectedFields {
		if !found {
			t.Errorf("expected error for field %q, not found in: %v", field, ve.Errors)
		}
	}
}

func TestValidate_InvalidLogging(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Level = "verbose"
	cfg.Logging.Format = "xml"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors for invalid logging")
	}
	ve := err.(*ValidationError)

	levelFound := false
	formatFound := false
	for _, fe := range ve.Errors {
		if fe.Field == "logging.level" {
			levelFound = true
		}
		if fe.Field == "logging.format" {
			formatFound = true
		}
	}
	if !levelFound {
		t.Errorf("expected error for logging.level, got: %v", ve.Errors)
	}
	if !formatFound {
		t.Errorf("expected error for logging.format, got: %v", ve.Errors)
	}
}

func TestValidate_InvalidEventsStorage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Events.Storage = "redis"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid events storage")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "events.storage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for events.storage, got: %v", ve.Errors)
	}
}

func TestValidate_EventsFileRequiresPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Events.Storage = "file"
	cfg.Events.FilePath = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for missing file path")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "events.file_path" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for events.file_path, got: %v", ve.Errors)
	}
}

func TestValidate_EventsMaxEventsZero(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Events.MaxEvents = 0

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for zero max_events")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "events.max_events" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for events.max_events, got: %v", ve.Errors)
	}
}

func TestValidate_InvalidListenAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = "not-a-valid-address"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid listen address")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "listen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for listen, got: %v", ve.Errors)
	}
}

func TestValidate_DashboardInvalidListen(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "bad-address"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid dashboard listen")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "dashboard.listen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for dashboard.listen, got: %v", ve.Errors)
	}
}

func TestValidate_DashboardWeakAPIKey(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = ":9443"
	cfg.Dashboard.APIKey = "secret123"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for weak dashboard API key")
	}
	ve := err.(*ValidationError)

	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "dashboard.api_key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for dashboard.api_key, got: %v", ve.Errors)
	}
}

func TestValidate_DashboardGeneratedAPIKeyAllowed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = ":9443"
	cfg.Dashboard.APIKey = ""

	if err := Validate(cfg); err != nil {
		t.Fatalf("expected empty dashboard API key to be allowed for startup generation, got: %v", err)
	}
}

func TestValidate_TrustedProxiesRejectsInvalidAndOverbroad(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "invalid", value: "not-an-ip"},
		{name: "ipv4 all", value: "0.0.0.0/0"},
		{name: "ipv6 all", value: "::/0"},
		{name: "overbroad ipv4", value: "1.0.0.0/7"},
		{name: "overbroad ipv6", value: "2000::/16"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TrustedProxies = []string{tt.value}

			err := Validate(cfg)
			if err == nil {
				t.Fatal("expected validation error for unsafe trusted proxy")
			}
			ve := err.(*ValidationError)

			found := false
			for _, fe := range ve.Errors {
				if fe.Field == "trusted_proxies[0]" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error for trusted_proxies[0], got: %v", ve.Errors)
			}
		})
	}
}

func TestValidate_TrustedProxiesAllowsSpecificProxyRanges(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxies = []string{
		"10.0.0.10",
		"10.0.1.0/24",
		"2001:db8::/48",
	}

	if err := Validate(cfg); err != nil {
		t.Fatalf("expected trusted proxy ranges to validate, got: %v", err)
	}
}

func TestValidate_TLSWithoutCert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for TLS without cert/key")
	}
	ve := err.(*ValidationError)

	certFound := false
	keyFound := false
	for _, fe := range ve.Errors {
		if fe.Field == "tls.cert_file" {
			certFound = true
		}
		if fe.Field == "tls.key_file" {
			keyFound = true
		}
	}
	if !certFound {
		t.Errorf("expected error for tls.cert_file, got: %v", ve.Errors)
	}
	if !keyFound {
		t.Errorf("expected error for tls.key_file, got: %v", ve.Errors)
	}
}

func TestValidate_TLSACMEMissingFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.ACME.Enabled = true
	cfg.TLS.ACME.Email = ""
	cfg.TLS.ACME.Domains = nil

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for ACME without email/domains")
	}
	ve := err.(*ValidationError)

	emailFound := false
	domainsFound := false
	for _, fe := range ve.Errors {
		if fe.Field == "tls.acme.email" {
			emailFound = true
		}
		if fe.Field == "tls.acme.domains" {
			domainsFound = true
		}
	}
	if !emailFound {
		t.Errorf("expected error for tls.acme.email, got: %v", ve.Errors)
	}
	if !domainsFound {
		t.Errorf("expected error for tls.acme.domains, got: %v", ve.Errors)
	}
}

func TestValidate_SanitizerZeroValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.MaxURLLength = 0
	cfg.WAF.Sanitizer.MaxHeaderSize = 0
	cfg.WAF.Sanitizer.MaxHeaderCount = 0
	cfg.WAF.Sanitizer.MaxBodySize = 0
	cfg.WAF.Sanitizer.MaxCookieSize = 0

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors for zero sanitizer values")
	}
	ve := err.(*ValidationError)

	expectedFields := []string{
		"waf.sanitizer.max_url_length",
		"waf.sanitizer.max_header_size",
		"waf.sanitizer.max_header_count",
		"waf.sanitizer.max_body_size",
		"waf.sanitizer.max_cookie_size",
	}

	for _, expected := range expectedFields {
		found := false
		for _, fe := range ve.Errors {
			if fe.Field == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected error for %q, not found in: %v", expected, ve.Errors)
		}
	}
}

func TestValidate_AggregatedErrors(t *testing.T) {
	cfg := DefaultConfig()
	// Introduce multiple errors across different sections
	cfg.Mode = "invalid"
	cfg.Listen = "bad"
	cfg.Logging.Level = "trace"
	cfg.Logging.Format = "xml"
	cfg.Events.Storage = "redis"
	cfg.Events.MaxEvents = 0

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	// We should have at least 5 errors (mode, listen, logging.level, logging.format, events.storage, events.max_events)
	if len(ve.Errors) < 5 {
		t.Fatalf("expected at least 5 errors, got %d: %v", len(ve.Errors), ve.Errors)
	}

	// Verify different field prefixes are present
	fieldPrefixes := []string{"mode", "listen", "logging.", "events."}
	for _, prefix := range fieldPrefixes {
		found := false
		for _, fe := range ve.Errors {
			if strings.HasPrefix(fe.Field, prefix) || fe.Field == prefix {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected at least one error with field prefix %q", prefix)
		}
	}
}

func TestValidationError_Format(t *testing.T) {
	ve := &ValidationError{
		Errors: []FieldError{
			{Field: "mode", Message: "must be one of: enforce, monitor, disabled; got \"bad\""},
			{Field: "listen", Message: "invalid host:port format"},
			{Field: "logging.level", Message: "must be one of: debug, info, warn, error; got \"trace\""},
		},
	}

	msg := ve.Error()
	if !strings.HasPrefix(msg, "config validation failed: 3 errors") {
		t.Fatalf("unexpected error prefix: %q", msg)
	}
	if !strings.Contains(msg, "  - mode:") {
		t.Fatalf("expected mode error in message: %q", msg)
	}
	if !strings.Contains(msg, "  - listen:") {
		t.Fatalf("expected listen error in message: %q", msg)
	}
	if !strings.Contains(msg, "  - logging.level:") {
		t.Fatalf("expected logging.level error in message: %q", msg)
	}
}

func TestValidationError_Format_SingleError(t *testing.T) {
	ve := &ValidationError{
		Errors: []FieldError{
			{Field: "mode", Message: "invalid"},
		},
	}

	msg := ve.Error()
	if !strings.HasPrefix(msg, "config validation failed: 1 error\n") {
		t.Fatalf("expected singular 'error' for 1 error, got: %q", msg)
	}
}

func TestValidationError_HasErrors(t *testing.T) {
	ve := &ValidationError{}
	if ve.HasErrors() {
		t.Fatal("expected HasErrors() false for empty errors")
	}

	ve.Errors = append(ve.Errors, FieldError{Field: "test", Message: "test"})
	if !ve.HasErrors() {
		t.Fatal("expected HasErrors() true with errors")
	}
}

func TestFieldError_Error(t *testing.T) {
	fe := FieldError{Field: "waf.detection.threshold.block", Message: "must be > 0; got -1"}
	expected := "waf.detection.threshold.block: must be > 0; got -1"
	if fe.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, fe.Error())
	}
}

func TestValidate_DisabledSectionsSkipValidation(t *testing.T) {
	cfg := DefaultConfig()
	// Disable sections and put invalid data - should pass because sections are disabled
	cfg.WAF.Detection.Enabled = false
	cfg.WAF.Detection.Threshold.Block = -1
	cfg.WAF.Detection.Threshold.Log = -1

	cfg.WAF.RateLimit.Enabled = false
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{ID: "", Limit: 0, Window: 0, Scope: "bad", Action: "bad"},
	}

	cfg.WAF.IPACL.Enabled = false
	cfg.WAF.IPACL.Whitelist = []string{"not-an-ip"}

	cfg.WAF.Sanitizer.Enabled = false
	cfg.WAF.Sanitizer.MaxURLLength = 0

	cfg.Dashboard.Enabled = false
	cfg.Dashboard.Listen = "bad"

	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no errors when sections are disabled, got: %v", err)
	}
}

func TestValidate_GeoIPRequireReadyRequiresEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.GeoIP.Enabled = false
	cfg.WAF.GeoIP.RequireReady = true

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error when GeoIP require_ready is set while GeoIP is disabled")
	}
	if !strings.Contains(err.Error(), "waf.geoip.require_ready") {
		t.Fatalf("expected waf.geoip.require_ready error, got: %v", err)
	}
}

func TestValidate_ValidModesAllPass(t *testing.T) {
	for _, mode := range []string{"enforce", "monitor", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Mode = mode
			err := Validate(cfg)
			if err != nil {
				t.Fatalf("expected mode %q to be valid, got: %v", mode, err)
			}
		})
	}
}

func TestValidate_ValidLoggingLevelsAllPass(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Logging.Level = level
			err := Validate(cfg)
			if err != nil {
				t.Fatalf("expected logging level %q to be valid, got: %v", level, err)
			}
		})
	}
}

func TestValidate_ValidLoggingFormatsAllPass(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Logging.Format = format
			err := Validate(cfg)
			if err != nil {
				t.Fatalf("expected logging format %q to be valid, got: %v", format, err)
			}
		})
	}
}

func TestValidate_ValidEventsStorageAllPass(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Events.Storage = "memory"
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected storage 'memory' valid, got: %v", err)
	}

	cfg = DefaultConfig()
	cfg.Events.Storage = "file"
	cfg.Events.FilePath = "/tmp/events.jsonl"
	if err := Validate(cfg); err != nil {
		t.Fatalf("expected storage 'file' with path valid, got: %v", err)
	}
}

func TestValidate_ValidRateLimitScopesAndActions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{ID: "r1", Scope: "ip", Limit: 100, Window: time.Minute, Action: "block"},
		{ID: "r2", Scope: "ip+path", Limit: 50, Window: 30 * time.Second, Action: "log"},
	}

	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected valid rate limit rules, got: %v", err)
	}
}

func TestIsValidIPOrCIDR(t *testing.T) {
	valid := []string{
		"192.168.1.1",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"::1",
		"fe80::/10",
		"0.0.0.0",
		"255.255.255.255",
		"2001:db8::1",
		"192.168.0.0/16",
	}
	for _, s := range valid {
		if !isValidIPOrCIDR(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}

	invalid := []string{
		"not-an-ip",
		"999.999.999.999",
		"192.168.1.0/33",
		"abc/def",
		"",
		"192.168.1",
		"1.2.3.4/abc",
	}
	for _, s := range invalid {
		if isValidIPOrCIDR(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

// --- Additional tests for uncovered LoadEnv paths ---

func TestLoadEnv_TLSVars(t *testing.T) {
	cfg := DefaultConfig()

	os.Setenv("GWAF_TLS_ENABLED", "true")
	os.Setenv("GWAF_TLS_LISTEN", ":9443")
	os.Setenv("GWAF_TLS_CERT_FILE", "/etc/ssl/test.pem")
	os.Setenv("GWAF_TLS_KEY_FILE", "/etc/ssl/test.key")
	defer os.Unsetenv("GWAF_TLS_ENABLED")
	defer os.Unsetenv("GWAF_TLS_LISTEN")
	defer os.Unsetenv("GWAF_TLS_CERT_FILE")
	defer os.Unsetenv("GWAF_TLS_KEY_FILE")

	LoadEnv(cfg)

	if !cfg.TLS.Enabled {
		t.Fatal("expected TLS enabled")
	}
	if cfg.TLS.Listen != ":9443" {
		t.Fatalf("expected TLS listen ':9443', got %q", cfg.TLS.Listen)
	}
	if cfg.TLS.CertFile != "/etc/ssl/test.pem" {
		t.Fatalf("expected cert_file, got %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/ssl/test.key" {
		t.Fatalf("expected key_file, got %q", cfg.TLS.KeyFile)
	}
}

func TestLoadEnv_DashboardEnabled(t *testing.T) {
	cfg := DefaultConfig()

	os.Setenv("GWAF_DASHBOARD_ENABLED", "false")
	defer os.Unsetenv("GWAF_DASHBOARD_ENABLED")

	LoadEnv(cfg)

	if cfg.Dashboard.Enabled {
		t.Fatal("expected dashboard disabled from env")
	}
}

func TestLoadEnv_InvalidIntIgnored(t *testing.T) {
	cfg := DefaultConfig()
	originalBlock := cfg.WAF.Detection.Threshold.Block

	os.Setenv("GWAF_WAF_DETECTION_THRESHOLD_BLOCK", "not_a_number")
	defer os.Unsetenv("GWAF_WAF_DETECTION_THRESHOLD_BLOCK")

	LoadEnv(cfg)

	// Should remain unchanged since parsing fails
	if cfg.WAF.Detection.Threshold.Block != originalBlock {
		t.Fatalf("expected threshold unchanged, got %d", cfg.WAF.Detection.Threshold.Block)
	}
}

func TestLoadEnv_InvalidBoolIgnored(t *testing.T) {
	cfg := DefaultConfig()

	os.Setenv("GWAF_TLS_ENABLED", "not_a_bool")
	defer os.Unsetenv("GWAF_TLS_ENABLED")

	LoadEnv(cfg)

	// Should remain unchanged
	if cfg.TLS.Enabled {
		t.Fatal("expected TLS still disabled (invalid bool ignored)")
	}
}

// --- Additional validateListenAddr edge cases ---

func TestValidate_EmptyListenAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for empty listen address")
	}
	ve := err.(*ValidationError)
	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "listen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for 'listen', got: %v", ve.Errors)
	}
}

func TestValidate_ListenAddressInvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ":99999"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for port 99999")
	}
	ve := err.(*ValidationError)
	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "listen" && strings.Contains(fe.Message, "port") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected port error for 'listen', got: %v", ve.Errors)
	}
}

func TestValidate_TLSInvalidListenAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/cert.pem"
	cfg.TLS.KeyFile = "/key.pem"
	cfg.TLS.Listen = "invalid-address"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for invalid TLS listen")
	}
	ve := err.(*ValidationError)
	found := false
	for _, fe := range ve.Errors {
		if fe.Field == "tls.listen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected error for 'tls.listen', got: %v", ve.Errors)
	}
}

func TestValidate_DashboardDisabledSkipsValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Dashboard.Enabled = false
	cfg.Dashboard.Listen = "totally-invalid"
	// Should not error since dashboard is disabled
	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error when dashboard disabled, got: %v", err)
	}
}

func TestValidate_TLSDisabledSkipsValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enabled = false
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	// Should not error since TLS is disabled
	err := Validate(cfg)
	if err != nil {
		t.Fatalf("expected no error when TLS disabled, got: %v", err)
	}
}

func TestLoadFile_PopulateError(t *testing.T) {
	// Write a file with invalid nested values that cause populate errors
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_values.yaml")

	// This should cause a populate error: boolean expected but got a mapping
	badYAML := `tls:
  enabled:
    nested: value`
	if err := os.WriteFile(path, []byte(badYAML), 0o644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid nested boolean value")
	}
	if !strings.Contains(err.Error(), "populating config") {
		t.Fatalf("expected populating config error, got: %v", err)
	}
}

func TestValidateListenAddr_EmptyPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = "host:"
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for empty port")
	}
}

func TestValidateListenAddr_InvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ":99999"
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestValidateListenAddr_NonNumericPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ":abc"
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestValidateListenAddr_InvalidFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = "not-a-host-port"
	err := Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid host:port format")
	}
}

func TestValidateAIAnalysisBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "batch size zero",
			mutate: func(cfg *Config) {
				cfg.WAF.AIAnalysis.BatchSize = 0
			},
			want: "waf.ai_analysis.batch_size",
		},
		{
			name: "batch size too large",
			mutate: func(cfg *Config) {
				cfg.WAF.AIAnalysis.BatchSize = 1001
			},
			want: "must be <= 1000",
		},
		{
			name: "negative token hour limit",
			mutate: func(cfg *Config) {
				cfg.WAF.AIAnalysis.MaxTokensPerHour = -1
			},
			want: "waf.ai_analysis.max_tokens_per_hour",
		},
		{
			name: "negative requests hour limit",
			mutate: func(cfg *Config) {
				cfg.WAF.AIAnalysis.MaxRequestsHour = -1
			},
			want: "waf.ai_analysis.max_requests_per_hour",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.WAF.AIAnalysis.Enabled = true
			tt.mutate(cfg)

			err := Validate(cfg)
			if err == nil {
				t.Fatal("Validate() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateDockerRejectsUnsafeRemoteEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Docker.Enabled = true
	cfg.Docker.SocketPath = "tcp://docker.example.com:2375"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error = nil, want unsafe remote Docker validation error")
	}
	for _, want := range []string{
		"docker.tls_verify",
		"docker.tls_ca_cert",
		"docker.tls_cert",
		"docker.tls_key",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error missing %q: %v", want, err)
		}
	}
}

func TestValidateDockerAcceptsTLSVerifiedRemoteEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Docker.Enabled = true
	cfg.Docker.SocketPath = "tcp://docker.example.com:2376"
	cfg.Docker.TLSVerify = true
	cfg.Docker.TLSCACert = "/etc/guardianwaf/docker/ca.pem"
	cfg.Docker.TLSCert = "/etc/guardianwaf/docker/cert.pem"
	cfg.Docker.TLSKey = "/etc/guardianwaf/docker/key.pem"

	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
