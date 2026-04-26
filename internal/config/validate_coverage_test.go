package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadEnv covers all GWAF_ environment variable setters.
func TestLoadEnv_Coverage(t *testing.T) {
	cfg := DefaultConfig()
	envVars := map[string]string{
		"GWAF_MODE":                              "monitor",
		"GWAF_LISTEN":                            ":9090",
		"GWAF_LOGGING_LEVEL":                     "debug",
		"GWAF_LOGGING_FORMAT":                    "text",
		"GWAF_LOGGING_OUTPUT":                    "stderr",
		"GWAF_WAF_DETECTION_THRESHOLD_BLOCK":     "60",
		"GWAF_WAF_DETECTION_THRESHOLD_LOG":       "30",
		"GWAF_DASHBOARD_LISTEN":                  ":9999",
		"GWAF_DASHBOARD_API_KEY":                 "test-key-123",
		"GWAF_DASHBOARD_ENABLED":                 "true",
		"GWAF_EVENTS_STORAGE":                    "file",
		"GWAF_EVENTS_FILE_PATH":                  "/tmp/events.jsonl",
		"GWAF_EVENTS_MAX_EVENTS":                 "50000",
		"GWAF_TLS_ENABLED":                       "true",
		"GWAF_TLS_LISTEN":                        ":9443",
		"GWAF_TLS_CERT_FILE":                     "/cert.pem",
		"GWAF_TLS_KEY_FILE":                      "/key.pem",
		"GWAF_TRACING_ENABLED":                   "true",
		"GWAF_TRACING_SERVICE_NAME":              "test-svc",
		"GWAF_TRACING_SAMPLING_RATE":             "0.5",
		"GWAF_TRACING_EXPORTER_TYPE":             "stdout",
		"GWAF_LOGGING_MAX_SIZE_MB":               "200",
		"GWAF_LOGGING_MAX_BACKUPS":               "10",
		"GWAF_LOGGING_MAX_AGE_DAYS":              "60",
		"GWAF_COMPLIANCE_ENABLED":                "true",
		"GWAF_COMPLIANCE_FRAMEWORKS":             "pci_dss,gdpr",
		"GWAF_COMPLIANCE_REPORT_DIR":             "/tmp/reports",
		"GWAF_COMPLIANCE_AUDIT_TRAIL_ENABLED":    "true",
	}
	for k, v := range envVars {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}
	LoadEnv(cfg)

	if cfg.Mode != "monitor" {
		t.Errorf("Mode: got %q, want monitor", cfg.Mode)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("Listen: got %q, want :9090", cfg.Listen)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level: got %q, want debug", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Logging.Format: got %q, want text", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "stderr" {
		t.Errorf("Logging.Output: got %q, want stderr", cfg.Logging.Output)
	}
	if cfg.WAF.Detection.Threshold.Block != 60 {
		t.Errorf("Detection.Block: got %d, want 60", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.WAF.Detection.Threshold.Log != 30 {
		t.Errorf("Detection.Log: got %d, want 30", cfg.WAF.Detection.Threshold.Log)
	}
	if cfg.Dashboard.Listen != ":9999" {
		t.Errorf("Dashboard.Listen: got %q, want :9999", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.APIKey != "test-key-123" {
		t.Errorf("Dashboard.APIKey: got %q", cfg.Dashboard.APIKey)
	}
	if !cfg.Dashboard.Enabled {
		t.Error("Dashboard.Enabled: got false, want true")
	}
	if cfg.Events.Storage != "file" {
		t.Errorf("Events.Storage: got %q, want file", cfg.Events.Storage)
	}
	if cfg.Events.FilePath != "/tmp/events.jsonl" {
		t.Errorf("Events.FilePath: got %q", cfg.Events.FilePath)
	}
	if cfg.Events.MaxEvents != 50000 {
		t.Errorf("Events.MaxEvents: got %d, want 50000", cfg.Events.MaxEvents)
	}
	if !cfg.TLS.Enabled {
		t.Error("TLS.Enabled: got false, want true")
	}
	if cfg.TLS.Listen != ":9443" {
		t.Errorf("TLS.Listen: got %q", cfg.TLS.Listen)
	}
	if cfg.TLS.CertFile != "/cert.pem" {
		t.Errorf("TLS.CertFile: got %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/key.pem" {
		t.Errorf("TLS.KeyFile: got %q", cfg.TLS.KeyFile)
	}
	if !cfg.Tracing.Enabled {
		t.Error("Tracing.Enabled: got false, want true")
	}
	if cfg.Tracing.ServiceName != "test-svc" {
		t.Errorf("Tracing.ServiceName: got %q", cfg.Tracing.ServiceName)
	}
	if cfg.Tracing.SamplingRate != 0.5 {
		t.Errorf("Tracing.SamplingRate: got %f, want 0.5", cfg.Tracing.SamplingRate)
	}
	if cfg.Tracing.ExporterType != "stdout" {
		t.Errorf("Tracing.ExporterType: got %q", cfg.Tracing.ExporterType)
	}
	if cfg.Logging.MaxSizeMB != 200 {
		t.Errorf("Logging.MaxSizeMB: got %d, want 200", cfg.Logging.MaxSizeMB)
	}
	if cfg.Logging.MaxBackups != 10 {
		t.Errorf("Logging.MaxBackups: got %d, want 10", cfg.Logging.MaxBackups)
	}
	if cfg.Logging.MaxAgeDays != 60 {
		t.Errorf("Logging.MaxAgeDays: got %d, want 60", cfg.Logging.MaxAgeDays)
	}
	if !cfg.Compliance.Enabled {
		t.Error("Compliance.Enabled: got false, want true")
	}
	if len(cfg.Compliance.Frameworks) != 2 || cfg.Compliance.Frameworks[0] != "pci_dss" {
		t.Errorf("Compliance.Frameworks: got %v", cfg.Compliance.Frameworks)
	}
	if cfg.Compliance.ReportDir != "/tmp/reports" {
		t.Errorf("Compliance.ReportDir: got %q", cfg.Compliance.ReportDir)
	}
	if !cfg.Compliance.AuditTrail.Enabled {
		t.Error("Compliance.AuditTrail.Enabled: got false, want true")
	}
}

// TestLoadEnv_InvalidValues tests that LoadEnv ignores invalid values.
func TestLoadEnv_InvalidValues(t *testing.T) {
	cfg := DefaultConfig()
	origBlock := cfg.WAF.Detection.Threshold.Block

	os.Setenv("GWAF_WAF_DETECTION_THRESHOLD_BLOCK", "notanumber")
	defer os.Unsetenv("GWAF_WAF_DETECTION_THRESHOLD_BLOCK")
	os.Setenv("GWAF_DASHBOARD_ENABLED", "notabool")
	defer os.Unsetenv("GWAF_DASHBOARD_ENABLED")
	os.Setenv("GWAF_TRACING_SAMPLING_RATE", "notafloat")
	defer os.Unsetenv("GWAF_TRACING_SAMPLING_RATE")
	os.Setenv("GWAF_LOGGING_MAX_SIZE_MB", "notanumber")
	defer os.Unsetenv("GWAF_LOGGING_MAX_SIZE_MB")

	LoadEnv(cfg)

	// Should keep original values
	if cfg.WAF.Detection.Threshold.Block != origBlock {
		t.Errorf("Block should be unchanged, got %d", cfg.WAF.Detection.Threshold.Block)
	}
	if cfg.Dashboard.Enabled != true {
		t.Error("Dashboard.Enabled should remain true")
	}
}

// TestLoadDir_EmptyDir tests LoadDir with an existing directory with a minimal config.
func TestLoadDir_EmptyDir(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_loadir_emptydir")
	os.MkdirAll(tmpDir, 0o755)
	defer os.RemoveAll(tmpDir)

	// Create a minimal guardianwaf.yaml
	os.WriteFile(filepath.Join(tmpDir, "guardianwaf.yaml"), []byte("mode: enforce\n"), 0o644)

	cfg, err := LoadDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadDir empty dir: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadDir returned nil config")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("Mode: got %q", cfg.Mode)
	}
}

// TestLoadDir_WithMainConfig tests LoadDir with a main config file.
func TestLoadDir_WithMainConfig(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_loadir_main")
	defer os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0o755)

	mainConfig := []byte("mode: monitor\nlisten: \":7070\"\n")
	os.WriteFile(filepath.Join(tmpDir, "guardianwaf.yaml"), mainConfig, 0o644)

	cfg, err := LoadDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if cfg.Mode != "monitor" {
		t.Errorf("Mode: got %q, want monitor", cfg.Mode)
	}
	if cfg.Listen != ":7070" {
		t.Errorf("Listen: got %q, want :7070", cfg.Listen)
	}
}

// TestLoadDir_WithRules tests LoadDir with rules.d directory.
func TestLoadDir_WithRules(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_loadir_rules")
	defer os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "rules.d"), 0o755)

	os.WriteFile(filepath.Join(tmpDir, "guardianwaf.yaml"), []byte("mode: enforce\n"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "rules.d", "custom.yaml"), []byte(`
custom_rules:
  - id: cr-001
    name: Test Rule
    enabled: true
    action: block
    score: 50
    conditions:
      - field: path
        op: contains
        value: "/admin"
rate_limits:
  - id: rl-001
    scope: ip
    limit: 50
    window: 1m
    action: block
ipacl:
  whitelist:
    - 10.0.0.0/8
  blacklist:
    - 192.168.1.0/24
`), 0o644)

	cfg, err := LoadDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadDir with rules: %v", err)
	}
	if len(cfg.WAF.CustomRules.Rules) != 1 {
		t.Errorf("CustomRules: got %d rules, want 1", len(cfg.WAF.CustomRules.Rules))
	}
	if cfg.WAF.CustomRules.Rules[0].ID != "cr-001" {
		t.Errorf("CustomRule ID: got %q", cfg.WAF.CustomRules.Rules[0].ID)
	}
	if len(cfg.WAF.RateLimit.Rules) < 2 {
		t.Errorf("RateLimit rules: got %d, want >= 2", len(cfg.WAF.RateLimit.Rules))
	}
	found := false
	for _, r := range cfg.WAF.RateLimit.Rules {
		if r.ID == "rl-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("rl-001 not found in rate limit rules")
	}
}

// TestLoadDir_WithDomains tests LoadDir with domains.d directory.
func TestLoadDir_WithDomains(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_loadir_domains")
	defer os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0o755)
	os.MkdirAll(filepath.Join(tmpDir, "domains.d"), 0o755)

	os.WriteFile(filepath.Join(tmpDir, "guardianwaf.yaml"), []byte("mode: enforce\n"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, "domains.d", "api.yaml"), []byte(`
domains:
  - api.example.com
tls:
  cert_file: /certs/api.pem
  key_file: /certs/api.key
routes:
  - path: /v1
    upstream: api-backend
upstreams:
  - name: api-backend
    targets:
      - url: http://localhost:8080
waf:
  detection:
    enabled: true
    threshold:
      block: 60
      log: 30
  rate_limit:
    enabled: true
    rules:
      - id: domain-rl
        scope: ip
        limit: 200
        window: 1m
        action: block
  bot_detection:
    enabled: true
    mode: enforce
  custom_rules:
    rules:
      - id: domain-cr
        name: Domain rule
        enabled: true
        action: block
        score: 40
`), 0o644)

	cfg, err := LoadDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadDir with domains: %v", err)
	}
	if len(cfg.VirtualHosts) != 1 {
		t.Fatalf("VirtualHosts: got %d, want 1", len(cfg.VirtualHosts))
	}
	vh := cfg.VirtualHosts[0]
	if len(vh.Domains) != 1 || vh.Domains[0] != "api.example.com" {
		t.Errorf("Domains: got %v", vh.Domains)
	}
	if vh.TLS.CertFile != "/certs/api.pem" {
		t.Errorf("TLS CertFile: got %q", vh.TLS.CertFile)
	}
	if vh.WAF == nil {
		t.Fatal("WAF override should not be nil")
	}
	if vh.WAF.Detection.Threshold.Block != 60 {
		t.Errorf("WAF detection block: got %d, want 60", vh.WAF.Detection.Threshold.Block)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "api-backend" {
		t.Errorf("Upstreams: got %v", cfg.Upstreams)
	}
}

// TestAppendTenantsFromDir_Coverage tests appendTenantsFromDir with a file path.
func TestAppendTenantsFromDir_Coverage(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_tenants_dir")
	defer os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0o755)

	// Write a tenant file
	os.WriteFile(filepath.Join(tmpDir, "tenant1.yaml"), []byte(`
id: t1
name: Tenant 1
domains:
  - t1.example.com
api_key: key123
active: true
`), 0o644)

	cfg := DefaultConfig()
	// appendTenantsFromDir takes a directory path, reads all .yaml/.yml files
	err := appendTenantsFromDir(tmpDir, cfg)
	if err != nil {
		t.Fatalf("appendTenantsFromDir: %v", err)
	}
	if len(cfg.Tenant.Tenants) != 1 {
		t.Fatalf("Tenants: got %d, want 1", len(cfg.Tenant.Tenants))
	}
	td := cfg.Tenant.Tenants[0]
	if td.ID != "t1" || td.Name != "Tenant 1" {
		t.Errorf("Tenant: got %+v", td)
	}
}

// TestAppendTenantsFromDir_NonExistent tests appendTenantsFromDir with non-existent dir.
func TestAppendTenantsFromDir_NonExistent(t *testing.T) {
	cfg := DefaultConfig()
	err := appendTenantsFromDir("/nonexistent/path", cfg)
	if err != nil {
		t.Fatalf("expected nil for non-existent dir, got: %v", err)
	}
}

// TestLoadDir_InvalidMainConfig tests LoadDir with invalid main config.
func TestLoadDir_InvalidMainConfig(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "gwaf_test_loadir_invalid")
	defer os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0o755)

	os.WriteFile(filepath.Join(tmpDir, "guardianwaf.yaml"), []byte("mode: [invalid\n"), 0o644)

	_, err := LoadDir(tmpDir)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

// TestLoadVirtualHostWAF_Coverage exercises all branches of loadVirtualHostWAF.
func TestLoadVirtualHostWAF_Coverage(t *testing.T) {
	t.Run("nil node", func(t *testing.T) {
		waf, err := loadVirtualHostWAF(nil)
		if waf != nil || err != nil {
			t.Errorf("got waf=%v err=%v, want nil/nil", waf, err)
		}
	})
	t.Run("non-map node", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, Value: "scalar"}
		waf, err := loadVirtualHostWAF(n)
		if waf != nil || err != nil {
			t.Errorf("got waf=%v err=%v, want nil/nil", waf, err)
		}
	})
	t.Run("null waf", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"waf": {Kind: ScalarNode, IsNull: true},
		}}
		waf, err := loadVirtualHostWAF(n)
		if waf != nil || err != nil {
			t.Errorf("got waf=%v err=%v, want nil/nil", waf, err)
		}
	})
	t.Run("waf not a map", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"waf": {Kind: ScalarNode, Value: "string"},
		}, MapKeys: []string{"waf"}}
		waf, err := loadVirtualHostWAF(n)
		if waf != nil || err == nil {
			t.Errorf("got waf=%v err=%v, want nil/error", waf, err)
		}
	})
	t.Run("detection disabled", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"waf": {Kind: MapNode, MapItems: map[string]*Node{
				"detection": {Kind: MapNode, MapItems: map[string]*Node{
					"enabled": {Kind: ScalarNode, Value: "false"},
				}},
			}},
		}, MapKeys: []string{"waf"}}
		waf, err := loadVirtualHostWAF(n)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if waf == nil {
			t.Fatal("expected non-nil waf")
		}
		// DefaultWAFConfig has Detection.Enabled=true, and loadVirtualHostWAF only sets true.
		// So when YAML has "false", it stays true (default).
		if !waf.Detection.Enabled {
			t.Error("detection should remain default (true) since false doesn't set it")
		}
	})
}

// TestParseCustomRule_Coverage tests parseCustomRule edge cases.
func TestParseCustomRule_Coverage(t *testing.T) {
	t.Run("priority negative", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"priority": {Kind: ScalarNode, Value: "-1"},
		}, MapKeys: []string{"priority"}}
		r := parseCustomRule(n)
		if r.Priority != 0 {
			t.Errorf("expected priority 0 for negative, got %d", r.Priority)
		}
	})
	t.Run("score negative", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"score": {Kind: ScalarNode, Value: "-5"},
		}, MapKeys: []string{"score"}}
		r := parseCustomRule(n)
		if r.Score != 0 {
			t.Errorf("expected score 0 for negative, got %d", r.Score)
		}
	})
	t.Run("conditions non-map", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"conditions": {Kind: SequenceNode, Items: []*Node{
				{Kind: ScalarNode, Value: "notamap"},
			}},
		}, MapKeys: []string{"conditions"}}
		r := parseCustomRule(n)
		if len(r.Conditions) != 0 {
			t.Errorf("expected 0 conditions for non-map item, got %d", len(r.Conditions))
		}
	})
}

// TestParseRateLimitRule_Coverage tests parseRateLimitRule edge cases.
func TestParseRateLimitRule_Coverage(t *testing.T) {
	t.Run("limit zero", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"limit": {Kind: ScalarNode, Value: "0"},
		}, MapKeys: []string{"limit"}}
		r := parseRateLimitRule(n)
		if r.Limit != 0 {
			t.Errorf("expected limit 0, got %d", r.Limit)
		}
	})
	t.Run("burst negative", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"burst": {Kind: ScalarNode, Value: "-1"},
		}, MapKeys: []string{"burst"}}
		r := parseRateLimitRule(n)
		if r.Burst != 0 {
			t.Errorf("expected burst 0, got %d", r.Burst)
		}
	})
	t.Run("window invalid", func(t *testing.T) {
		n := &Node{Kind: MapNode, MapItems: map[string]*Node{
			"window": {Kind: ScalarNode, Value: "notaduration"},
		}, MapKeys: []string{"window"}}
		r := parseRateLimitRule(n)
		if r.Window != 0 {
			t.Errorf("expected zero Window for invalid, got %v", r.Window)
		}
	})
}

// TestParseNodeValue tests parseNodeValue for all types.
func TestParseNodeValue_Coverage(t *testing.T) {
	t.Run("nil node", func(t *testing.T) {
		if v := parseNodeValue(nil); v != nil {
			t.Errorf("expected nil, got %v", v)
		}
	})
	t.Run("null node", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, IsNull: true}
		if v := parseNodeValue(n); v != nil {
			t.Errorf("expected nil, got %v", v)
		}
	})
	t.Run("int value", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, Value: "42"}
		v := parseNodeValue(n)
		if vi, ok := v.(int); !ok || vi != 42 {
			t.Errorf("expected int 42, got %v", v)
		}
	})
	t.Run("float value", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, Value: "3.14"}
		v := parseNodeValue(n)
		if vf, ok := v.(float64); !ok || vf != 3.14 {
			t.Errorf("expected float64 3.14, got %v", v)
		}
	})
	t.Run("bool value", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, Value: "true"}
		v := parseNodeValue(n)
		if vb, ok := v.(bool); !ok || !vb {
			t.Errorf("expected bool true, got %v", v)
		}
	})
	t.Run("string value", func(t *testing.T) {
		n := &Node{Kind: ScalarNode, Value: "hello"}
		v := parseNodeValue(n)
		if vs, ok := v.(string); !ok || vs != "hello" {
			t.Errorf("expected string hello, got %v", v)
		}
	})
	t.Run("sequence value", func(t *testing.T) {
		n := &Node{Kind: SequenceNode, Items: []*Node{
			{Kind: ScalarNode, Value: "a"},
			{Kind: ScalarNode, Value: "b"},
		}}
		v := parseNodeValue(n)
		s, ok := v.([]string)
		if !ok || len(s) != 2 || s[0] != "a" || s[1] != "b" {
			t.Errorf("expected [a, b], got %v", v)
		}
	})
}

// TestPopulateAlerting_Emails tests the email section of populateAlerting.
func TestPopulateAlerting_Emails(t *testing.T) {
	yaml := []byte(`
alerting:
  enabled: true
  emails:
    - name: ops
      smtp_host: smtp.example.com
      smtp_port: 587
      username: user
      password: pass
      from: waf@example.com
      to:
        - ops@example.com
      use_tls: true
      events:
        - block
      min_score: 50
      cooldown: 5m
      subject: "[WAF] Alert"
      template: "Event {{EventID}} from {{ClientIP}}"
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}
	if !cfg.Alerting.Enabled {
		t.Error("Alerting should be enabled")
	}
	if len(cfg.Alerting.Emails) != 1 {
		t.Fatalf("expected 1 email config, got %d", len(cfg.Alerting.Emails))
	}
	e := cfg.Alerting.Emails[0]
	if e.SMTPHost != "smtp.example.com" {
		t.Errorf("SMTPHost: got %q", e.SMTPHost)
	}
	if e.SMTPPort != 587 {
		t.Errorf("SMTPPort: got %d", e.SMTPPort)
	}
	if e.Subject != "[WAF] Alert" {
		t.Errorf("Subject: got %q", e.Subject)
	}
	if e.Template != "Event {{EventID}} from {{ClientIP}}" {
		t.Errorf("Template: got %q", e.Template)
	}
	if e.MinScore != 50 {
		t.Errorf("MinScore: got %d", e.MinScore)
	}
	if e.Cooldown != 5*time.Minute {
		t.Errorf("Cooldown: got %v", e.Cooldown)
	}
}

// TestPopulateAlerting_EmailErrors tests email parsing error paths.
func TestPopulateAlerting_EmailErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"invalid smtp_port", "alerting:\n  enabled: true\n  emails:\n    - smtp_port: abc\n      to:\n        - a@b.com\n"},
		{"invalid min_score", "alerting:\n  enabled: true\n  emails:\n    - smtp_host: smtp.example.com\n      to:\n        - a@b.com\n      min_score: abc\n"},
		{"invalid cooldown", "alerting:\n  enabled: true\n  emails:\n    - smtp_host: smtp.example.com\n      to:\n        - a@b.com\n      cooldown: abc\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			cfg := DefaultConfig()
			if err := PopulateFromNode(cfg, node); err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestPopulateFromNode_EmailPort tests email port parsing edge case.
func TestPopulateFromNode_EmailPortNull(t *testing.T) {
	yaml := []byte(`
alerting:
  emails:
    - smtp_host: smtp.example.com
      smtp_port:
      to:
        - a@b.com
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	// smtp_port: null should not error
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}
}

// TestResolveConfigPath tests config path resolution.
func TestResolveConfigPath_Coverage(t *testing.T) {
	t.Run("explicit path", func(t *testing.T) {
		if p := ResolveConfigPath("/etc/guardianwaf/config.yaml"); p != "/etc/guardianwaf/config.yaml" {
			t.Errorf("got %q", p)
		}
	})
	t.Run("env config path", func(t *testing.T) {
		os.Setenv("GWAF_CONFIG_PATH", "/custom/path.yaml")
		defer os.Unsetenv("GWAF_CONFIG_PATH")
		if p := ResolveConfigPath(""); p != "/custom/path.yaml" {
			t.Errorf("got %q", p)
		}
	})
	t.Run("env-based file", func(t *testing.T) {
		os.Unsetenv("GWAF_CONFIG_PATH")
		os.Setenv("GWAF_ENV", "staging")
		defer os.Unsetenv("GWAF_ENV")
		// If the file doesn't exist, falls back to default
		if p := ResolveConfigPath(""); p != "guardianwaf.yaml" {
			t.Logf("ResolveConfigPath returned %q (file may exist)", p)
		}
	})
	t.Run("default", func(t *testing.T) {
		os.Unsetenv("GWAF_CONFIG_PATH")
		os.Unsetenv("GWAF_ENV")
		if p := ResolveConfigPath(""); p != "guardianwaf.yaml" {
			t.Errorf("got %q, want guardianwaf.yaml", p)
		}
	})
}

// TestExpandEnvVars_Coverage tests env var expansion edge cases.
func TestExpandEnvVars_Coverage(t *testing.T) {
	t.Run("escaped dollar", func(t *testing.T) {
		if v := expandEnvVars("$$test"); v != "$test" {
			t.Errorf("got %q, want $test", v)
		}
	})
	t.Run("no brace", func(t *testing.T) {
		if v := expandEnvVars("$NOTANENV"); v != "$NOTANENV" {
			t.Errorf("got %q", v)
		}
	})
	t.Run("unclosed brace", func(t *testing.T) {
		if v := expandEnvVars("${UNDEFINED_VAR"); v != "${UNDEFINED_VAR" {
			t.Errorf("got %q", v)
		}
	})
	t.Run("invalid var name", func(t *testing.T) {
		if v := expandEnvVars("${in valid}"); v != "${in valid}" {
			t.Errorf("got %q", v)
		}
	})
	t.Run("with default", func(t *testing.T) {
		os.Unsetenv("GWAF_TEST_UNSET_VAR_12345")
		v := expandEnvVars("${GWAF_TEST_UNSET_VAR_12345:-fallback}")
		if v != "fallback" {
			t.Errorf("got %q, want fallback", v)
		}
	})
	t.Run("set var", func(t *testing.T) {
		os.Setenv("GWAF_TEST_SET_VAR", "hello")
		defer os.Unsetenv("GWAF_TEST_SET_VAR")
		v := expandEnvVars("${GWAF_TEST_SET_VAR:-fallback}")
		if v != "hello" {
			t.Errorf("got %q, want hello", v)
		}
	})
	t.Run("empty braces", func(t *testing.T) {
		v := expandEnvVars("${}")
		if v != "${}" {
			t.Errorf("got %q", v)
		}
	})
	t.Run("plain text", func(t *testing.T) {
		v := expandEnvVars("just text")
		if v != "just text" {
			t.Errorf("got %q", v)
		}
	})
}

// TestPopulateFromNode_PopulateMLAnomalyFull tests ML anomaly parsing.
func TestPopulateFromNode_MLAnomalyFull(t *testing.T) {
	yaml := []byte(`
waf:
  ml_anomaly:
    enabled: true
    mode: enforce
    threshold: 0.85
    window_size: 200
    min_samples: 100
    feature_buckets: 30
    auto_block: true
    block_threshold: 0.95
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}
	if !cfg.WAF.MLAnomaly.Enabled {
		t.Error("MLAnomaly should be enabled")
	}
	if cfg.WAF.MLAnomaly.Mode != "enforce" {
		t.Errorf("Mode: got %q", cfg.WAF.MLAnomaly.Mode)
	}
	if cfg.WAF.MLAnomaly.Threshold != 0.85 {
		t.Errorf("Threshold: got %f", cfg.WAF.MLAnomaly.Threshold)
	}
	if cfg.WAF.MLAnomaly.WindowSize != 200 {
		t.Errorf("WindowSize: got %d", cfg.WAF.MLAnomaly.WindowSize)
	}
	if cfg.WAF.MLAnomaly.MinSamples != 100 {
		t.Errorf("MinSamples: got %d", cfg.WAF.MLAnomaly.MinSamples)
	}
	if cfg.WAF.MLAnomaly.FeatureBuckets != 30 {
		t.Errorf("FeatureBuckets: got %d", cfg.WAF.MLAnomaly.FeatureBuckets)
	}
	if !cfg.WAF.MLAnomaly.AutoBlock {
		t.Error("AutoBlock should be true")
	}
	if cfg.WAF.MLAnomaly.BlockThreshold != 0.95 {
		t.Errorf("BlockThreshold: got %f", cfg.WAF.MLAnomaly.BlockThreshold)
	}
}

// TestPopulateFromNode_APIDiscoveryFull tests API discovery parsing.
func TestPopulateFromNode_APIDiscoveryFull(t *testing.T) {
	yaml := []byte(`
waf:
  api_discovery:
    enabled: true
    capture_mode: active
    ring_buffer_size: 5000
    min_samples: 50
    cluster_threshold: 0.9
    export_path: /tmp/api-disc
    export_format: json
    auto_export: true
    export_interval: 12h
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}
	if !cfg.WAF.APIDiscovery.Enabled {
		t.Error("APIDiscovery should be enabled")
	}
	if cfg.WAF.APIDiscovery.CaptureMode != "active" {
		t.Errorf("CaptureMode: got %q", cfg.WAF.APIDiscovery.CaptureMode)
	}
	if cfg.WAF.APIDiscovery.ExportFormat != "json" {
		t.Errorf("ExportFormat: got %q", cfg.WAF.APIDiscovery.ExportFormat)
	}
}

// TestPopulateFromNode_GraphQLFull tests GraphQL parsing.
func TestPopulateFromNode_GraphQLFull(t *testing.T) {
	yaml := []byte(`
waf:
  graphql:
    enabled: true
    max_depth: 5
    max_complexity: 500
    block_introspection: false
    allow_endpoints:
      - /graphql
      - /v2/graphql
`)
	node, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}
	if !cfg.WAF.GraphQL.Enabled {
		t.Error("GraphQL should be enabled")
	}
	if cfg.WAF.GraphQL.MaxDepth != 5 {
		t.Errorf("MaxDepth: got %d", cfg.WAF.GraphQL.MaxDepth)
	}
	if cfg.WAF.GraphQL.MaxComplexity != 500 {
		t.Errorf("MaxComplexity: got %d", cfg.WAF.GraphQL.MaxComplexity)
	}
	if cfg.WAF.GraphQL.BlockIntrospection {
		t.Error("BlockIntrospection should be false")
	}
	if len(cfg.WAF.GraphQL.AllowEndpoints) != 2 {
		t.Errorf("AllowEndpoints: got %d", len(cfg.WAF.GraphQL.AllowEndpoints))
	}
}
