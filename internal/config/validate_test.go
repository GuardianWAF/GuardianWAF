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
