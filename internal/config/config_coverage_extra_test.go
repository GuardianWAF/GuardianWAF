package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- defaults.go: error paths ---

func TestPopulateFromNode_AIAnalysisErrors(t *testing.T) {
	if err := populateAIAnalysis(&AIAnalysisConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map node, got %v", err)
	}

	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"enabled_bool", "waf:\n  ai_analysis:\n    enabled: notbool", "enabled:"},
		{"batch_size_int", "waf:\n  ai_analysis:\n    batch_size: bad", "batch_size:"},
		{"batch_interval_dur", "waf:\n  ai_analysis:\n    batch_interval: bad", "batch_interval:"},
		{"min_score_int", "waf:\n  ai_analysis:\n    min_score: bad", "min_score:"},
		{"max_tokens_per_hour_int", "waf:\n  ai_analysis:\n    max_tokens_per_hour: bad", "max_tokens_per_hour:"},
		{"max_tokens_per_day_int", "waf:\n  ai_analysis:\n    max_tokens_per_day: bad", "max_tokens_per_day:"},
		{"max_requests_per_hour_int", "waf:\n  ai_analysis:\n    max_requests_per_hour: bad", "max_requests_per_hour:"},
		{"auto_block_bool", "waf:\n  ai_analysis:\n    auto_block: bad", "auto_block:"},
		{"auto_block_ttl_dur", "waf:\n  ai_analysis:\n    auto_block_ttl: bad", "auto_block_ttl:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			cfg := DefaultConfig()
			err = PopulateFromNode(cfg, node)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPopulateFromNode_DockerErrors(t *testing.T) {
	if err := populateDocker(&DockerConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"enabled_bool", "docker:\n  enabled: bad", "enabled:"},
		{"poll_interval_dur", "docker:\n  poll_interval: bad", "poll_interval:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			cfg := DefaultConfig()
			err = PopulateFromNode(cfg, node)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPopulateFromNode_TLSErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"tls_enabled_bool", "tls:\n  enabled: bad", "tls: enabled:"},
		{"tls_http_redirect_bool", "tls:\n  http_redirect: bad", "tls: http_redirect:"},
		{"acme_enabled_bool", "tls:\n  acme:\n    enabled: bad", "tls: acme: enabled:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			cfg := DefaultConfig()
			err = PopulateFromNode(cfg, node)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPopulateFromNode_UpstreamErrors(t *testing.T) {
	node, _ := Parse([]byte("upstreams:\n  - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map upstream item: %v", err)
	}

	node, _ = Parse([]byte("upstreams:\n  - name: u1\n    targets:\n      - url: http://a\n        weight: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "target weight") {
		t.Fatalf("expected target weight error, got %v", err)
	}

	node, _ = Parse([]byte("upstreams:\n  - name: u1\n    health_check:\n      interval: bad"))
	err = PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "health_check: interval") {
		t.Fatalf("expected health_check interval error, got %v", err)
	}

	node, _ = Parse([]byte("upstreams:\n  - name: u1\n    targets:\n      - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map target: %v", err)
	}
}

func TestPopulateFromNode_RouteErrors(t *testing.T) {
	node, _ := Parse([]byte("routes:\n  - path: /\n    strip_prefix: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "strip_prefix") {
		t.Fatalf("expected strip_prefix error, got %v", err)
	}

	node, _ = Parse([]byte("routes:\n  - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map route: %v", err)
	}
}

func TestPopulateFromNode_VirtualHostErrors(t *testing.T) {
	node, _ := Parse([]byte("virtual_hosts:\n  - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map vhost: %v", err)
	}

	node, _ = Parse([]byte("virtual_hosts:\n  - domains:\n      - example.com\n    routes:\n      - path: /\n        strip_prefix: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "routes: strip_prefix") {
		t.Fatalf("expected routes error inside vhost, got %v", err)
	}
}

func TestPopulateFromNode_WAFChallengeError(t *testing.T) {
	if err := populateChallenge(&ChallengeConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	node, _ := Parse([]byte("waf:\n  challenge:\n    enabled: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "challenge: enabled") {
		t.Fatalf("expected challenge enabled error, got %v", err)
	}
	node, _ = Parse([]byte("waf:\n  challenge:\n    difficulty: bad"))
	err = PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "challenge: difficulty") {
		t.Fatalf("expected challenge difficulty error, got %v", err)
	}
	node, _ = Parse([]byte("waf:\n  challenge:\n    cookie_ttl: bad"))
	err = PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "challenge: cookie_ttl") {
		t.Fatalf("expected challenge cookie_ttl error, got %v", err)
	}
}

func TestPopulateFromNode_WAFIPACLError(t *testing.T) {
	if err := populateIPACL(&IPACLConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  ip_acl:\n    enabled: bad", "ip_acl: enabled"},
		{"waf:\n  ip_acl:\n    auto_ban:\n      enabled: bad", "ip_acl: auto_ban.enabled"},
		{"waf:\n  ip_acl:\n    auto_ban:\n      default_ttl: bad", "ip_acl: auto_ban.default_ttl"},
		{"waf:\n  ip_acl:\n    auto_ban:\n      max_ttl: bad", "ip_acl: auto_ban.max_ttl"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_WAFRateLimitError(t *testing.T) {
	if err := populateRateLimit(&RateLimitConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}

	node, _ := Parse([]byte("waf:\n  rate_limit:\n    rules:\n      - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map rule: %v", err)
	}

	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  rate_limit:\n    enabled: bad", "rate_limit: enabled"},
		{"waf:\n  rate_limit:\n    rules:\n      - id: r1\n        limit: bad", "rate_limit: rule limit"},
		{"waf:\n  rate_limit:\n    rules:\n      - id: r1\n        window: bad", "rate_limit: rule window"},
		{"waf:\n  rate_limit:\n    rules:\n      - id: r1\n        burst: bad", "rate_limit: rule burst"},
		{"waf:\n  rate_limit:\n    rules:\n      - id: r1\n        auto_ban_after: bad", "rate_limit: rule auto_ban_after"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_WAFSanitizerError(t *testing.T) {
	if err := populateSanitizer(&SanitizerConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}

	node, _ := Parse([]byte("waf:\n  sanitizer:\n    path_overrides:\n      - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map override: %v", err)
	}

	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  sanitizer:\n    enabled: bad", "sanitizer: enabled"},
		{"waf:\n  sanitizer:\n    max_url_length: bad", "sanitizer: max_url_length"},
		{"waf:\n  sanitizer:\n    max_header_size: bad", "sanitizer: max_header_size"},
		{"waf:\n  sanitizer:\n    max_header_count: bad", "sanitizer: max_header_count"},
		{"waf:\n  sanitizer:\n    max_body_size: bad", "sanitizer: max_body_size"},
		{"waf:\n  sanitizer:\n    max_cookie_size: bad", "sanitizer: max_cookie_size"},
		{"waf:\n  sanitizer:\n    block_null_bytes: bad", "sanitizer: block_null_bytes"},
		{"waf:\n  sanitizer:\n    normalize_encoding: bad", "sanitizer: normalize_encoding"},
		{"waf:\n  sanitizer:\n    strip_hop_by_hop: bad", "sanitizer: strip_hop_by_hop"},
		{"waf:\n  sanitizer:\n    path_overrides:\n      - path: /api\n        max_body_size: bad", "sanitizer: path_override max_body_size"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_WAFDetectionError(t *testing.T) {
	if err := populateDetection(&DetectionConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}

	node, _ := Parse([]byte("waf:\n  detection:\n    detectors:\n      sqli:\n        enabled: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "detectors.sqli.enabled") {
		t.Fatalf("expected detectors sqli enabled error, got %v", err)
	}
	node, _ = Parse([]byte("waf:\n  detection:\n    detectors:\n      sqli:\n        multiplier: bad"))
	err = PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "detectors.sqli.multiplier") {
		t.Fatalf("expected detectors sqli multiplier error, got %v", err)
	}

	node, _ = Parse([]byte("waf:\n  detection:\n    exclusions:\n      - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map exclusion: %v", err)
	}

	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  detection:\n    enabled: bad", "detection: enabled"},
		{"waf:\n  detection:\n    threshold:\n      block: bad", "detection: threshold.block"},
		{"waf:\n  detection:\n    threshold:\n      log: bad", "detection: threshold.log"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_WAFBotDetectionError(t *testing.T) {
	if err := populateBotDetection(&BotDetectionConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  bot_detection:\n    enabled: bad", "bot_detection: enabled"},
		{"waf:\n  bot_detection:\n    tls_fingerprint:\n      enabled: bad", "bot_detection: tls_fingerprint.enabled"},
		{"waf:\n  bot_detection:\n    user_agent:\n      enabled: bad", "bot_detection: user_agent.enabled"},
		{"waf:\n  bot_detection:\n    user_agent:\n      block_empty: bad", "bot_detection: user_agent.block_empty"},
		{"waf:\n  bot_detection:\n    user_agent:\n      block_known_scanners: bad", "bot_detection: user_agent.block_known_scanners"},
		{"waf:\n  bot_detection:\n    behavior:\n      enabled: bad", "bot_detection: behavior.enabled"},
		{"waf:\n  bot_detection:\n    behavior:\n      window: bad", "bot_detection: behavior.window"},
		{"waf:\n  bot_detection:\n    behavior:\n      rps_threshold: bad", "bot_detection: behavior.rps_threshold"},
		{"waf:\n  bot_detection:\n    behavior:\n      error_rate_threshold: bad", "bot_detection: behavior.error_rate_threshold"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_WAFResponseError(t *testing.T) {
	if err := populateResponse(&ResponseConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	if err := populateSecurityHeaders(&SecurityHeadersConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	if err := populateDataMasking(&DataMaskingConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		yaml string
		want string
	}{
		{"waf:\n  response:\n    security_headers:\n      enabled: bad", "response: security_headers: enabled"},
		{"waf:\n  response:\n    security_headers:\n      hsts:\n        enabled: bad", "response: security_headers: hsts.enabled"},
		{"waf:\n  response:\n    security_headers:\n      hsts:\n        max_age: bad", "response: security_headers: hsts.max_age"},
		{"waf:\n  response:\n    security_headers:\n      hsts:\n        include_subdomains: bad", "response: security_headers: hsts.include_subdomains"},
		{"waf:\n  response:\n    security_headers:\n      x_content_type_options: bad", "response: security_headers: x_content_type_options"},
		{"waf:\n  response:\n    data_masking:\n      enabled: bad", "response: data_masking: enabled"},
		{"waf:\n  response:\n    data_masking:\n      mask_credit_cards: bad", "response: data_masking: mask_credit_cards"},
		{"waf:\n  response:\n    data_masking:\n      mask_ssn: bad", "response: data_masking: mask_ssn"},
		{"waf:\n  response:\n    data_masking:\n      mask_api_keys: bad", "response: data_masking: mask_api_keys"},
		{"waf:\n  response:\n    data_masking:\n      strip_stack_traces: bad", "response: data_masking: strip_stack_traces"},
		{"waf:\n  response:\n    error_pages:\n      enabled: bad", "response: error_pages.enabled"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_DashboardErrorExtra(t *testing.T) {
	if err := populateDashboard(&DashboardConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		yaml string
		want string
	}{
		{"dashboard:\n  enabled: bad", "dashboard: enabled"},
		{"dashboard:\n  tls: bad", "dashboard: tls"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_MCPErrorExtra(t *testing.T) {
	if err := populateMCP(&MCPConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	node, _ := Parse([]byte("mcp:\n  enabled: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "mcp: enabled") {
		t.Fatalf("expected mcp enabled error, got %v", err)
	}
}

func TestPopulateFromNode_LoggingErrorExtra(t *testing.T) {
	if err := populateLogging(&LogConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	cases := []struct {
		yaml string
		want string
	}{
		{"logging:\n  log_allowed: bad", "logging: log_allowed"},
		{"logging:\n  log_blocked: bad", "logging: log_blocked"},
		{"logging:\n  log_body: bad", "logging: log_body"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}
}

func TestPopulateFromNode_EventsErrorExtra(t *testing.T) {
	if err := populateEvents(&EventsConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}
	node, _ := Parse([]byte("events:\n  max_events: bad"))
	err := PopulateFromNode(DefaultConfig(), node)
	if err == nil || !strings.Contains(err.Error(), "events: max_events") {
		t.Fatalf("expected events max_events error, got %v", err)
	}
}

// --- serialize.go direct tests ---

func TestMarshalField_EmptyString(t *testing.T) {
	var b strings.Builder
	marshalField(&b, "", "key", reflect.ValueOf(""), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for empty string, got %q", b.String())
	}
}

func TestMarshalField_ZeroDuration(t *testing.T) {
	var b strings.Builder
	marshalField(&b, "", "key", reflect.ValueOf(time.Duration(0)), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for zero duration, got %q", b.String())
	}
}

func TestMarshalField_Float64Integer(t *testing.T) {
	var b strings.Builder
	marshalField(&b, "", "key", reflect.ValueOf(2.0), 0)
	if b.String() != "key: 2\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalField_Float64Fractional(t *testing.T) {
	var b strings.Builder
	marshalField(&b, "", "key", reflect.ValueOf(2.5), 0)
	if b.String() != "key: 2.5\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalField_EmptyMap(t *testing.T) {
	var b strings.Builder
	marshalField(&b, "", "key", reflect.ValueOf(map[string]string{}), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for empty map, got %q", b.String())
	}
}

func TestMarshalField_NilInterface(t *testing.T) {
	var b strings.Builder
	var x any
	marshalField(&b, "", "key", reflect.ValueOf(&x).Elem(), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for nil interface, got %q", b.String())
	}
}

func TestMarshalField_NonNilInterface(t *testing.T) {
	var b strings.Builder
	var x any = "hello"
	marshalField(&b, "", "key", reflect.ValueOf(&x).Elem(), 0)
	if b.String() != "key: hello\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalSlice_Default(t *testing.T) {
	var b strings.Builder
	marshalSlice(&b, "", "key", reflect.ValueOf([]int{1, 2}), 0)
	want := "key:\n  - 1\n  - 2\n"
	if b.String() != want {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalSlice_StructSkipTag(t *testing.T) {
	type Item struct {
		A string `yaml:"-"`
		B string
	}
	var b strings.Builder
	marshalSlice(&b, "", "items", reflect.ValueOf([]Item{{A: "x", B: "y"}}), 0)
	if strings.Contains(b.String(), "a:") || strings.Contains(b.String(), "b:") {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalStruct_SkipZeroNested(t *testing.T) {
	type Inner struct {
		A string `yaml:"a"`
	}
	type Outer struct {
		Inner Inner `yaml:"inner"`
	}
	var b strings.Builder
	marshalStruct(&b, reflect.ValueOf(Outer{}), reflect.TypeOf(Outer{}), 1)
	if b.String() != "" {
		t.Errorf("expected skipping zero nested struct, got %q", b.String())
	}
}

func TestMarshalStruct_SkipTag(t *testing.T) {
	type Outer struct {
		A string `yaml:"-"`
		B string
	}
	var b strings.Builder
	marshalStruct(&b, reflect.ValueOf(Outer{A: "x", B: "y"}), reflect.TypeOf(Outer{}), 0)
	if strings.Contains(b.String(), "a:") || strings.Contains(b.String(), "b:") {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_StringQuoted(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(":"), 0)
	if b.String() != "k: \":\"\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_StringPlain(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf("hello"), 0)
	if b.String() != "k: hello\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_Int(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(42), 0)
	if b.String() != "k: 42\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_DurationExtra(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(30*time.Second), 0)
	if b.String() != "k: 30s\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_Float64Integer(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(3.0), 0)
	if b.String() != "k: 3\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_Float64Fractional(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(3.14), 0)
	if !strings.HasPrefix(b.String(), "k: 3.14") {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_EmptySlice(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf([]string{}), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for empty slice, got %q", b.String())
	}
}

func TestMarshalInlineField_NonStringSlice(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf([]int{1}), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for non-string slice, got %q", b.String())
	}
}

func TestMarshalInlineField_StructExtra(t *testing.T) {
	type Inner struct {
		A string `yaml:"a"`
	}
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(Inner{A: "x"}), 1)
	if !strings.Contains(b.String(), "k:\n  a: x") {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_InterfaceNil(t *testing.T) {
	var b strings.Builder
	var x any
	marshalInlineField(&b, "k", reflect.ValueOf(&x).Elem(), 0)
	if b.String() != "" {
		t.Errorf("expected empty output for nil interface, got %q", b.String())
	}
}

func TestMarshalInlineField_InterfaceNonNil(t *testing.T) {
	var b strings.Builder
	var x any = "hello"
	marshalInlineField(&b, "k", reflect.ValueOf(&x).Elem(), 0)
	if b.String() != "k: hello\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalMap_InterfaceScalar(t *testing.T) {
	var b strings.Builder
	m := map[string]any{"k": "v"}
	marshalMap(&b, reflect.ValueOf(m), 0)
	if b.String() != "k: v\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestIsZeroValue_InterfaceNil(t *testing.T) {
	var x any
	if !isZeroValue(reflect.ValueOf(&x).Elem()) {
		t.Error("expected nil interface to be zero")
	}
}

func TestIsZeroValue_Unsupported(t *testing.T) {
	ch := make(chan int)
	if isZeroValue(reflect.ValueOf(ch)) {
		t.Error("expected unsupported kind to be non-zero")
	}
}

// --- yaml.go edge tests ---

func TestParse_MappingSequenceItemBreak(t *testing.T) {
	node, err := Parse([]byte("a: 1\n- item\nb: 2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Get("a") == nil {
		t.Error("expected key a")
	}
	if node.Get("b") != nil {
		t.Error("expected mapping to stop before b")
	}
}

func TestParse_MappingNonKVBreak(t *testing.T) {
	node, err := Parse([]byte("a: 1\nnotkv\nb: 2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Get("a") == nil {
		t.Error("expected key a")
	}
	if node.Get("b") != nil {
		t.Error("expected mapping to stop before b")
	}
}

func TestParse_MappingIndentedBreak(t *testing.T) {
	node, err := Parse([]byte("key: value\n    over: 1\nnext: 2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Get("key") == nil {
		t.Error("expected key key")
	}
	if node.Get("next") != nil {
		t.Error("expected mapping to stop before next")
	}
}

func TestParse_FlowMapError(t *testing.T) {
	_, err := Parse([]byte("key: {bad}"))
	if err == nil {
		t.Fatal("expected error for invalid flow map")
	}
}

func TestParse_BlockSequenceIndentMismatch(t *testing.T) {
	node, err := Parse([]byte("- a\n  b: 1\nc: 2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Slice()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestParse_BlockSequenceNonItemBreak(t *testing.T) {
	node, err := Parse([]byte("- a\nnot_seq: 1\nb: 2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Slice()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestParse_BlockSequenceNestedMapResolveError(t *testing.T) {
	_, err := Parse([]byte("- k: {bad}"))
	if err == nil {
		t.Fatal("expected error for bad flow map in nested map")
	}
}

func TestParse_BlockSequenceNestedMapWrongIndent(t *testing.T) {
	node, err := Parse([]byte("- k: v\n   wrong: 1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Slice()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestParse_BlockSequenceNestedMapNonKV(t *testing.T) {
	node, err := Parse([]byte("- k: v\n  notkv"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items := node.Slice()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestParse_BlockSequenceNestedMapExtraKeyError(t *testing.T) {
	_, err := Parse([]byte("- k: v\n  k2: {bad}"))
	if err == nil {
		t.Fatal("expected error for bad flow map in extra key")
	}
}

func TestParse_BlockSequenceFlowSeqError(t *testing.T) {
	_, err := Parse([]byte("- [bad"))
	if err == nil {
		t.Fatal("expected error for bad flow sequence")
	}
}

func TestParse_BlockSequenceFlowMapError(t *testing.T) {
	_, err := Parse([]byte("- {bad}"))
	if err == nil {
		t.Fatal("expected error for bad flow map")
	}
}

func TestParse_BlockSequenceEmptyDashMappingDepthError(t *testing.T) {
	p := &parser{
		lines:   []string{"- ", "  key: value"},
		pos:     0,
		maxNest: 0,
	}
	_, err := p.parseBlockSequence(0, 0)
	if err == nil {
		t.Fatal("expected depth error")
	}
}

func TestParse_LiteralBlockIndentDrop(t *testing.T) {
	node, err := Parse([]byte("key: |\n  line1\n not_enough"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := node.Get("key").String()
	if !strings.Contains(v, "line1") {
		t.Errorf("expected line1 in output, got %q", v)
	}
	if strings.Contains(v, "not_enough") {
		t.Error("did not expect not_enough")
	}
}

func TestParse_LiteralBlockKeepSingleLine(t *testing.T) {
	node, err := Parse([]byte("key: |+\n  hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := node.Get("key").String()
	if v != "hello\n" {
		t.Errorf("expected 'hello\\n', got %q", v)
	}
}

func TestParse_FoldedBlockIndentDrop(t *testing.T) {
	node, err := Parse([]byte("key: >\n  line1\n not_enough"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := node.Get("key").String()
	if !strings.Contains(v, "line1") {
		t.Errorf("expected line1, got %q", v)
	}
	if strings.Contains(v, "not_enough") {
		t.Error("did not expect not_enough")
	}
}

func TestParse_FlowSequenceNestedError(t *testing.T) {
	_, err := Parse([]byte("key: [[bad]"))
	if err == nil {
		t.Fatal("expected error for nested invalid flow sequence")
	}
}

func TestParse_FlowSequenceNestedMapError(t *testing.T) {
	_, err := Parse([]byte("key: [ {bad} ]"))
	if err == nil {
		t.Fatal("expected error for nested invalid flow map")
	}
}

func TestCountIndent_AllSpaces(t *testing.T) {
	if got := countIndent("   "); got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
	if got := countIndent("\t\t"); got != 2 {
		t.Errorf("expected 2, got %d", got)
	}
}

// --- Additional reachability tests for remaining uncovered lines ---

func TestPopulateACME_NonMapNode(t *testing.T) {
	if err := populateACME(&ACMEConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map node, got %v", err)
	}
}

func TestPopulateAIAnalysis_ValidFields(t *testing.T) {
	node := &Node{
		Kind:    MapNode,
		MapKeys: []string{"enabled", "store_path", "catalog_url", "auto_block"},
		MapItems: map[string]*Node{
			"enabled":     {Kind: ScalarNode, Value: "true"},
			"store_path":  {Kind: ScalarNode, Value: "/tmp/ai"},
			"catalog_url": {Kind: ScalarNode, Value: "https://example.com/catalog"},
			"auto_block":  {Kind: ScalarNode, Value: "false"},
		},
	}
	ai := AIAnalysisConfig{}
	if err := populateAIAnalysis(&ai, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ai.Enabled {
		t.Error("expected Enabled true")
	}
	if ai.StorePath != "/tmp/ai" {
		t.Errorf("unexpected StorePath: %q", ai.StorePath)
	}
	if ai.AutoBlock {
		t.Error("expected AutoBlock false")
	}
}

func TestPopulateDetection_NilMapAndNonMapSub(t *testing.T) {
	node := &Node{
		Kind:    MapNode,
		MapKeys: []string{"detectors"},
		MapItems: map[string]*Node{
			"detectors": {
				Kind:    MapNode,
				MapKeys: []string{"sqli", "xss"},
				MapItems: map[string]*Node{
					"sqli": {Kind: ScalarNode},
					"xss": {
						Kind:    MapNode,
						MapKeys: []string{"enabled"},
						MapItems: map[string]*Node{
							"enabled": {Kind: ScalarNode, Value: "true"},
						},
					},
				},
			},
		},
	}
	det := DetectionConfig{}
	if err := populateDetection(&det, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if det.Detectors == nil {
		t.Fatal("expected Detectors map initialized")
	}
	if _, ok := det.Detectors["xss"]; !ok {
		t.Error("expected xss detector populated")
	}
}

func TestPopulateDocker_ValidEnabled(t *testing.T) {
	node := &Node{
		Kind:    MapNode,
		MapKeys: []string{"enabled"},
		MapItems: map[string]*Node{
			"enabled": {Kind: ScalarNode, Value: "true"},
		},
	}
	d := DockerConfig{}
	if err := populateDocker(&d, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Enabled {
		t.Error("expected Enabled true")
	}
}

func TestMarshalInlineField_BoolExtra(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf(true), 0)
	if b.String() != "k: true\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

func TestMarshalInlineField_StringSlice(t *testing.T) {
	var b strings.Builder
	marshalInlineField(&b, "k", reflect.ValueOf([]string{"a", "b"}), 0)
	if b.String() != "k: [a, b]\n" {
		t.Errorf("unexpected output: %q", b.String())
	}
}

// --- Alerting ---

func TestPopulateFromNode_AlertingErrors(t *testing.T) {
	if err := populateAlerting(&AlertingConfig{}, &Node{Kind: ScalarNode}); err != nil {
		t.Errorf("expected nil for non-map, got %v", err)
	}

	cases := []struct {
		yaml string
		want string
	}{
		{"alerting:\n  enabled: bad", "alerting: enabled"},
		{"alerting:\n  webhooks:\n    - name: wh1\n      min_score: bad", "alerting: min_score"},
		{"alerting:\n  webhooks:\n    - name: wh1\n      cooldown: bad", "alerting: cooldown"},
	}
	for _, tc := range cases {
		node, _ := Parse([]byte(tc.yaml))
		err := PopulateFromNode(DefaultConfig(), node)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("expected error containing %q, got %v", tc.want, err)
		}
	}

	// non-map webhook item should be skipped
	node, _ := Parse([]byte("alerting:\n  webhooks:\n    - notmap"))
	if err := PopulateFromNode(DefaultConfig(), node); err != nil {
		t.Fatalf("unexpected error for non-map webhook item: %v", err)
	}
}

func TestPopulateAlerting_Valid(t *testing.T) {
	node := &Node{
		Kind:    MapNode,
		MapKeys: []string{"enabled", "webhooks"},
		MapItems: map[string]*Node{
			"enabled": {Kind: ScalarNode, Value: "true"},
			"webhooks": {
				Kind: SequenceNode,
				Items: []*Node{{
					Kind:    MapNode,
					MapKeys: []string{"name", "url", "type", "events", "min_score", "cooldown", "headers"},
					MapItems: map[string]*Node{
						"name":      {Kind: ScalarNode, Value: "wh1"},
						"url":       {Kind: ScalarNode, Value: "http://example.com"},
						"type":      {Kind: ScalarNode, Value: "slack"},
						"events":    {Kind: SequenceNode, Items: []*Node{{Kind: ScalarNode, Value: "block"}}},
						"min_score": {Kind: ScalarNode, Value: "50"},
						"cooldown":  {Kind: ScalarNode, Value: "1m"},
						"headers": {
							Kind:    MapNode,
							MapKeys: []string{"X-Key"},
							MapItems: map[string]*Node{
								"X-Key": {Kind: ScalarNode, Value: "secret"},
							},
						},
					},
				}},
			},
		},
	}
	alert := AlertingConfig{}
	if err := populateAlerting(&alert, node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !alert.Enabled {
		t.Error("expected Enabled true")
	}
	if len(alert.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(alert.Webhooks))
	}
	wh := alert.Webhooks[0]
	if wh.Name != "wh1" || wh.URL != "http://example.com" || wh.Type != "slack" {
		t.Errorf("unexpected webhook fields: %+v", wh)
	}
	if wh.MinScore != 50 {
		t.Errorf("unexpected min_score: %d", wh.MinScore)
	}
	if wh.Cooldown != time.Minute {
		t.Errorf("unexpected cooldown: %v", wh.Cooldown)
	}
	if wh.Headers["X-Key"] != "secret" {
		t.Errorf("unexpected header: %v", wh.Headers)
	}
}
