package config

import (
	"reflect"
	"testing"
	"time"
)

func TestPopulateFromNode_MajorNestedSectionsMatchExpectedStructs(t *testing.T) {
	yaml := `waf:
  zero_trust:
    enabled: true
    require_mtls: true
    require_attestation: true
    session_ttl: 15m
    attestation_ttl: 5m
    trusted_ca_path: /etc/guardianwaf/ca.pem
    device_trust_threshold: high
    allow_bypass_paths: [/livez, /readyz]
  cache:
    enabled: true
    backend: redis
    ttl: 2m
    max_size: 256
    redis_addr: redis:6379
    redis_password: redis-secret
    redis_db: 3
    prefix: gwaf
    cache_methods: [GET, HEAD]
    cache_status_codes: [200, 204, 301]
    skip_paths: [/admin, /api/private]
    max_cache_size: 512
    stale_while_revalidate: true
  replay:
    enabled: true
    storage_path: /var/lib/guardianwaf/replay
    format: json
    max_file_size: 64
    max_files: 8
    retention_days: 21
    capture_request: true
    capture_response: true
    capture_headers: [X-Request-ID, Authorization]
    skip_paths: [/healthz, /metrics]
    skip_methods: [OPTIONS]
    compress: true
    replay:
      enabled: true
      target_base_url: https://replay.example.com
      rate_limit: 25
      concurrency: 4
      timeout: 3s
      follow_redirects: true
      modify_host: true
      preserve_ids: true
      dry_run: true
      headers:
        X-Replay: "1"
        X-Env: staging
  canary:
    enabled: true
    canary_version: v2
    stable_upstream: stable
    canary_upstream: canary
    strategy: percentage
    percentage: 15
    header_name: X-Canary
    header_value: "1"
    cookie_name: gwaf_canary
    cookie_value: v2
    regions: [us-east-1, eu-west-1]
    auto_rollback: true
    error_threshold: 0.05
    latency_threshold: 250ms
    health_check_path: /readyz
    metadata:
      owner: platform
      ticket: REL-42
  analytics:
    enabled: true
    storage_path: /var/lib/guardianwaf/analytics
    retention_days: 30
    flush_interval: 15s
    max_data_points: 10000
    enable_time_series: true
  cluster_sync:
    enabled: true
    node_id: node-a
    node_name: Node A
    listen: ":9444"
    port: 9444
    shared_secret: cluster-secret
    sync_interval: 10s
    conflict_resolution: last_write_wins
    max_retries: 3
    retry_delay: 2s
    clusters:
      - id: cluster-a
        name: Cluster A
        sync_scope: all
        bidirectional: true
        nodes:
          - id: node-b
            name: Node B
            address: https://node-b.example.com
          - id: node-c
            name: Node C
            address: https://node-c.example.com
  remediation:
    enabled: true
    auto_apply: true
    confidence_threshold: 90
    max_rules_per_day: 20
    rule_ttl: 24h
    excluded_paths: [/admin, /internal]
    storage_path: /var/lib/guardianwaf/remediation.json
  websocket:
    enabled: true
    max_message_size: 1048576
    max_frame_size: 65536
    rate_limit_per_second: 10
    rate_limit_burst: 20
    allowed_origins: [https://app.example.com, https://admin.example.com]
    blocked_extensions: [permessage-deflate]
    block_empty_messages: true
    block_binary_messages: true
    max_concurrent_per_ip: 5
    handshake_timeout: 3s
    idle_timeout: 1m
    scan_payloads: true
  siem:
    enabled: true
    endpoint: https://siem.example.com/events
    format: json
    api_key: siem-key
    index: guardianwaf
    batch_size: 100
    flush_interval: 10s
    timeout: 3s
    skip_verify: true
    fields:
      env: prod
      team: security
  virtual_patch:
    enabled: true
    auto_update: true
    update_interval: 12h
    cve_path: /var/lib/guardianwaf/cves.json
    nvd_feed_url: https://nvd.nist.gov/feed
    auto_generate_rules: true
    block_severity: [CRITICAL, HIGH]
    notify_on_patch: true`

	node, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	cfg := &Config{}
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode() error = %v", err)
	}

	assertEqualConfigSection(t, "zero_trust", cfg.WAF.ZeroTrust, ZeroTrustConfig{
		Enabled:              true,
		RequireMTLS:          true,
		RequireAttestation:   true,
		SessionTTL:           15 * time.Minute,
		AttestationTTL:       5 * time.Minute,
		TrustedCAPath:        "/etc/guardianwaf/ca.pem",
		DeviceTrustThreshold: "high",
		AllowBypassPaths:     []string{"/livez", "/readyz"},
	})
	assertEqualConfigSection(t, "cache", cfg.WAF.Cache, CacheConfig{
		Enabled:              true,
		Backend:              "redis",
		TTL:                  2 * time.Minute,
		MaxSize:              256,
		RedisAddr:            "redis:6379",
		RedisPass:            "redis-secret",
		RedisDB:              3,
		Prefix:               "gwaf",
		CacheMethods:         []string{"GET", "HEAD"},
		CacheStatusCodes:     []int{200, 204, 301},
		SkipPaths:            []string{"/admin", "/api/private"},
		MaxCacheSize:         512,
		StaleWhileRevalidate: true,
	})
	assertEqualConfigSection(t, "replay", cfg.WAF.Replay, ReplayConfig{
		Enabled:         true,
		StoragePath:     "/var/lib/guardianwaf/replay",
		Format:          "json",
		MaxFileSize:     64,
		MaxFiles:        8,
		RetentionDays:   21,
		CaptureRequest:  true,
		CaptureResponse: true,
		CaptureHeaders:  []string{"X-Request-ID", "Authorization"},
		SkipPaths:       []string{"/healthz", "/metrics"},
		SkipMethods:     []string{"OPTIONS"},
		Compress:        true,
		Replay: ReplayEngineConfig{
			Enabled:         true,
			TargetBaseURL:   "https://replay.example.com",
			RateLimit:       25,
			Concurrency:     4,
			Timeout:         3 * time.Second,
			FollowRedirects: true,
			ModifyHost:      true,
			PreserveIDs:     true,
			DryRun:          true,
			Headers:         map[string]string{"X-Replay": "1", "X-Env": "staging"},
		},
	})
	assertEqualConfigSection(t, "canary", cfg.WAF.Canary, CanaryConfig{
		Enabled:          true,
		CanaryVersion:    "v2",
		StableUpstream:   "stable",
		CanaryUpstream:   "canary",
		Strategy:         "percentage",
		Percentage:       15,
		HeaderName:       "X-Canary",
		HeaderValue:      "1",
		CookieName:       "gwaf_canary",
		CookieValue:      "v2",
		Regions:          []string{"us-east-1", "eu-west-1"},
		AutoRollback:     true,
		ErrorThreshold:   0.05,
		LatencyThreshold: 250 * time.Millisecond,
		HealthCheckPath:  "/readyz",
		Metadata:         map[string]string{"owner": "platform", "ticket": "REL-42"},
	})
	assertEqualConfigSection(t, "analytics", cfg.WAF.Analytics, AnalyticsConfig{
		Enabled:          true,
		StoragePath:      "/var/lib/guardianwaf/analytics",
		RetentionDays:    30,
		FlushInterval:    15 * time.Second,
		MaxDataPoints:    10000,
		EnableTimeSeries: true,
	})
	assertEqualConfigSection(t, "cluster_sync", cfg.WAF.ClusterSync, ClusterSyncConfig{
		Enabled:            true,
		NodeID:             "node-a",
		NodeName:           "Node A",
		Listen:             ":9444",
		Port:               9444,
		SharedSecret:       "cluster-secret",
		SyncInterval:       10 * time.Second,
		ConflictResolution: "last_write_wins",
		MaxRetries:         3,
		RetryDelay:         2 * time.Second,
		Clusters: []ClusterMembership{{
			ID:            "cluster-a",
			Name:          "Cluster A",
			SyncScope:     "all",
			Bidirectional: true,
			Nodes: []ClusterNodeConfig{
				{ID: "node-b", Name: "Node B", Address: "https://node-b.example.com"},
				{ID: "node-c", Name: "Node C", Address: "https://node-c.example.com"},
			},
		}},
	})
	assertEqualConfigSection(t, "remediation", cfg.WAF.Remediation, RemediationConfig{
		Enabled:             true,
		AutoApply:           true,
		ConfidenceThreshold: 90,
		MaxRulesPerDay:      20,
		RuleTTL:             24 * time.Hour,
		ExcludedPaths:       []string{"/admin", "/internal"},
		StoragePath:         "/var/lib/guardianwaf/remediation.json",
	})
	assertEqualConfigSection(t, "websocket", cfg.WAF.WebSocket, WebSocketConfig{
		Enabled:             true,
		MaxMessageSize:      1048576,
		MaxFrameSize:        65536,
		RateLimitPerSecond:  10,
		RateLimitBurst:      20,
		AllowedOrigins:      []string{"https://app.example.com", "https://admin.example.com"},
		BlockedExtensions:   []string{"permessage-deflate"},
		BlockEmptyMessages:  true,
		BlockBinaryMessages: true,
		MaxConcurrentPerIP:  5,
		HandshakeTimeout:    3 * time.Second,
		IdleTimeout:         time.Minute,
		ScanPayloads:        true,
	})
	assertEqualConfigSection(t, "siem", cfg.WAF.SIEM, SIEMConfig{
		Enabled:       true,
		Endpoint:      "https://siem.example.com/events",
		Format:        "json",
		APIKey:        "siem-key",
		Index:         "guardianwaf",
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       3 * time.Second,
		SkipVerify:    true,
		Fields:        map[string]string{"env": "prod", "team": "security"},
	})
	assertEqualConfigSection(t, "virtual_patch", cfg.WAF.VirtualPatch, VirtualPatchConfig{
		Enabled:           true,
		AutoUpdate:        true,
		UpdateInterval:    12 * time.Hour,
		CVEPath:           "/var/lib/guardianwaf/cves.json",
		NVDFeedURL:        "https://nvd.nist.gov/feed",
		AutoGenerateRules: true,
		BlockSeverity:     []string{"CRITICAL", "HIGH"},
		NotifyOnPatch:     true,
	})
}

func assertEqualConfigSection[T any](t *testing.T, name string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mismatch\ngot:  %#v\nwant: %#v", name, got, want)
	}
}
