package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultConfig returns a Config populated with production-safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:   "enforce",
		Listen: ":8088",
		TLS: TLSConfig{
			Listen:       ":8443",
			HTTPRedirect: true,
			ACME: ACMEConfig{
				CacheDir: "/var/lib/guardianwaf/acme",
			},
		},
		WAF: WAFConfig{
			IPACL: IPACLConfig{
				Enabled: true,
				AutoBan: AutoBanConfig{
					Enabled:    true,
					DefaultTTL: 1 * time.Hour,
					MaxTTL:     24 * time.Hour,
				},
			},
			RateLimit: RateLimitConfig{
				Enabled: true,
				Rules: []RateLimitRule{
					{
						ID:     "global",
						Scope:  "ip",
						Limit:  1000,
						Window: 1 * time.Minute,
						Burst:  50,
						Action: "block",
					},
				},
			},
			Sanitizer: SanitizerConfig{
				Enabled:           true,
				MaxURLLength:      8192,
				MaxHeaderSize:     8192,
				MaxHeaderCount:    100,
				MaxBodySize:       10 * 1024 * 1024, // 10MB
				MaxCookieSize:     4096,
				BlockNullBytes:    true,
				NormalizeEncoding: true,
				StripHopByHop:     true,
				AllowedMethods:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
			},
			Detection: DetectionConfig{
				Enabled: true,
				Threshold: ThresholdConfig{
					Block: 50,
					Log:   25,
				},
				Detectors: map[string]DetectorConfig{
					"sqli": {Enabled: true, Multiplier: 1.0},
					"xss":  {Enabled: true, Multiplier: 1.0},
					"lfi":  {Enabled: true, Multiplier: 1.0},
					"cmdi": {Enabled: true, Multiplier: 1.0},
					"xxe":  {Enabled: true, Multiplier: 1.0},
					"ssrf": {Enabled: true, Multiplier: 1.0},
				},
			},
			BotDetection: BotDetectionConfig{
				Enabled: true,
				Mode:    "monitor",
				TLSFingerprint: TLSFingerprintConfig{
					Enabled:         true,
					KnownBotsAction: "block",
					UnknownAction:   "log",
					MismatchAction:  "log",
				},
				UserAgent: UAConfig{
					Enabled:            true,
					BlockEmpty:         true,
					BlockKnownScanners: true,
				},
				Behavior: BehaviorConfig{
					Enabled:            true,
					Window:             5 * time.Minute,
					RPSThreshold:       10,
					ErrorRateThreshold: 30,
				},
				Enhanced: EnhancedBotDetectionConfig{
					Enabled: false,
					Mode:    "enforce",
					Biometric: BiometricDetectionConfig{
						Enabled:        false,
						MinEvents:      20,
						ScoreThreshold: 50,
						TimeWindow:     5 * time.Minute,
					},
					BrowserFingerprint: BrowserFingerprintConfig{
						Enabled:       true,
						CheckCanvas:   true,
						CheckWebGL:    true,
						CheckFonts:    true,
						CheckHeadless: true,
					},
					Captcha: CaptchaChallengeConfig{
						Enabled:  false,
						Provider: "hcaptcha",
						Timeout:  30 * time.Second,
					},
				},
			},
			Challenge: ChallengeConfig{
				Enabled:    false,
				Difficulty: 20,
				CookieTTL:  1 * time.Hour,
				CookieName: "__gwaf_challenge",
			},
			Response: ResponseConfig{
				SecurityHeaders: SecurityHeadersConfig{
					Enabled: true,
					HSTS: HSTSConfig{
						Enabled:           true,
						MaxAge:            31536000,
						IncludeSubDomains: true,
					},
					XContentTypeOptions: true,
					XFrameOptions:       "SAMEORIGIN",
					ReferrerPolicy:      "strict-origin-when-cross-origin",
					PermissionsPolicy:   "camera=(), microphone=(), geolocation=()",
				},
				DataMasking: DataMaskingConfig{
					Enabled:          true,
					MaskCreditCards:  true,
					MaskSSN:          true,
					MaskAPIKeys:      true,
					StripStackTraces: true,
				},
				ErrorPages: ErrorPagesConfig{
					Enabled: true,
					Mode:    "production",
				},
			},
			AIAnalysis: AIAnalysisConfig{
				Enabled:          false,
				StorePath:        "data/ai",
				BatchSize:        20,
				BatchInterval:    60 * time.Second,
				MinScore:         25,
				MaxTokensPerHour: 50000,
				MaxTokensPerDay:  500000,
				MaxRequestsHour:  30,
				AutoBlock:        false,
				AutoBlockTTL:     time.Hour,
			},
			MLAnomaly: MLAnomalyConfig{
				Enabled:        false,
				Mode:           "monitor",
				Threshold:      0.7,
				WindowSize:     100,
				MinSamples:     50,
				FeatureBuckets: 20,
				AutoBlock:      false,
				BlockThreshold: 0.9,
			},
			APIDiscovery: APIDiscoveryConfig{
				Enabled:          false,
				CaptureMode:      "passive",
				RingBufferSize:   10000,
				MinSamples:       100,
				ClusterThreshold: 0.85,
				ExportPath:       "data/api-discovery",
				ExportFormat:     "openapi",
				AutoExport:       false,
				ExportInterval:   24 * time.Hour,
			},
			GraphQL: GraphQLConfig{
				Enabled:            false,
				MaxDepth:           10,
				MaxComplexity:      1000,
				BlockIntrospection: false,
				AllowEndpoints:     []string{"/graphql", "/api/graphql"},
			},
			GRPC: GRPCConfig{
				Enabled:        false,
				GRPCWebEnabled: true,
				ValidateProto:  true,
				MaxMessageSize: 4 * 1024 * 1024, // 4MB
			},
			Tenant: TenantConfig{
				Enabled:    false,
				MaxTenants: 100,
				HeaderName: "X-GuardianWAF-Tenant",
				DefaultQuota: ResourceQuotaConfig{
					MaxRequestsPerMinute: 10000,
					MaxRequestsPerHour:   500000,
					MaxBandwidthMbps:     100,
					MaxRules:             100,
					MaxRateLimitRules:    10,
					MaxIPACLs:            1000,
				},
			},
			DLP: DLPConfig{
				Enabled:      false,
				ScanRequest:  true,
				ScanResponse: true,
				BlockOnMatch: false,
				MaskResponse: true,
				MaxBodySize:  1024 * 1024, // 1MB
				Patterns:     []string{"credit_card", "ssn", "api_key", "private_key", "tax_id"},
			},
			ZeroTrust: ZeroTrustConfig{
				Enabled:              false,
				RequireMTLS:          true,
				RequireAttestation:   false,
				SessionTTL:           1 * time.Hour,
				AttestationTTL:       24 * time.Hour,
				DeviceTrustThreshold: "medium",
				AllowBypassPaths:     []string{"/healthz", "/metrics"},
			},
		},
		Dashboard: DashboardConfig{
			Enabled: true,
			Listen:  ":9443",
			TLS:     true,
		},
		Docker: DockerConfig{
			Enabled:      false,
			SocketPath:   "/var/run/docker.sock",
			LabelPrefix:  "gwaf",
			PollInterval: 5 * time.Second,
			Network:      "bridge",
		},
		MCP: MCPConfig{
			Enabled:   true,
			Transport: "stdio",
		},
		Logging: LogConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			LogAllowed: false,
			LogBlocked: true,
			LogBody:    false,
		},
		Events: EventsConfig{
			Storage:   "memory",
			MaxEvents: 100000,
			FilePath:  "/var/log/guardianwaf/events.jsonl",
		},
	}
}

// parseDuration parses a duration string like "1s", "5m", "1h", "24h", "100ms".
// It delegates to time.ParseDuration which handles these formats natively.
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// PopulateFromNode reads a parsed YAML Node tree and populates the Config struct.
// It walks the Node tree and maps values to Config fields manually.
// Fields not present in the Node tree retain their current values (typically defaults).
func PopulateFromNode(cfg *Config, node *Node) error {
	if node == nil || node.Kind != MapNode {
		return nil
	}

	// Top-level scalars
	if v := node.Get("mode"); v != nil && !v.IsNull {
		cfg.Mode = v.String()
	}
	if v := node.Get("listen"); v != nil && !v.IsNull {
		cfg.Listen = v.String()
	}

	// TLS
	if n := node.Get("tls"); n != nil {
		if err := populateTLS(&cfg.TLS, n); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}

	// Upstreams
	if n := node.Get("upstreams"); n != nil && n.Kind == SequenceNode {
		upstreams, err := populateUpstreams(n)
		if err != nil {
			return fmt.Errorf("upstreams: %w", err)
		}
		cfg.Upstreams = upstreams
	}

	// Routes
	if n := node.Get("routes"); n != nil && n.Kind == SequenceNode {
		routes, err := populateRoutes(n)
		if err != nil {
			return fmt.Errorf("routes: %w", err)
		}
		cfg.Routes = routes
	}

	// Virtual Hosts
	if n := node.Get("virtual_hosts"); n != nil && n.Kind == SequenceNode {
		vhosts, err := populateVirtualHosts(n)
		if err != nil {
			return fmt.Errorf("virtual_hosts: %w", err)
		}
		cfg.VirtualHosts = vhosts
	}

	// WAF
	if n := node.Get("waf"); n != nil {
		if err := populateWAF(&cfg.WAF, n); err != nil {
			return fmt.Errorf("waf: %w", err)
		}
	}

	// Dashboard
	if n := node.Get("dashboard"); n != nil {
		if err := populateDashboard(&cfg.Dashboard, n); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}

	// MCP
	if n := node.Get("mcp"); n != nil {
		if err := populateMCP(&cfg.MCP, n); err != nil {
			return fmt.Errorf("mcp: %w", err)
		}
	}

	// Docker
	if n := node.Get("docker"); n != nil {
		if err := populateDocker(&cfg.Docker, n); err != nil {
			return fmt.Errorf("docker: %w", err)
		}
	}

	// Logging
	if n := node.Get("logging"); n != nil {
		if err := populateLogging(&cfg.Logging, n); err != nil {
			return fmt.Errorf("logging: %w", err)
		}
	}

	// Events
	if n := node.Get("events"); n != nil {
		if err := populateEvents(&cfg.Events, n); err != nil {
			return fmt.Errorf("events: %w", err)
		}
	}

	// Alerting
	if n := node.Get("alerting"); n != nil {
		if err := populateAlerting(&cfg.Alerting, n); err != nil {
			return fmt.Errorf("alerting: %w", err)
		}
	}

	return nil
}

// --- TLS ---

func populateTLS(tls *TLSConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		tls.Enabled = b
	}
	if v := n.Get("listen"); v != nil && !v.IsNull {
		tls.Listen = v.String()
	}
	if v := n.Get("cert_file"); v != nil && !v.IsNull {
		tls.CertFile = v.String()
	}
	if v := n.Get("key_file"); v != nil && !v.IsNull {
		tls.KeyFile = v.String()
	}
	if v := n.Get("http_redirect"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("http_redirect: %w", err)
		}
		tls.HTTPRedirect = b
	}
	if a := n.Get("acme"); a != nil {
		if err := populateACME(&tls.ACME, a); err != nil {
			return fmt.Errorf("acme: %w", err)
		}
	}
	return nil
}

func populateACME(acme *ACMEConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		acme.Enabled = b
	}
	if v := n.Get("email"); v != nil && !v.IsNull {
		acme.Email = v.String()
	}
	if v := n.Get("domains"); v != nil {
		acme.Domains = nodeStringSlice(v)
	}
	if v := n.Get("cache_dir"); v != nil && !v.IsNull {
		acme.CacheDir = v.String()
	}
	return nil
}

// --- Upstreams ---

func populateUpstreams(n *Node) ([]UpstreamConfig, error) {
	items := n.Slice()
	result := make([]UpstreamConfig, 0, len(items))
	for _, item := range items {
		if item.Kind != MapNode {
			continue
		}
		u := UpstreamConfig{}
		if v := item.Get("name"); v != nil && !v.IsNull {
			u.Name = v.String()
		}
		if v := item.Get("load_balancer"); v != nil && !v.IsNull {
			u.LoadBalancer = v.String()
		}
		if t := item.Get("targets"); t != nil && t.Kind == SequenceNode {
			for _, ti := range t.Slice() {
				if ti.Kind != MapNode {
					continue
				}
				tc := TargetConfig{Weight: 1}
				if v := ti.Get("url"); v != nil && !v.IsNull {
					tc.URL = v.String()
				}
				if v := ti.Get("weight"); v != nil {
					w, err := nodeInt(v)
					if err != nil {
						return nil, fmt.Errorf("target weight: %w", err)
					}
					tc.Weight = w
				}
				u.Targets = append(u.Targets, tc)
			}
		}
		if hc := item.Get("health_check"); hc != nil && hc.Kind == MapNode {
			if err := populateHealthCheck(&u.HealthCheck, hc); err != nil {
				return nil, fmt.Errorf("health_check: %w", err)
			}
		}
		result = append(result, u)
	}
	return result, nil
}

func populateHealthCheck(hc *HealthCheckConfig, n *Node) error {
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		hc.Enabled = b
	}
	if v := n.Get("interval"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("interval: %w", err)
		}
		hc.Interval = d
	}
	if v := n.Get("timeout"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
		hc.Timeout = d
	}
	if v := n.Get("path"); v != nil && !v.IsNull {
		hc.Path = v.String()
	}
	return nil
}

// --- Routes ---

func populateRoutes(n *Node) ([]RouteConfig, error) {
	items := n.Slice()
	result := make([]RouteConfig, 0, len(items))
	for _, item := range items {
		if item.Kind != MapNode {
			continue
		}
		r := RouteConfig{}
		if v := item.Get("path"); v != nil && !v.IsNull {
			r.Path = v.String()
		}
		if v := item.Get("upstream"); v != nil && !v.IsNull {
			r.Upstream = v.String()
		}
		if v := item.Get("strip_prefix"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return nil, fmt.Errorf("strip_prefix: %w", err)
			}
			r.StripPrefix = b
		}
		if v := item.Get("methods"); v != nil {
			r.Methods = nodeStringSlice(v)
		}
		result = append(result, r)
	}
	return result, nil
}

// --- Virtual Hosts ---

func populateVirtualHosts(n *Node) ([]VirtualHostConfig, error) {
	items := n.Slice()
	result := make([]VirtualHostConfig, 0, len(items))
	for _, item := range items {
		if item.Kind != MapNode {
			continue
		}
		vh := VirtualHostConfig{}
		if v := item.Get("domains"); v != nil {
			vh.Domains = nodeStringSlice(v)
		}
		if t := item.Get("tls"); t != nil && t.Kind == MapNode {
			if v := t.Get("cert_file"); v != nil && !v.IsNull {
				vh.TLS.CertFile = v.String()
			}
			if v := t.Get("key_file"); v != nil && !v.IsNull {
				vh.TLS.KeyFile = v.String()
			}
		}
		if r := item.Get("routes"); r != nil && r.Kind == SequenceNode {
			routes, err := populateRoutes(r)
			if err != nil {
				return nil, fmt.Errorf("routes: %w", err)
			}
			vh.Routes = routes
		}
		result = append(result, vh)
	}
	return result, nil
}

// --- WAF ---

func populateWAF(waf *WAFConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if sub := n.Get("ip_acl"); sub != nil {
		if err := populateIPACL(&waf.IPACL, sub); err != nil {
			return fmt.Errorf("ip_acl: %w", err)
		}
	}
	if sub := n.Get("rate_limit"); sub != nil {
		if err := populateRateLimit(&waf.RateLimit, sub); err != nil {
			return fmt.Errorf("rate_limit: %w", err)
		}
	}
	if sub := n.Get("sanitizer"); sub != nil {
		if err := populateSanitizer(&waf.Sanitizer, sub); err != nil {
			return fmt.Errorf("sanitizer: %w", err)
		}
	}
	if sub := n.Get("detection"); sub != nil {
		if err := populateDetection(&waf.Detection, sub); err != nil {
			return fmt.Errorf("detection: %w", err)
		}
	}
	if sub := n.Get("bot_detection"); sub != nil {
		if err := populateBotDetection(&waf.BotDetection, sub); err != nil {
			return fmt.Errorf("bot_detection: %w", err)
		}
	}
	if sub := n.Get("challenge"); sub != nil {
		if err := populateChallenge(&waf.Challenge, sub); err != nil {
			return fmt.Errorf("challenge: %w", err)
		}
	}
	if sub := n.Get("response"); sub != nil {
		if err := populateResponse(&waf.Response, sub); err != nil {
			return fmt.Errorf("response: %w", err)
		}
	}
	if sub := n.Get("ai_analysis"); sub != nil {
		if err := populateAIAnalysis(&waf.AIAnalysis, sub); err != nil {
			return fmt.Errorf("ai_analysis: %w", err)
		}
	}
	if sub := n.Get("ml_anomaly"); sub != nil {
		if err := populateMLAnomaly(&waf.MLAnomaly, sub); err != nil {
			return fmt.Errorf("ml_anomaly: %w", err)
		}
	}
	if sub := n.Get("api_discovery"); sub != nil {
		if err := populateAPIDiscovery(&waf.APIDiscovery, sub); err != nil {
			return fmt.Errorf("api_discovery: %w", err)
		}
	}
	if sub := n.Get("graphql"); sub != nil {
		if err := populateGraphQL(&waf.GraphQL, sub); err != nil {
			return fmt.Errorf("graphql: %w", err)
		}
	}
	return nil
}

func populateAIAnalysis(ai *AIAnalysisConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		ai.Enabled = b
	}
	if v := n.Get("store_path"); v != nil && !v.IsNull {
		ai.StorePath = v.String()
	}
	if v := n.Get("catalog_url"); v != nil && !v.IsNull {
		ai.CatalogURL = v.String()
	}
	if v := n.Get("batch_size"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("batch_size: %w", err)
		}
		ai.BatchSize = i
	}
	if v := n.Get("batch_interval"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("batch_interval: %w", err)
		}
		ai.BatchInterval = d
	}
	if v := n.Get("min_score"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("min_score: %w", err)
		}
		ai.MinScore = i
	}
	if v := n.Get("max_tokens_per_hour"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_tokens_per_hour: %w", err)
		}
		ai.MaxTokensPerHour = int64(i)
	}
	if v := n.Get("max_tokens_per_day"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_tokens_per_day: %w", err)
		}
		ai.MaxTokensPerDay = int64(i)
	}
	if v := n.Get("max_requests_per_hour"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_requests_per_hour: %w", err)
		}
		ai.MaxRequestsHour = i
	}
	if v := n.Get("auto_block"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("auto_block: %w", err)
		}
		ai.AutoBlock = b
	}
	if v := n.Get("auto_block_ttl"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("auto_block_ttl: %w", err)
		}
		ai.AutoBlockTTL = d
	}
	return nil
}

func populateMLAnomaly(ml *MLAnomalyConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		ml.Enabled = b
	}
	if v := n.Get("mode"); v != nil && !v.IsNull {
		ml.Mode = v.String()
	}
	if v := n.Get("threshold"); v != nil {
		f, err := nodeFloat64(v)
		if err != nil {
			return fmt.Errorf("threshold: %w", err)
		}
		ml.Threshold = f
	}
	if v := n.Get("window_size"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("window_size: %w", err)
		}
		ml.WindowSize = i
	}
	if v := n.Get("min_samples"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("min_samples: %w", err)
		}
		ml.MinSamples = i
	}
	if v := n.Get("feature_buckets"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("feature_buckets: %w", err)
		}
		ml.FeatureBuckets = i
	}
	if v := n.Get("auto_block"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("auto_block: %w", err)
		}
		ml.AutoBlock = b
	}
	if v := n.Get("block_threshold"); v != nil {
		f, err := nodeFloat64(v)
		if err != nil {
			return fmt.Errorf("block_threshold: %w", err)
		}
		ml.BlockThreshold = f
	}
	return nil
}

func populateAPIDiscovery(ad *APIDiscoveryConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		ad.Enabled = b
	}
	if v := n.Get("capture_mode"); v != nil && !v.IsNull {
		ad.CaptureMode = v.String()
	}
	if v := n.Get("ring_buffer_size"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("ring_buffer_size: %w", err)
		}
		ad.RingBufferSize = i
	}
	if v := n.Get("min_samples"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("min_samples: %w", err)
		}
		ad.MinSamples = i
	}
	if v := n.Get("cluster_threshold"); v != nil {
		f, err := nodeFloat64(v)
		if err != nil {
			return fmt.Errorf("cluster_threshold: %w", err)
		}
		ad.ClusterThreshold = f
	}
	if v := n.Get("export_path"); v != nil && !v.IsNull {
		ad.ExportPath = v.String()
	}
	if v := n.Get("export_format"); v != nil && !v.IsNull {
		ad.ExportFormat = v.String()
	}
	if v := n.Get("auto_export"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("auto_export: %w", err)
		}
		ad.AutoExport = b
	}
	if v := n.Get("export_interval"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("export_interval: %w", err)
		}
		ad.ExportInterval = d
	}
	return nil
}

func populateGraphQL(gql *GraphQLConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		gql.Enabled = b
	}
	if v := n.Get("max_depth"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_depth: %w", err)
		}
		gql.MaxDepth = i
	}
	if v := n.Get("max_complexity"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_complexity: %w", err)
		}
		gql.MaxComplexity = i
	}
	if v := n.Get("block_introspection"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("block_introspection: %w", err)
		}
		gql.BlockIntrospection = b
	}
	if v := n.Get("allow_endpoints"); v != nil {
		gql.AllowEndpoints = nodeStringSlice(v)
	}
	return nil
}

func populateChallenge(ch *ChallengeConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		ch.Enabled = b
	}
	if v := n.Get("difficulty"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("difficulty: %w", err)
		}
		ch.Difficulty = i
	}
	if v := n.Get("cookie_ttl"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("cookie_ttl: %w", err)
		}
		ch.CookieTTL = d
	}
	if v := n.Get("cookie_name"); v != nil && !v.IsNull {
		ch.CookieName = v.String()
	}
	if v := n.Get("secret_key"); v != nil && !v.IsNull {
		ch.SecretKey = v.String()
	}
	return nil
}

func populateIPACL(acl *IPACLConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		acl.Enabled = b
	}
	if v := n.Get("whitelist"); v != nil {
		acl.Whitelist = nodeStringSlice(v)
	}
	if v := n.Get("blacklist"); v != nil {
		acl.Blacklist = nodeStringSlice(v)
	}
	if sub := n.Get("auto_ban"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("auto_ban.enabled: %w", err)
			}
			acl.AutoBan.Enabled = b
		}
		if v := sub.Get("default_ttl"); v != nil && !v.IsNull {
			d, err := parseDuration(v.String())
			if err != nil {
				return fmt.Errorf("auto_ban.default_ttl: %w", err)
			}
			acl.AutoBan.DefaultTTL = d
		}
		if v := sub.Get("max_ttl"); v != nil && !v.IsNull {
			d, err := parseDuration(v.String())
			if err != nil {
				return fmt.Errorf("auto_ban.max_ttl: %w", err)
			}
			acl.AutoBan.MaxTTL = d
		}
	}
	return nil
}

func populateRateLimit(rl *RateLimitConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		rl.Enabled = b
	}
	if rules := n.Get("rules"); rules != nil && rules.Kind == SequenceNode {
		var parsed []RateLimitRule
		for _, item := range rules.Slice() {
			if item.Kind != MapNode {
				continue
			}
			r := RateLimitRule{}
			if v := item.Get("id"); v != nil && !v.IsNull {
				r.ID = v.String()
			}
			if v := item.Get("scope"); v != nil && !v.IsNull {
				r.Scope = v.String()
			}
			if v := item.Get("paths"); v != nil {
				r.Paths = nodeStringSlice(v)
			}
			if v := item.Get("limit"); v != nil {
				i, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("rule limit: %w", err)
				}
				r.Limit = i
			}
			if v := item.Get("window"); v != nil && !v.IsNull {
				d, err := parseDuration(v.String())
				if err != nil {
					return fmt.Errorf("rule window: %w", err)
				}
				r.Window = d
			}
			if v := item.Get("burst"); v != nil {
				i, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("rule burst: %w", err)
				}
				r.Burst = i
			}
			if v := item.Get("action"); v != nil && !v.IsNull {
				r.Action = v.String()
			}
			if v := item.Get("auto_ban_after"); v != nil {
				i, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("rule auto_ban_after: %w", err)
				}
				r.AutoBanAfter = i
			}
			parsed = append(parsed, r)
		}
		rl.Rules = parsed
	}
	return nil
}

func populateSanitizer(san *SanitizerConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		san.Enabled = b
	}
	if v := n.Get("max_url_length"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_url_length: %w", err)
		}
		san.MaxURLLength = i
	}
	if v := n.Get("max_header_size"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_header_size: %w", err)
		}
		san.MaxHeaderSize = i
	}
	if v := n.Get("max_header_count"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_header_count: %w", err)
		}
		san.MaxHeaderCount = i
	}
	if v := n.Get("max_body_size"); v != nil {
		i, err := nodeInt64(v)
		if err != nil {
			return fmt.Errorf("max_body_size: %w", err)
		}
		san.MaxBodySize = i
	}
	if v := n.Get("max_cookie_size"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_cookie_size: %w", err)
		}
		san.MaxCookieSize = i
	}
	if v := n.Get("block_null_bytes"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("block_null_bytes: %w", err)
		}
		san.BlockNullBytes = b
	}
	if v := n.Get("normalize_encoding"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("normalize_encoding: %w", err)
		}
		san.NormalizeEncoding = b
	}
	if v := n.Get("strip_hop_by_hop"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("strip_hop_by_hop: %w", err)
		}
		san.StripHopByHop = b
	}
	if v := n.Get("allowed_methods"); v != nil {
		san.AllowedMethods = nodeStringSlice(v)
	}
	if overrides := n.Get("path_overrides"); overrides != nil && overrides.Kind == SequenceNode {
		var parsed []PathOverride
		for _, item := range overrides.Slice() {
			if item.Kind != MapNode {
				continue
			}
			po := PathOverride{}
			if v := item.Get("path"); v != nil && !v.IsNull {
				po.Path = v.String()
			}
			if v := item.Get("max_body_size"); v != nil {
				i, err := nodeInt64(v)
				if err != nil {
					return fmt.Errorf("path_override max_body_size: %w", err)
				}
				po.MaxBodySize = i
			}
			parsed = append(parsed, po)
		}
		san.PathOverrides = parsed
	}
	return nil
}

func populateDetection(det *DetectionConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		det.Enabled = b
	}
	if th := n.Get("threshold"); th != nil && th.Kind == MapNode {
		if v := th.Get("block"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("threshold.block: %w", err)
			}
			det.Threshold.Block = i
		}
		if v := th.Get("log"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("threshold.log: %w", err)
			}
			det.Threshold.Log = i
		}
	}
	if detectors := n.Get("detectors"); detectors != nil && detectors.Kind == MapNode {
		if det.Detectors == nil {
			det.Detectors = make(map[string]DetectorConfig)
		}
		for _, key := range detectors.MapKeys {
			sub := detectors.MapItems[key]
			if sub == nil || sub.Kind != MapNode {
				continue
			}
			dc := DetectorConfig{Multiplier: 1.0} // default multiplier
			if v := sub.Get("enabled"); v != nil {
				b, err := nodeBool(v)
				if err != nil {
					return fmt.Errorf("detectors.%s.enabled: %w", key, err)
				}
				dc.Enabled = b
			}
			if v := sub.Get("multiplier"); v != nil {
				f, err := nodeFloat64(v)
				if err != nil {
					return fmt.Errorf("detectors.%s.multiplier: %w", key, err)
				}
				dc.Multiplier = f
			}
			det.Detectors[key] = dc
		}
	}
	if exclusions := n.Get("exclusions"); exclusions != nil && exclusions.Kind == SequenceNode {
		var parsed []ExclusionConfig
		for _, item := range exclusions.Slice() {
			if item.Kind != MapNode {
				continue
			}
			ec := ExclusionConfig{}
			if v := item.Get("path"); v != nil && !v.IsNull {
				ec.Path = v.String()
			}
			if v := item.Get("detectors"); v != nil {
				ec.Detectors = nodeStringSlice(v)
			}
			if v := item.Get("reason"); v != nil && !v.IsNull {
				ec.Reason = v.String()
			}
			parsed = append(parsed, ec)
		}
		det.Exclusions = parsed
	}
	return nil
}

func populateBotDetection(bd *BotDetectionConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		bd.Enabled = b
	}
	if v := n.Get("mode"); v != nil && !v.IsNull {
		bd.Mode = v.String()
	}
	if sub := n.Get("tls_fingerprint"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("tls_fingerprint.enabled: %w", err)
			}
			bd.TLSFingerprint.Enabled = b
		}
		if v := sub.Get("known_bots_action"); v != nil && !v.IsNull {
			bd.TLSFingerprint.KnownBotsAction = v.String()
		}
		if v := sub.Get("unknown_action"); v != nil && !v.IsNull {
			bd.TLSFingerprint.UnknownAction = v.String()
		}
		if v := sub.Get("mismatch_action"); v != nil && !v.IsNull {
			bd.TLSFingerprint.MismatchAction = v.String()
		}
	}
	if sub := n.Get("user_agent"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("user_agent.enabled: %w", err)
			}
			bd.UserAgent.Enabled = b
		}
		if v := sub.Get("block_empty"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("user_agent.block_empty: %w", err)
			}
			bd.UserAgent.BlockEmpty = b
		}
		if v := sub.Get("block_known_scanners"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("user_agent.block_known_scanners: %w", err)
			}
			bd.UserAgent.BlockKnownScanners = b
		}
	}
	if sub := n.Get("behavior"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("behavior.enabled: %w", err)
			}
			bd.Behavior.Enabled = b
		}
		if v := sub.Get("window"); v != nil && !v.IsNull {
			d, err := parseDuration(v.String())
			if err != nil {
				return fmt.Errorf("behavior.window: %w", err)
			}
			bd.Behavior.Window = d
		}
		if v := sub.Get("rps_threshold"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("behavior.rps_threshold: %w", err)
			}
			bd.Behavior.RPSThreshold = i
		}
		if v := sub.Get("error_rate_threshold"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("behavior.error_rate_threshold: %w", err)
			}
			bd.Behavior.ErrorRateThreshold = i
		}
	}
	if sub := n.Get("enhanced"); sub != nil && sub.Kind == MapNode {
		if err := populateEnhancedBotDetection(&bd.Enhanced, sub); err != nil {
			return fmt.Errorf("enhanced: %w", err)
		}
	}
	return nil
}

func populateEnhancedBotDetection(ebd *EnhancedBotDetectionConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		ebd.Enabled = b
	}
	if v := n.Get("mode"); v != nil && !v.IsNull {
		ebd.Mode = v.String()
	}
	if sub := n.Get("biometric"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("biometric.enabled: %w", err)
			}
			ebd.Biometric.Enabled = b
		}
		if v := sub.Get("min_events"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("biometric.min_events: %w", err)
			}
			ebd.Biometric.MinEvents = i
		}
		if v := sub.Get("score_threshold"); v != nil {
			f, err := nodeFloat64(v)
			if err != nil {
				return fmt.Errorf("biometric.score_threshold: %w", err)
			}
			ebd.Biometric.ScoreThreshold = f
		}
		if v := sub.Get("time_window"); v != nil && !v.IsNull {
			d, err := parseDuration(v.String())
			if err != nil {
				return fmt.Errorf("biometric.time_window: %w", err)
			}
			ebd.Biometric.TimeWindow = d
		}
	}
	if sub := n.Get("browser_fingerprint"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("browser_fingerprint.enabled: %w", err)
			}
			ebd.BrowserFingerprint.Enabled = b
		}
		if v := sub.Get("check_canvas"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("browser_fingerprint.check_canvas: %w", err)
			}
			ebd.BrowserFingerprint.CheckCanvas = b
		}
		if v := sub.Get("check_webgl"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("browser_fingerprint.check_webgl: %w", err)
			}
			ebd.BrowserFingerprint.CheckWebGL = b
		}
		if v := sub.Get("check_fonts"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("browser_fingerprint.check_fonts: %w", err)
			}
			ebd.BrowserFingerprint.CheckFonts = b
		}
		if v := sub.Get("check_headless"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("browser_fingerprint.check_headless: %w", err)
			}
			ebd.BrowserFingerprint.CheckHeadless = b
		}
	}
	if sub := n.Get("captcha"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("captcha.enabled: %w", err)
			}
			ebd.Captcha.Enabled = b
		}
		if v := sub.Get("provider"); v != nil && !v.IsNull {
			ebd.Captcha.Provider = v.String()
		}
		if v := sub.Get("site_key"); v != nil && !v.IsNull {
			ebd.Captcha.SiteKey = v.String()
		}
		if v := sub.Get("secret_key"); v != nil && !v.IsNull {
			ebd.Captcha.SecretKey = v.String()
		}
		if v := sub.Get("timeout"); v != nil && !v.IsNull {
			d, err := parseDuration(v.String())
			if err != nil {
				return fmt.Errorf("captcha.timeout: %w", err)
			}
			ebd.Captcha.Timeout = d
		}
	}
	return nil
}

func populateResponse(resp *ResponseConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if sub := n.Get("security_headers"); sub != nil {
		if err := populateSecurityHeaders(&resp.SecurityHeaders, sub); err != nil {
			return fmt.Errorf("security_headers: %w", err)
		}
	}
	if sub := n.Get("data_masking"); sub != nil {
		if err := populateDataMasking(&resp.DataMasking, sub); err != nil {
			return fmt.Errorf("data_masking: %w", err)
		}
	}
	if sub := n.Get("error_pages"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("error_pages.enabled: %w", err)
			}
			resp.ErrorPages.Enabled = b
		}
		if v := sub.Get("mode"); v != nil && !v.IsNull {
			resp.ErrorPages.Mode = v.String()
		}
	}
	return nil
}

func populateSecurityHeaders(sh *SecurityHeadersConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		sh.Enabled = b
	}
	if sub := n.Get("hsts"); sub != nil && sub.Kind == MapNode {
		if v := sub.Get("enabled"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("hsts.enabled: %w", err)
			}
			sh.HSTS.Enabled = b
		}
		if v := sub.Get("max_age"); v != nil {
			i, err := nodeInt(v)
			if err != nil {
				return fmt.Errorf("hsts.max_age: %w", err)
			}
			sh.HSTS.MaxAge = i
		}
		if v := sub.Get("include_subdomains"); v != nil {
			b, err := nodeBool(v)
			if err != nil {
				return fmt.Errorf("hsts.include_subdomains: %w", err)
			}
			sh.HSTS.IncludeSubDomains = b
		}
	}
	if v := n.Get("x_content_type_options"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("x_content_type_options: %w", err)
		}
		sh.XContentTypeOptions = b
	}
	if v := n.Get("x_frame_options"); v != nil && !v.IsNull {
		sh.XFrameOptions = v.String()
	}
	if v := n.Get("referrer_policy"); v != nil && !v.IsNull {
		sh.ReferrerPolicy = v.String()
	}
	if v := n.Get("permissions_policy"); v != nil && !v.IsNull {
		sh.PermissionsPolicy = v.String()
	}
	return nil
}

func populateDataMasking(dm *DataMaskingConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		dm.Enabled = b
	}
	if v := n.Get("mask_credit_cards"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("mask_credit_cards: %w", err)
		}
		dm.MaskCreditCards = b
	}
	if v := n.Get("mask_ssn"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("mask_ssn: %w", err)
		}
		dm.MaskSSN = b
	}
	if v := n.Get("mask_api_keys"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("mask_api_keys: %w", err)
		}
		dm.MaskAPIKeys = b
	}
	if v := n.Get("strip_stack_traces"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("strip_stack_traces: %w", err)
		}
		dm.StripStackTraces = b
	}
	return nil
}

// --- Dashboard ---

func populateDashboard(dash *DashboardConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		dash.Enabled = b
	}
	if v := n.Get("listen"); v != nil && !v.IsNull {
		dash.Listen = v.String()
	}
	if v := n.Get("api_key"); v != nil && !v.IsNull {
		dash.APIKey = v.String()
	}
	if v := n.Get("tls"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		dash.TLS = b
	}
	return nil
}

// --- MCP ---

func populateMCP(mcp *MCPConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		mcp.Enabled = b
	}
	if v := n.Get("transport"); v != nil && !v.IsNull {
		mcp.Transport = v.String()
	}
	return nil
}

// --- Docker ---

func populateDocker(dock *DockerConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		dock.Enabled = b
	}
	if v := n.Get("socket_path"); v != nil && !v.IsNull {
		dock.SocketPath = v.String()
	}
	if v := n.Get("label_prefix"); v != nil && !v.IsNull {
		dock.LabelPrefix = v.String()
	}
	if v := n.Get("poll_interval"); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			return fmt.Errorf("poll_interval: %w", err)
		}
		dock.PollInterval = d
	}
	if v := n.Get("network"); v != nil && !v.IsNull {
		dock.Network = v.String()
	}
	return nil
}

// --- Logging ---

func populateLogging(log *LogConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("level"); v != nil && !v.IsNull {
		log.Level = v.String()
	}
	if v := n.Get("format"); v != nil && !v.IsNull {
		log.Format = v.String()
	}
	if v := n.Get("output"); v != nil && !v.IsNull {
		log.Output = v.String()
	}
	if v := n.Get("log_allowed"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("log_allowed: %w", err)
		}
		log.LogAllowed = b
	}
	if v := n.Get("log_blocked"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("log_blocked: %w", err)
		}
		log.LogBlocked = b
	}
	if v := n.Get("log_body"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("log_body: %w", err)
		}
		log.LogBody = b
	}
	return nil
}

// --- Events ---

func populateEvents(ev *EventsConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("storage"); v != nil && !v.IsNull {
		ev.Storage = v.String()
	}
	if v := n.Get("max_events"); v != nil {
		i, err := nodeInt(v)
		if err != nil {
			return fmt.Errorf("max_events: %w", err)
		}
		ev.MaxEvents = i
	}
	if v := n.Get("file_path"); v != nil && !v.IsNull {
		ev.FilePath = v.String()
	}
	return nil
}

// --- Alerting ---

func populateAlerting(alert *AlertingConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if v := n.Get("enabled"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("enabled: %w", err)
		}
		alert.Enabled = b
	}
	if w := n.Get("webhooks"); w != nil && w.Kind == SequenceNode {
		items := w.Slice()
		alert.Webhooks = make([]WebhookConfig, 0, len(items))
		for _, item := range items {
			if item.Kind != MapNode {
				continue
			}
			wc := WebhookConfig{}
			if v := item.Get("name"); v != nil && !v.IsNull {
				wc.Name = v.String()
			}
			if v := item.Get("url"); v != nil && !v.IsNull {
				wc.URL = v.String()
			}
			if v := item.Get("type"); v != nil && !v.IsNull {
				wc.Type = v.String()
			}
			if v := item.Get("events"); v != nil {
				wc.Events = nodeStringSlice(v)
			}
			if v := item.Get("min_score"); v != nil {
				i, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("min_score: %w", err)
				}
				wc.MinScore = i
			}
			if v := item.Get("cooldown"); v != nil && !v.IsNull {
				d, err := parseDuration(v.String())
				if err != nil {
					return fmt.Errorf("cooldown: %w", err)
				}
				wc.Cooldown = d
			}
			if v := item.Get("headers"); v != nil && v.Kind == MapNode {
				wc.Headers = make(map[string]string)
				for k, vn := range v.Map() {
					if vn != nil && !vn.IsNull {
						wc.Headers[k] = vn.String()
					}
				}
			}
			alert.Webhooks = append(alert.Webhooks, wc)
		}
	}
	if e := n.Get("emails"); e != nil && e.Kind == SequenceNode {
		items := e.Slice()
		alert.Emails = make([]EmailConfig, 0, len(items))
		for _, item := range items {
			if item.Kind != MapNode {
				continue
			}
			ec := EmailConfig{}
			if v := item.Get("name"); v != nil && !v.IsNull {
				ec.Name = v.String()
			}
			if v := item.Get("smtp_host"); v != nil && !v.IsNull {
				ec.SMTPHost = v.String()
			}
			if v := item.Get("smtp_port"); v != nil && !v.IsNull {
				p, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("smtp_port: %w", err)
				}
				ec.SMTPPort = p
			}
			if v := item.Get("username"); v != nil && !v.IsNull {
				ec.Username = v.String()
			}
			if v := item.Get("password"); v != nil && !v.IsNull {
				ec.Password = v.String()
			}
			if v := item.Get("from"); v != nil && !v.IsNull {
				ec.From = v.String()
			}
			if v := item.Get("to"); v != nil {
				ec.To = nodeStringSlice(v)
			}
			if v := item.Get("use_tls"); v != nil {
				b, err := nodeBool(v)
				if err != nil {
					return fmt.Errorf("use_tls: %w", err)
				}
				ec.UseTLS = b
			}
			if v := item.Get("events"); v != nil {
				ec.Events = nodeStringSlice(v)
			}
			if v := item.Get("min_score"); v != nil {
				i, err := nodeInt(v)
				if err != nil {
					return fmt.Errorf("min_score: %w", err)
				}
				ec.MinScore = i
			}
			if v := item.Get("cooldown"); v != nil && !v.IsNull {
				d, err := parseDuration(v.String())
				if err != nil {
					return fmt.Errorf("cooldown: %w", err)
				}
				ec.Cooldown = d
			}
			if v := item.Get("subject"); v != nil && !v.IsNull {
				ec.Subject = v.String()
			}
			if v := item.Get("template"); v != nil && !v.IsNull {
				ec.Template = v.String()
			}
			alert.Emails = append(alert.Emails, ec)
		}
	}
	return nil
}

// --- Node conversion helpers ---

// nodeBool extracts a bool from a Node, returning an error if conversion fails.
func nodeBool(n *Node) (bool, error) {
	if n == nil || n.IsNull {
		return false, nil
	}
	return n.Bool()
}

// nodeInt extracts an int from a Node.
func nodeInt(n *Node) (int, error) {
	if n == nil || n.IsNull {
		return 0, nil
	}
	return n.Int()
}

// nodeInt64 extracts an int64 from a Node.
func nodeInt64(n *Node) (int64, error) {
	if n == nil || n.IsNull {
		return 0, nil
	}
	if n.Kind != ScalarNode {
		return 0, fmt.Errorf("cannot convert %s node to int64", n.Kind)
	}
	return strconv.ParseInt(n.Value, 10, 64)
}

// nodeFloat64 extracts a float64 from a Node.
func nodeFloat64(n *Node) (float64, error) {
	if n == nil || n.IsNull {
		return 0, nil
	}
	return n.Float64()
}

// nodeStringSlice extracts a string slice from a sequence Node.
// Each item in the sequence is converted to its string value.
func nodeStringSlice(n *Node) []string {
	if n == nil {
		return nil
	}
	items := n.Slice()
	if items == nil {
		// If it's a scalar, treat it as a single-element slice
		if n.Kind == ScalarNode && !n.IsNull {
			s := n.String()
			if s != "" {
				return []string{s}
			}
		}
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		s := item.String()
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}
