package config

import (
	"errors"
	"fmt"
	"reflect"
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
					Enabled:           true,
					DefaultTTL:        1 * time.Hour,
					MaxTTL:            24 * time.Hour,
					MaxAutoBanEntries: 100000,
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
					"sqli":   {Enabled: true, Multiplier: 1.0},
					"xss":    {Enabled: true, Multiplier: 1.0},
					"lfi":    {Enabled: true, Multiplier: 1.0},
					"cmdi":   {Enabled: true, Multiplier: 1.0},
					"xxe":    {Enabled: true, Multiplier: 1.0},
					"ssrf":   {Enabled: true, Multiplier: 1.0},
					"ssti":   {Enabled: true, Multiplier: 1.0},
					"nosqli": {Enabled: true, Multiplier: 1.0},
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
				BlockIntrospection: true,
				AllowEndpoints:     []string{"/graphql", "/api/graphql"},
			},
			GRPC: GRPCConfig{
				Enabled:              false, // layer removed; kept parsed-but-inert for old configs
				GRPCWebEnabled:       true,
				ReflectionEnabled:    false,
				ValidateProto:        false,           // Enable for strict validation
				MaxMessageSize:       4 * 1024 * 1024, // 4MB
				MaxStreamDuration:    30 * time.Minute,
				MaxConcurrentStreams: 100,
				RequireTLS:           true,
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
			SIEM: SIEMConfig{
				Enabled:       false,
				Format:        "json",
				BatchSize:     100,
				FlushInterval: 5 * time.Second,
				Timeout:       10 * time.Second,
				Fields:        make(map[string]string),
			},
			Cache: CacheConfig{
				Enabled:              false,
				Backend:              "memory",
				TTL:                  5 * time.Minute,
				MaxSize:              100,
				Prefix:               "gwaf",
				CacheMethods:         []string{"GET", "HEAD"},
				CacheStatusCodes:     []int{200, 301, 302, 404},
				SkipPaths:            []string{"/api/login", "/api/logout", "/healthz"},
				MaxCacheSize:         1024,
				StaleWhileRevalidate: false,
			},
			Replay: ReplayConfig{
				Enabled:         false,
				StoragePath:     "data/replay",
				Format:          "json",
				MaxFileSize:     100,
				MaxFiles:        10,
				RetentionDays:   30,
				CaptureRequest:  true,
				CaptureResponse: false,
				SkipPaths:       []string{"/healthz", "/metrics", "/gwaf"},
				SkipMethods:     []string{"OPTIONS", "HEAD"},
				Compress:        true,
				Replay: ReplayEngineConfig{
					Enabled:         false,
					RateLimit:       100,
					Concurrency:     10,
					Timeout:         30 * time.Second,
					FollowRedirects: false,
					ModifyHost:      true,
					PreserveIDs:     false,
					DryRun:          false,
					Headers:         make(map[string]string),
				},
			},
			Canary: CanaryConfig{
				Enabled:          false,
				Strategy:         "percentage",
				Percentage:       10,
				HeaderName:       "X-Canary",
				CookieName:       "canary",
				AutoRollback:     true,
				ErrorThreshold:   5.0,
				LatencyThreshold: 500 * time.Millisecond,
				HealthCheckPath:  "/healthz",
				Metadata:         make(map[string]string),
			},
			Analytics: AnalyticsConfig{
				Enabled:          false, // layer removed; kept parsed-but-inert for old configs
				StoragePath:      "data/analytics",
				RetentionDays:    30,
				FlushInterval:    60 * time.Second,
				MaxDataPoints:    10000,
				EnableTimeSeries: true,
			},
			ClusterSync: ClusterSyncConfig{
				Enabled:            false,
				NodeID:             "",
				NodeName:           "node-1",
				Listen:             "0.0.0.0",
				Port:               9444,
				SharedSecret:       "",
				SyncInterval:       30 * time.Second,
				ConflictResolution: "last_write_wins",
				MaxRetries:         3,
				RetryDelay:         5 * time.Second,
				Clusters:           []ClusterMembership{},
			},
			Cluster: ClusterConfig{
				Enabled: false,
				Config:  nil,
			},
			Remediation: RemediationConfig{
				Enabled:             false,
				AutoApply:           false,
				ConfidenceThreshold: 85,
				MaxRulesPerDay:      10,
				RuleTTL:             24 * time.Hour,
				ExcludedPaths:       []string{"/healthz", "/metrics", "/api/v1/status"},
				StoragePath:         "data/remediation",
			},
			WebSocket: WebSocketConfig{
				Enabled:             false, // layer removed; kept parsed-but-inert for old configs
				MaxMessageSize:      10 * 1024 * 1024,
				MaxFrameSize:        1 * 1024 * 1024,
				RateLimitPerSecond:  100,
				RateLimitBurst:      50,
				AllowedOrigins:      []string{},
				BlockedExtensions:   []string{},
				BlockEmptyMessages:  false,
				BlockBinaryMessages: false,
				MaxConcurrentPerIP:  100,
				HandshakeTimeout:    10 * time.Second,
				IdleTimeout:         60 * time.Second,
				ScanPayloads:        true,
			},
			CRS: CRSConfig{
				Enabled:          false,
				ParanoiaLevel:    1,
				AnomalyThreshold: 5,
				RulePath:         "",
				Exclusions:       []string{},
				DisabledRules:    []string{},
			},
			VirtualPatch: VirtualPatchConfig{
				Enabled:           false,
				AutoUpdate:        true,
				UpdateInterval:    24 * time.Hour,
				NVDFeedURL:        "https://services.nvd.nist.gov/rest/json/cves/2.0",
				AutoGenerateRules: true,
				BlockSeverity:     []string{"CRITICAL", "HIGH"},
				NotifyOnPatch:     true,
			},
		},
		Dashboard: DashboardConfig{
			Enabled: true,
			Listen:  ":9443",
			TLS:     false,
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
	if v := node.Get("allow_private_upstreams"); v != nil {
		b, err := nodeBool(v)
		if err != nil {
			return fmt.Errorf("allow_private_upstreams: %w", err)
		}
		cfg.AllowPrivateUpstreams = &b
	}
	if v := node.Get("allowed_upstream_cidrs"); v != nil {
		cfg.AllowedUpstreamCIDRs = nodeStringSlice(v)
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

	if err := populateTaggedValue(reflect.ValueOf(cfg), node); err != nil {
		return err
	}

	return nil
}

var durationType = reflect.TypeOf(time.Duration(0))

func populateTaggedValue(dst reflect.Value, node *Node) error {
	if node == nil || node.IsNull || !dst.IsValid() {
		return nil
	}
	for dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		dst = dst.Elem()
	}

	switch dst.Kind() {
	case reflect.Struct:
		if dst.Type() == durationType {
			d, err := parseDuration(node.String())
			if err != nil {
				return err
			}
			dst.SetInt(int64(d))
			return nil
		}
		if node.Kind != MapNode {
			return nil
		}
		return populateTaggedStruct(dst, node)
	case reflect.String:
		dst.SetString(node.String())
	case reflect.Bool:
		b, err := nodeBool(node)
		if err != nil {
			return err
		}
		dst.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if dst.Type() == durationType {
			d, err := parseDuration(node.String())
			if err != nil {
				return err
			}
			dst.SetInt(int64(d))
			return nil
		}
		i, err := nodeInt64(node)
		if err != nil {
			return err
		}
		dst.SetInt(i)
	case reflect.Float32, reflect.Float64:
		f, err := nodeFloat64(node)
		if err != nil {
			return err
		}
		dst.SetFloat(f)
	case reflect.Slice:
		return populateTaggedSlice(dst, node)
	case reflect.Map:
		return populateTaggedMap(dst, node)
	case reflect.Interface:
		dst.Set(reflect.ValueOf(nodeToInterface(node)))
	}
	return nil
}

func populateTaggedStruct(dst reflect.Value, node *Node) error {
	typ := dst.Type()
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !dst.Field(i).CanSet() {
			continue
		}
		name := yamlFieldName(field)
		if name == "" {
			continue
		}
		child := node.Get(name)
		if child == nil || child.IsNull {
			continue
		}
		if err := populateTaggedValue(dst.Field(i), child); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func populateTaggedSlice(dst reflect.Value, node *Node) error {
	if node.Kind != SequenceNode {
		return nil
	}
	elemType := dst.Type().Elem()
	items := node.Slice()
	out := reflect.MakeSlice(dst.Type(), 0, len(items))
	for i, item := range items {
		if elemType.Kind() == reflect.Struct && item.Kind != MapNode {
			continue
		}
		elem := reflect.New(elemType).Elem()
		if i < dst.Len() {
			elem.Set(dst.Index(i))
		}
		if err := populateTaggedValue(elem, item); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
		out = reflect.Append(out, elem)
	}
	dst.Set(out)
	return nil
}

func populateTaggedMap(dst reflect.Value, node *Node) error {
	if node.Kind != MapNode {
		return nil
	}
	if dst.Type().Key().Kind() != reflect.String {
		return nil
	}
	valueType := dst.Type().Elem()
	out := reflect.MakeMapWithSize(dst.Type(), len(node.MapItems))
	if !dst.IsNil() {
		for _, key := range dst.MapKeys() {
			out.SetMapIndex(key, dst.MapIndex(key))
		}
	}
	for _, key := range node.MapKeys {
		child := node.MapItems[key]
		if child == nil || child.IsNull {
			continue
		}
		value := reflect.New(valueType).Elem()
		mapKey := reflect.ValueOf(key)
		if existing := out.MapIndex(mapKey); existing.IsValid() {
			value.Set(existing)
		}
		if err := populateTaggedValue(value, child); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		out.SetMapIndex(mapKey, value)
	}
	dst.Set(out)
	return nil
}

func nodeToInterface(node *Node) any {
	if node == nil || node.IsNull {
		return nil
	}
	switch node.Kind {
	case ScalarNode:
		if b, err := nodeBool(node); err == nil {
			return b
		}
		if i, err := nodeInt64(node); err == nil {
			return i
		}
		if f, err := nodeFloat64(node); err == nil {
			return f
		}
		return node.String()
	case SequenceNode:
		items := node.Slice()
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, nodeToInterface(item))
		}
		return out
	case MapNode:
		out := make(map[string]any, len(node.MapItems))
		for _, key := range node.MapKeys {
			out[key] = nodeToInterface(node.MapItems[key])
		}
		return out
	default:
		return nil
	}
}

// nodeBoolField populates a bool field from a config node, returning any parse error.
// parentKey is prepended to the field name in error messages for nested fields.
// A null value (e.g. `enabled:` with nothing) is treated as "not set" and keeps
// the existing default; only a present, non-null, malformed value is an error.
func nodeBoolField(n *Node, key, parentKey string, field *bool) error {
	if v := n.Get(key); v != nil && !v.IsNull {
		b, err := nodeBool(v)
		if err != nil {
			prefix := key
			if parentKey != "" {
				prefix = parentKey + "." + key
			}
			return fmt.Errorf("%s: %w", prefix, err)
		}
		*field = b
	}
	return nil
}

// nodeStringField populates a string field from a config node.
func nodeStringField(n *Node, key string, field *string) {
	if v := n.Get(key); v != nil && !v.IsNull {
		*field = v.String()
	}
}

// nodeIntField populates an int field from a config node, returning any parse error.
// parentKey is prepended to the field name in error messages for nested fields.
// A null value is treated as "not set" and keeps the existing default; only a
// present, non-null, malformed value is an error.
func nodeIntField(n *Node, key, parentKey string, field *int, minVal int) error {
	if v := n.Get(key); v != nil && !v.IsNull {
		i, err := nodeInt(v)
		if err != nil {
			prefix := key
			if parentKey != "" {
				prefix = parentKey + "." + key
			}
			return fmt.Errorf("%s: %w", prefix, err)
		}
		*field = i
	}
	return nil
}

// fieldErrs accumulates field-level parse errors within a populate function so
// every malformed value is reported together, and a typo (e.g. `enabled: ture`)
// fails the config load loudly instead of silently keeping the default.
type fieldErrs struct{ errs []error }

func (fe *fieldErrs) boolField(n *Node, key, parentKey string, field *bool) {
	if err := nodeBoolField(n, key, parentKey, field); err != nil {
		fe.errs = append(fe.errs, err)
	}
}

func (fe *fieldErrs) intField(n *Node, key, parentKey string, field *int, minVal int) {
	if err := nodeIntField(n, key, parentKey, field, minVal); err != nil {
		fe.errs = append(fe.errs, err)
	}
}

func (fe *fieldErrs) durationField(n *Node, key, parentKey string, field *time.Duration) {
	if v := n.Get(key); v != nil && !v.IsNull {
		d, err := parseDuration(v.String())
		if err != nil {
			prefix := key
			if parentKey != "" {
				prefix = parentKey + "." + key
			}
			fe.errs = append(fe.errs, fmt.Errorf("%s: %w", prefix, err))
			return
		}
		*field = d
	}
}

func (fe *fieldErrs) floatField(n *Node, key string, field *float64, minVal float64) {
	if v := n.Get(key); v != nil && !v.IsNull {
		f, err := nodeFloat64(v)
		if err != nil {
			fe.errs = append(fe.errs, fmt.Errorf("%s: %w", key, err))
			return
		}
		if f > minVal {
			*field = f
		}
	}
}

func (fe *fieldErrs) err() error { return errors.Join(fe.errs...) }

// --- TLS ---

func populateTLS(tls *TLSConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &tls.Enabled)
	nodeStringField(n, "listen", &tls.Listen)
	nodeStringField(n, "cert_file", &tls.CertFile)
	nodeStringField(n, "key_file", &tls.KeyFile)
	fe.boolField(n, "http_redirect", "", &tls.HTTPRedirect)
	if a := n.Get("acme"); a != nil {
		if err := populateACME(&tls.ACME, a); err != nil {
			return fmt.Errorf("acme: %w", err)
		}
	}
	return fe.err()
}

func populateACME(acme *ACMEConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &acme.Enabled)
	nodeStringField(n, "email", &acme.Email)
	if v := n.Get("domains"); v != nil {
		acme.Domains = nodeStringSlice(v)
	}
	nodeStringField(n, "cache_dir", &acme.CacheDir)
	return fe.err()
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
	if sub := n.Get("geoip"); sub != nil {
		if err := populateGeoIP(&waf.GeoIP, sub); err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
	}
	if sub := n.Get("threat_intel"); sub != nil {
		if err := populateThreatIntel(&waf.ThreatIntel, sub); err != nil {
			return fmt.Errorf("threat_intel: %w", err)
		}
	}
	if sub := n.Get("cors"); sub != nil {
		if err := populateCORS(&waf.CORS, sub); err != nil {
			return fmt.Errorf("cors: %w", err)
		}
	}
	if sub := n.Get("ato_protection"); sub != nil {
		if err := populateATOProtection(&waf.ATOProtection, sub); err != nil {
			return fmt.Errorf("ato_protection: %w", err)
		}
	}
	if sub := n.Get("api_security"); sub != nil {
		if err := populateAPISecurity(&waf.APISecurity, sub); err != nil {
			return fmt.Errorf("api_security: %w", err)
		}
	}
	if sub := n.Get("api_validation"); sub != nil {
		if err := populateAPIValidation(&waf.APIValidation, sub); err != nil {
			return fmt.Errorf("api_validation: %w", err)
		}
	}
	if sub := n.Get("client_side"); sub != nil {
		if err := populateClientSide(&waf.ClientSide, sub); err != nil {
			return fmt.Errorf("client_side: %w", err)
		}
	}
	if sub := n.Get("crs"); sub != nil {
		if err := populateCRS(&waf.CRS, sub); err != nil {
			return fmt.Errorf("crs: %w", err)
		}
	}
	return nil
}

func populateGeoIP(geo *GeoIPConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &geo.Enabled)
	nodeStringField(n, "db_path", &geo.DBPath)
	fe.boolField(n, "auto_download", "", &geo.AutoDownload)
	nodeStringField(n, "download_url", &geo.DownloadURL)
	fe.boolField(n, "require_ready", "", &geo.RequireReady)
	fe.boolField(n, "allow_insecure_url", "", &geo.AllowInsecureURL)
	return fe.err()
}

func populateThreatIntel(ti *ThreatIntelConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &ti.Enabled)
	fe.intField(n, "cache_size", "", &ti.CacheSize, 0)
	fe.durationField(n, "cache_ttl", "", &ti.CacheTTL)
	if sub := n.Get("ip_reputation"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "ip_reputation", &ti.IPReputation.Enabled)
		fe.boolField(sub, "block_malicious", "ip_reputation", &ti.IPReputation.BlockMalicious)
		fe.intField(sub, "score_threshold", "ip_reputation", &ti.IPReputation.ScoreThreshold, 0)
	}
	if sub := n.Get("domain_reputation"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "domain_reputation", &ti.DomainRep.Enabled)
		fe.boolField(sub, "block_malicious", "domain_reputation", &ti.DomainRep.BlockMalicious)
		fe.boolField(sub, "check_redirects", "domain_reputation", &ti.DomainRep.CheckRedirects)
	}
	if sub := n.Get("feeds"); sub != nil && sub.Kind == SequenceNode {
		feedSlice := sub.Slice()
		ti.Feeds = make([]ThreatFeedConfig, 0, len(feedSlice))
		for i, child := range feedSlice {
			if child.Kind != MapNode {
				continue
			}
			var f ThreatFeedConfig
			nodeStringField(child, "type", &f.Type)
			nodeStringField(child, "path", &f.Path)
			nodeStringField(child, "url", &f.URL)
			nodeStringField(child, "format", &f.Format)
			if err := nodeBoolField(child, "allow_insecure_url", "", &f.AllowInsecureURL); err != nil {
				return fmt.Errorf("feeds[%d].allow_insecure_url: %w", i, err)
			}
			if v := child.Get("refresh"); v != nil && !v.IsNull {
				if d, err := parseDuration(v.String()); err == nil {
					f.Refresh = d
				} else {
					return fmt.Errorf("feeds[%d].refresh: %w", i, err)
				}
			}
			ti.Feeds = append(ti.Feeds, f)
		}
	}
	return fe.err()
}

func populateCORS(cors *CORSConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &cors.Enabled)
	fe.boolField(n, "allow_credentials", "", &cors.AllowCredentials)
	fe.boolField(n, "strict_mode", "", &cors.StrictMode)
	fe.intField(n, "max_age_seconds", "", &cors.MaxAgeSeconds, 0)
	fe.intField(n, "preflight_cache_seconds", "", &cors.PreflightCacheSeconds, 0)
	if v := n.Get("allow_origins"); v != nil && v.Kind == SequenceNode {
		cors.AllowOrigins = nodeStringSlice(v)
	}
	if v := n.Get("allow_methods"); v != nil && v.Kind == SequenceNode {
		cors.AllowMethods = nodeStringSlice(v)
	}
	if v := n.Get("allow_headers"); v != nil && v.Kind == SequenceNode {
		cors.AllowHeaders = nodeStringSlice(v)
	}
	if v := n.Get("expose_headers"); v != nil && v.Kind == SequenceNode {
		cors.ExposeHeaders = nodeStringSlice(v)
	}
	return fe.err()
}

func populateATOProtection(ato *ATOProtectionConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &ato.Enabled)
	nodeStringField(n, "geodb_path", &ato.GeoDBPath)
	if v := n.Get("login_paths"); v != nil && v.Kind == SequenceNode {
		ato.LoginPaths = nodeStringSlice(v)
	}
	if sub := n.Get("brute_force"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "brute_force", &ato.BruteForce.Enabled)
		fe.durationField(sub, "window", "", &ato.BruteForce.Window)
		fe.intField(sub, "max_attempts_per_ip", "brute_force", &ato.BruteForce.MaxAttemptsPerIP, 0)
		fe.intField(sub, "max_attempts_per_email", "brute_force", &ato.BruteForce.MaxAttemptsPerEmail, 0)
		fe.durationField(sub, "block_duration", "", &ato.BruteForce.BlockDuration)
	}
	if sub := n.Get("credential_stuffing"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "credential_stuffing", &ato.CredStuffing.Enabled)
		fe.intField(sub, "distributed_threshold", "credential_stuffing", &ato.CredStuffing.DistributedThreshold, 0)
		fe.durationField(sub, "window", "", &ato.CredStuffing.Window)
		fe.durationField(sub, "block_duration", "", &ato.CredStuffing.BlockDuration)
	}
	if sub := n.Get("password_spray"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "password_spray", &ato.PasswordSpray.Enabled)
		fe.intField(sub, "threshold", "password_spray", &ato.PasswordSpray.Threshold, 0)
		fe.durationField(sub, "window", "", &ato.PasswordSpray.Window)
		fe.durationField(sub, "block_duration", "", &ato.PasswordSpray.BlockDuration)
	}
	if sub := n.Get("impossible_travel"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "impossible_travel", &ato.Travel.Enabled)
		fe.floatField(sub, "max_distance_km", &ato.Travel.MaxDistanceKm, 0)
		fe.floatField(sub, "max_time_hours", &ato.Travel.MaxTimeHours, 0)
		fe.durationField(sub, "block_duration", "", &ato.Travel.BlockDuration)
	}
	return fe.err()
}

func populateAPISecurity(as *APISecurityConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &as.Enabled)
	nodeStringField(n, "header_name", &as.HeaderName)
	nodeStringField(n, "query_param", &as.QueryParam)
	if v := n.Get("skip_paths"); v != nil && v.Kind == SequenceNode {
		as.SkipPaths = nodeStringSlice(v)
	}
	if sub := n.Get("jwt"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "jwt", &as.JWT.Enabled)
		nodeStringField(sub, "issuer", &as.JWT.Issuer)
		nodeStringField(sub, "audience", &as.JWT.Audience)
		nodeStringField(sub, "public_key_file", &as.JWT.PublicKeyFile)
		nodeStringField(sub, "jwks_url", &as.JWT.JWKSURL)
		nodeStringField(sub, "public_key_pem", &as.JWT.PublicKeyPEM)
		if v := sub.Get("algorithms"); v != nil && v.Kind == SequenceNode {
			as.JWT.Algorithms = nodeStringSlice(v)
		}
		fe.intField(sub, "clock_skew_seconds", "jwt", &as.JWT.ClockSkewSeconds, 0)
	}
	if sub := n.Get("api_keys"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "api_keys", &as.APIKeys.Enabled)
		nodeStringField(sub, "header_name", &as.APIKeys.HeaderName)
		nodeStringField(sub, "query_param", &as.APIKeys.QueryParam)
		if v := sub.Get("keys"); v != nil && v.Kind == SequenceNode {
			keysSlice := v.Slice()
			as.APIKeys.Keys = make([]APIKeyConfig, 0, len(keysSlice))
			for _, child := range keysSlice {
				if child.Kind != MapNode {
					continue
				}
				var k APIKeyConfig
				nodeStringField(child, "name", &k.Name)
				nodeStringField(child, "key_hash", &k.KeyHash)
				nodeStringField(child, "key_prefix", &k.KeyPrefix)
				fe.boolField(child, "enabled", "", &k.Enabled)
				fe.intField(child, "rate_limit", "key", &k.RateLimit, 0)
				if pv := child.Get("allowed_paths"); pv != nil && pv.Kind == SequenceNode {
					k.AllowedPaths = nodeStringSlice(pv)
				}
				as.APIKeys.Keys = append(as.APIKeys.Keys, k)
			}
		}
	}
	return fe.err()
}

func populateAPIValidation(av *APIValidationConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &av.Enabled)
	fe.boolField(n, "validate_request", "", &av.ValidateRequest)
	fe.boolField(n, "validate_response", "", &av.ValidateResponse)
	fe.boolField(n, "strict_mode", "", &av.StrictMode)
	fe.boolField(n, "block_on_violation", "", &av.BlockOnViolation)
	fe.intField(n, "violation_score", "", &av.ViolationScore, 0)
	fe.intField(n, "cache_size", "", &av.CacheSize, 0)
	if v := n.Get("schemas"); v != nil && v.Kind == SequenceNode {
		schemaSlice := v.Slice()
		av.Schemas = make([]SchemaSourceConfig, 0, len(schemaSlice))
		for _, child := range schemaSlice {
			if child.Kind != MapNode {
				continue
			}
			var s SchemaSourceConfig
			nodeStringField(child, "path", &s.Path)
			nodeStringField(child, "type", &s.Type)
			fe.boolField(child, "auto_learn", "", &s.AutoLearn)
			av.Schemas = append(av.Schemas, s)
		}
	}
	return fe.err()
}

func populateClientSide(cs *ClientSideConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &cs.Enabled)
	nodeStringField(n, "mode", &cs.Mode)
	if v := n.Get("exclusions"); v != nil && v.Kind == SequenceNode {
		cs.Exclusions = nodeStringSlice(v)
	}
	if sub := n.Get("magecart_detection"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "magecart_detection", &cs.MagecartDetection.Enabled)
		fe.boolField(sub, "detect_obfuscated_js", "magecart_detection", &cs.MagecartDetection.DetectObfuscatedJS)
		fe.boolField(sub, "detect_suspicious_domains", "magecart_detection", &cs.MagecartDetection.DetectSuspiciousDomains)
		fe.boolField(sub, "detect_form_exfiltration", "magecart_detection", &cs.MagecartDetection.DetectFormExfiltration)
		fe.boolField(sub, "detect_keyloggers", "magecart_detection", &cs.MagecartDetection.DetectKeyloggers)
		fe.intField(sub, "block_score", "magecart_detection", &cs.MagecartDetection.BlockScore, 0)
		fe.intField(sub, "alert_score", "magecart_detection", &cs.MagecartDetection.AlertScore, 0)
		if v := sub.Get("known_skimming_domains"); v != nil && v.Kind == SequenceNode {
			cs.MagecartDetection.KnownSkimmingDomains = nodeStringSlice(v)
		}
	}
	if sub := n.Get("agent_injection"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "agent_injection", &cs.AgentInjection.Enabled)
		nodeStringField(sub, "script_url", &cs.AgentInjection.ScriptURL)
		fe.boolField(sub, "inject_in_html", "agent_injection", &cs.AgentInjection.InjectInHTML)
		nodeStringField(sub, "inject_position", &cs.AgentInjection.InjectPosition)
		fe.boolField(sub, "monitor_dom", "agent_injection", &cs.AgentInjection.MonitorDOM)
		fe.boolField(sub, "monitor_network", "agent_injection", &cs.AgentInjection.MonitorNetwork)
		fe.boolField(sub, "monitor_forms", "agent_injection", &cs.AgentInjection.MonitorForms)
	}
	if sub := n.Get("csp"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "csp", &cs.CSP.Enabled)
		fe.boolField(sub, "report_only", "csp", &cs.CSP.ReportOnly)
		cs.CSP.DefaultSrc = nodeStringSlice(sub.Get("default_src"))
		cs.CSP.ScriptSrc = nodeStringSlice(sub.Get("script_src"))
		cs.CSP.StyleSrc = nodeStringSlice(sub.Get("style_src"))
		cs.CSP.ImgSrc = nodeStringSlice(sub.Get("img_src"))
		cs.CSP.ConnectSrc = nodeStringSlice(sub.Get("connect_src"))
		cs.CSP.FontSrc = nodeStringSlice(sub.Get("font_src"))
		cs.CSP.ObjectSrc = nodeStringSlice(sub.Get("object_src"))
		cs.CSP.MediaSrc = nodeStringSlice(sub.Get("media_src"))
		cs.CSP.FrameSrc = nodeStringSlice(sub.Get("frame_src"))
		cs.CSP.FrameAncestors = nodeStringSlice(sub.Get("frame_ancestors"))
		cs.CSP.FormAction = nodeStringSlice(sub.Get("form_action"))
		cs.CSP.BaseURI = nodeStringSlice(sub.Get("base_uri"))
		nodeStringField(sub, "report_uri", &cs.CSP.ReportURI)
		fe.boolField(sub, "upgrade_insecure_requests", "csp", &cs.CSP.UpgradeInsecure)
	}
	return fe.err()
}

func populateCRS(crs *CRSConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &crs.Enabled)
	nodeStringField(n, "rule_path", &crs.RulePath)
	fe.intField(n, "paranoia_level", "", &crs.ParanoiaLevel, 0)
	fe.intField(n, "anomaly_threshold", "", &crs.AnomalyThreshold, 0)
	if v := n.Get("exclusions"); v != nil && v.Kind == SequenceNode {
		crs.Exclusions = nodeStringSlice(v)
	}
	if v := n.Get("disabled_rules"); v != nil && v.Kind == SequenceNode {
		crs.DisabledRules = nodeStringSlice(v)
	}
	return fe.err()
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
	if err := nodeBoolField(n, "enabled", "", &gql.Enabled); err != nil {
		return err
	}
	if err := nodeIntField(n, "max_depth", "", &gql.MaxDepth, 0); err != nil {
		return err
	}
	if err := nodeIntField(n, "max_complexity", "", &gql.MaxComplexity, 0); err != nil {
		return err
	}
	if err := nodeBoolField(n, "block_introspection", "", &gql.BlockIntrospection); err != nil {
		return err
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
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &ch.Enabled)
	fe.intField(n, "difficulty", "", &ch.Difficulty, 1)
	fe.durationField(n, "cookie_ttl", "", &ch.CookieTTL)
	nodeStringField(n, "cookie_name", &ch.CookieName)
	nodeStringField(n, "secret_key", &ch.SecretKey)
	return fe.err()
}

func populateIPACL(acl *IPACLConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if err := nodeBoolField(n, "enabled", "", &acl.Enabled); err != nil {
		return err
	}
	if v := n.Get("whitelist"); v != nil {
		acl.Whitelist = nodeStringSlice(v)
	}
	if v := n.Get("blacklist"); v != nil {
		acl.Blacklist = nodeStringSlice(v)
	}
	if sub := n.Get("auto_ban"); sub != nil && sub.Kind == MapNode {
		if err := nodeBoolField(sub, "enabled", "auto_ban", &acl.AutoBan.Enabled); err != nil {
			return err
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
	if err := nodeBoolField(n, "enabled", "", &san.Enabled); err != nil {
		return err
	}
	if err := nodeIntField(n, "max_url_length", "", &san.MaxURLLength, 0); err != nil {
		return err
	}
	if err := nodeIntField(n, "max_header_size", "", &san.MaxHeaderSize, 0); err != nil {
		return err
	}
	if err := nodeIntField(n, "max_header_count", "", &san.MaxHeaderCount, 0); err != nil {
		return err
	}
	if v := n.Get("max_body_size"); v != nil {
		i, err := nodeInt64(v)
		if err != nil {
			return fmt.Errorf("max_body_size: %w", err)
		}
		san.MaxBodySize = i
	}
	if err := nodeIntField(n, "max_cookie_size", "", &san.MaxCookieSize, 0); err != nil {
		return err
	}
	if err := nodeBoolField(n, "block_null_bytes", "", &san.BlockNullBytes); err != nil {
		return err
	}
	if err := nodeBoolField(n, "normalize_encoding", "", &san.NormalizeEncoding); err != nil {
		return err
	}
	if err := nodeBoolField(n, "strip_hop_by_hop", "", &san.StripHopByHop); err != nil {
		return err
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
	if err := nodeBoolField(n, "enabled", "", &det.Enabled); err != nil {
		return err
	}
	if th := n.Get("threshold"); th != nil && th.Kind == MapNode {
		if err := nodeIntField(th, "block", "threshold", &det.Threshold.Block, 0); err != nil {
			return err
		}
		if err := nodeIntField(th, "log", "threshold", &det.Threshold.Log, 0); err != nil {
			return err
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
			if err := nodeBoolField(sub, "enabled", "detectors."+key, &dc.Enabled); err != nil {
				return err
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
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &bd.Enabled)
	nodeStringField(n, "mode", &bd.Mode)
	if sub := n.Get("tls_fingerprint"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "tls_fingerprint", &bd.TLSFingerprint.Enabled)
		nodeStringField(sub, "known_bots_action", &bd.TLSFingerprint.KnownBotsAction)
		nodeStringField(sub, "unknown_action", &bd.TLSFingerprint.UnknownAction)
		nodeStringField(sub, "mismatch_action", &bd.TLSFingerprint.MismatchAction)
	}
	if sub := n.Get("user_agent"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "user_agent", &bd.UserAgent.Enabled)
		fe.boolField(sub, "block_empty", "user_agent", &bd.UserAgent.BlockEmpty)
		fe.boolField(sub, "block_known_scanners", "user_agent", &bd.UserAgent.BlockKnownScanners)
	}
	if sub := n.Get("behavior"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "behavior", &bd.Behavior.Enabled)
		fe.durationField(sub, "window", "behavior", &bd.Behavior.Window)
		fe.intField(sub, "rps_threshold", "behavior", &bd.Behavior.RPSThreshold, 0)
		fe.intField(sub, "error_rate_threshold", "behavior", &bd.Behavior.ErrorRateThreshold, 0)
	}
	return fe.err()
}

func populateResponse(resp *ResponseConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
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
		fe.boolField(sub, "enabled", "error_pages", &resp.ErrorPages.Enabled)
		nodeStringField(sub, "mode", &resp.ErrorPages.Mode)
	}
	return fe.err()
}

func populateSecurityHeaders(sh *SecurityHeadersConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &sh.Enabled)
	if sub := n.Get("hsts"); sub != nil && sub.Kind == MapNode {
		fe.boolField(sub, "enabled", "hsts", &sh.HSTS.Enabled)
		fe.intField(sub, "max_age", "hsts", &sh.HSTS.MaxAge, 0)
		fe.boolField(sub, "include_subdomains", "hsts", &sh.HSTS.IncludeSubDomains)
	}
	fe.boolField(n, "x_content_type_options", "", &sh.XContentTypeOptions)
	nodeStringField(n, "x_frame_options", &sh.XFrameOptions)
	nodeStringField(n, "referrer_policy", &sh.ReferrerPolicy)
	nodeStringField(n, "permissions_policy", &sh.PermissionsPolicy)
	return fe.err()
}

func populateDataMasking(dm *DataMaskingConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &dm.Enabled)
	fe.boolField(n, "mask_credit_cards", "", &dm.MaskCreditCards)
	fe.boolField(n, "mask_ssn", "", &dm.MaskSSN)
	fe.boolField(n, "mask_api_keys", "", &dm.MaskAPIKeys)
	fe.boolField(n, "strip_stack_traces", "", &dm.StripStackTraces)
	return fe.err()
}

// --- Dashboard ---

func populateDashboard(dash *DashboardConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &dash.Enabled)
	nodeStringField(n, "listen", &dash.Listen)
	nodeStringField(n, "api_key", &dash.APIKey)
	nodeStringField(n, "admin_key", &dash.AdminKey)
	nodeStringField(n, "audit_path", &dash.AuditPath)
	fe.boolField(n, "tls", "", &dash.TLS)
	return fe.err()
}

// --- MCP ---

func populateMCP(mcp *MCPConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &mcp.Enabled)
	nodeStringField(n, "transport", &mcp.Transport)
	return fe.err()
}

func populateDocker(dock *DockerConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	fe.boolField(n, "enabled", "", &dock.Enabled)
	nodeStringField(n, "socket_path", &dock.SocketPath)
	fe.boolField(n, "tls_verify", "", &dock.TLSVerify)
	nodeStringField(n, "tls_ca_cert", &dock.TLSCACert)
	nodeStringField(n, "tls_cert", &dock.TLSCert)
	nodeStringField(n, "tls_key", &dock.TLSKey)
	nodeStringField(n, "label_prefix", &dock.LabelPrefix)
	fe.durationField(n, "poll_interval", "", &dock.PollInterval)
	nodeStringField(n, "network", &dock.Network)
	return fe.err()
}

func populateLogging(log *LogConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	nodeStringField(n, "level", &log.Level)
	nodeStringField(n, "format", &log.Format)
	nodeStringField(n, "output", &log.Output)
	fe.boolField(n, "log_allowed", "", &log.LogAllowed)
	fe.boolField(n, "log_blocked", "", &log.LogBlocked)
	fe.boolField(n, "log_body", "", &log.LogBody)
	return fe.err()
}

// --- Events ---

func populateEvents(ev *EventsConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	var fe fieldErrs
	nodeStringField(n, "storage", &ev.Storage)
	fe.intField(n, "max_events", "", &ev.MaxEvents, 0)
	nodeStringField(n, "file_path", &ev.FilePath)
	return fe.err()
}

// --- Alerting ---

func populateAlerting(alert *AlertingConfig, n *Node) error {
	if n.Kind != MapNode {
		return nil
	}
	if err := nodeBoolField(n, "enabled", "", &alert.Enabled); err != nil {
		return err
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
