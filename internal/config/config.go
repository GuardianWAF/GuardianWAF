// Package config provides configuration types and loading for GuardianWAF.
// All structs mirror the YAML configuration schema defined in SPECIFICATION.md.
// The yaml struct tags are documentary — actual loading uses the YAML parser's Node tree.
package config

import (
	"strings"
	"time"
)

// Config is the top-level configuration for GuardianWAF.
type Config struct {
	Mode   string    `yaml:"mode"`   // "enforce", "monitor", "disabled"
	Listen string    `yaml:"listen"` // Listen address (e.g., ":8088")
	TLS    TLSConfig `yaml:"tls"`

	Upstreams    []UpstreamConfig    `yaml:"upstreams"`
	Routes       []RouteConfig       `yaml:"routes"`
	VirtualHosts []VirtualHostConfig `yaml:"virtual_hosts"`

	WAF       WAFConfig       `yaml:"waf"`
	Dashboard DashboardConfig `yaml:"dashboard"`
	MCP       MCPConfig       `yaml:"mcp"`
	Docker    DockerConfig    `yaml:"docker"`
	Alerting  AlertingConfig  `yaml:"alerting"`
	Logging        LogConfig       `yaml:"logging"`
	Events         EventsConfig    `yaml:"events"`
	Tenant         TenantConfig    `yaml:"tenant"`
	TrustedProxies []string        `yaml:"trusted_proxies"` // CIDRs/IPs whose X-Forwarded-For/X-Real-IP headers are trusted
	Tracing        TracingConfig   `yaml:"tracing"`
}

// AlertingConfig controls webhook and email-based alert delivery.
type AlertingConfig struct {
	Enabled  bool            `yaml:"enabled"`
	Webhooks []WebhookConfig `yaml:"webhooks"`
	Emails   []EmailConfig   `yaml:"emails"`
}

// WebhookConfig defines a single webhook target.
type WebhookConfig struct {
	Name     string            `yaml:"name"`
	URL      string            `yaml:"url"`
	Type     string            `yaml:"type"`   // "slack", "discord", "generic", "pagerduty"
	Events   []string          `yaml:"events"` // "block", "challenge", "log", "all"
	MinScore int               `yaml:"min_score"`
	Cooldown time.Duration     `yaml:"cooldown"`
	Headers  map[string]string `yaml:"headers"`
}

// EmailConfig defines SMTP email alert delivery.
type EmailConfig struct {
	Name     string        `yaml:"name"`
	SMTPHost string        `yaml:"smtp_host"`
	SMTPPort int           `yaml:"smtp_port"`
	Username string        `yaml:"username"`
	Password string        `yaml:"password"`
	From     string        `yaml:"from"`
	To       []string      `yaml:"to"`
	UseTLS   bool          `yaml:"use_tls"`
	Events   []string      `yaml:"events"`
	MinScore int           `yaml:"min_score"`
	Cooldown time.Duration `yaml:"cooldown"`
	Subject  string        `yaml:"subject"`  // optional custom subject template
	Template string        `yaml:"template"` // optional custom body template
}

// DockerConfig controls Docker container auto-discovery.
type DockerConfig struct {
	Enabled      bool          `yaml:"enabled"`
	SocketPath   string        `yaml:"socket_path"`   // default: /var/run/docker.sock
	LabelPrefix  string        `yaml:"label_prefix"`  // default: gwaf
	PollInterval time.Duration `yaml:"poll_interval"` // default: 5s
	Network      string        `yaml:"network"`       // default: bridge
}

// TLSConfig holds TLS/SSL settings including optional ACME auto-certificate.
type TLSConfig struct {
	Enabled      bool       `yaml:"enabled"`
	Listen       string     `yaml:"listen"`
	CertFile     string     `yaml:"cert_file"`
	KeyFile      string     `yaml:"key_file"`
	HTTPRedirect bool       `yaml:"http_redirect"` // redirect HTTP→HTTPS when TLS enabled
	ACME         ACMEConfig `yaml:"acme"`
	HTTP3        HTTP3Config `yaml:"http3"`
}

// ACMEConfig holds automatic certificate management settings.
type ACMEConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Email    string   `yaml:"email"`
	Domains  []string `yaml:"domains"`
	CacheDir string   `yaml:"cache_dir"`
}

// HTTP3Config controls HTTP/3 and QUIC settings.
type HTTP3Config struct {
	Enabled            bool          `yaml:"enabled"`
	Listen             string        `yaml:"listen"`              // UDP listen address (default: same as TLS)
	MaxHeaderBytes     int           `yaml:"max_header_bytes"`    // Max header size (default: 1MB)
	ReadTimeout        time.Duration `yaml:"read_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout"`
	IdleTimeout        time.Duration `yaml:"idle_timeout"`
	Enable0RTT         bool          `yaml:"enable_0rtt"`         // Enable 0-RTT handshake
	EnableDatagrams    bool          `yaml:"enable_datagrams"`    // Enable HTTP/3 datagrams (WebTransport)
	AltSvcPort         int           `yaml:"alt_svc_port"`        // Port advertised in Alt-Svc header
	AdvertiseAltSvc    bool          `yaml:"advertise_alt_svc"`   // Advertise HTTP/3 via Alt-Svc header
}

// UpstreamConfig defines a named group of backend targets with health checking.
type UpstreamConfig struct {
	Name         string            `yaml:"name"`
	Targets      []TargetConfig    `yaml:"targets"`
	HealthCheck  HealthCheckConfig `yaml:"health_check"`
	LoadBalancer string            `yaml:"load_balancer"` // "round_robin", "weighted", "least_conn", "ip_hash"
}

// TargetConfig is a single backend target with an optional weight for load balancing.
type TargetConfig struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"`
}

// HealthCheckConfig controls periodic health probes against upstream targets.
type HealthCheckConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Path     string        `yaml:"path"`
}

// RouteConfig maps an incoming path prefix to a named upstream.
type RouteConfig struct {
	Path        string   `yaml:"path"`
	Upstream    string   `yaml:"upstream"`
	StripPrefix bool     `yaml:"strip_prefix"`
	Methods     []string `yaml:"methods"`
}

// VirtualHostConfig maps domain names to routes with optional per-vhost TLS.
type VirtualHostConfig struct {
	Domains []string       `yaml:"domains"` // e.g., ["api.example.com", "*.api.example.com"]
	TLS     VHostTLSConfig `yaml:"tls"`
	Routes  []RouteConfig  `yaml:"routes"`
	WAF     *WAFConfig     `yaml:"waf,omitempty"` // Per-domain WAF override; nil = use global
}

// VHostTLSConfig holds per-virtual-host TLS certificate paths.
type VHostTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// CustomRulesConfig controls the custom rule engine.
type CustomRulesConfig struct {
	Enabled bool         `yaml:"enabled"`
	Rules   []CustomRule `yaml:"rules"`
}

// CustomRule defines a single custom WAF rule.
type CustomRule struct {
	ID         string          `yaml:"id"`
	Name       string          `yaml:"name"`
	Enabled    bool            `yaml:"enabled"`
	Priority   int             `yaml:"priority"`
	Conditions []RuleCondition `yaml:"conditions"`
	Action     string          `yaml:"action"` // "block", "log", "challenge", "pass"
	Score      int             `yaml:"score"`
}

// RuleCondition defines a match condition for a custom rule.
type RuleCondition struct {
	Field string `yaml:"field"` // "path", "method", "ip", "country", "header:X-Name", "user_agent", etc.
	Op    string `yaml:"op"`    // "equals", "contains", "starts_with", "matches", "in", "in_cidr", etc.
	Value any    `yaml:"value"` // string, []string, or number
}

// GeoIPConfig controls GeoIP database loading.
type GeoIPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	DBPath       string `yaml:"db_path"`       // path to CSV database
	AutoDownload bool   `yaml:"auto_download"` // auto-download DB-IP Lite if missing
	DownloadURL  string `yaml:"download_url"`  // custom download URL (default: DB-IP Lite)
}

// WAFConfig is the top-level container for all WAF protection settings.
type WAFConfig struct {
	IPACL            IPACLConfig            `yaml:"ip_acl"`
	CustomRules      CustomRulesConfig      `yaml:"custom_rules"`
	GeoIP            GeoIPConfig            `yaml:"geoip"`
	ThreatIntel      ThreatIntelConfig      `yaml:"threat_intel"`
	CORS             CORSConfig             `yaml:"cors"`
	RateLimit        RateLimitConfig        `yaml:"rate_limit"`
	ATOProtection    ATOProtectionConfig    `yaml:"ato_protection"`
	APISecurity      APISecurityConfig      `yaml:"api_security"`
	APIValidation    APIValidationConfig    `yaml:"api_validation"`
	Sanitizer        SanitizerConfig        `yaml:"sanitizer"`
	Detection        DetectionConfig        `yaml:"detection"`
	BotDetection     BotDetectionConfig     `yaml:"bot_detection"`
	Challenge        ChallengeConfig        `yaml:"challenge"`
	Response         ResponseConfig         `yaml:"response"`
	ClientSide       ClientSideConfig       `yaml:"client_side"`
	AIAnalysis       AIAnalysisConfig       `yaml:"ai_analysis"`
	MLAnomaly        MLAnomalyConfig        `yaml:"ml_anomaly"`
	APIDiscovery     APIDiscoveryConfig     `yaml:"api_discovery"`
	GraphQL          GraphQLConfig          `yaml:"graphql"`
	GRPC             GRPCConfig             `yaml:"grpc"`
	Tenant           TenantConfig           `yaml:"tenant"`
	DLP              DLPConfig              `yaml:"dlp"`
	ZeroTrust        ZeroTrustConfig        `yaml:"zero_trust"`
	SIEM             SIEMConfig             `yaml:"siem"`
	Cache            CacheConfig            `yaml:"cache"`
	Replay           ReplayConfig           `yaml:"replay"`
	Canary           CanaryConfig           `yaml:"canary"`
	Analytics        AnalyticsConfig        `yaml:"analytics"`
	ClusterSync      ClusterSyncConfig      `yaml:"cluster_sync"`
	Cluster          ClusterConfig          `yaml:"cluster"`
	Remediation      RemediationConfig      `yaml:"remediation"`
	WebSocket        WebSocketConfig        `yaml:"websocket"`
	CRS              CRSConfig              `yaml:"crs"`
	VirtualPatch     VirtualPatchConfig     `yaml:"virtual_patch"`
}

// AIAnalysisConfig controls AI-powered threat analysis.
type AIAnalysisConfig struct {
	Enabled          bool          `yaml:"enabled"`
	StorePath        string        `yaml:"store_path"`
	CatalogURL       string        `yaml:"catalog_url"`
	BatchSize        int           `yaml:"batch_size"`
	BatchInterval    time.Duration `yaml:"batch_interval"`
	MinScore         int           `yaml:"min_score"`
	MaxTokensPerHour int64         `yaml:"max_tokens_per_hour"`
	MaxTokensPerDay  int64         `yaml:"max_tokens_per_day"`
	MaxRequestsHour  int           `yaml:"max_requests_per_hour"`
	AutoBlock        bool          `yaml:"auto_block"`
	AutoBlockTTL     time.Duration `yaml:"auto_block_ttl"`
}

// DLPConfig controls Data Loss Prevention pattern detection.
type DLPConfig struct {
	Enabled      bool     `yaml:"enabled"`
	ScanRequest  bool     `yaml:"scan_request"`
	ScanResponse bool     `yaml:"scan_response"`
	BlockOnMatch bool     `yaml:"block_on_match"`
	MaskResponse bool     `yaml:"mask_response"`
	MaxBodySize  int      `yaml:"max_body_size"`
	Patterns     []string `yaml:"patterns"`
}

// ZeroTrustConfig controls Zero Trust Network Access settings.
type ZeroTrustConfig struct {
	Enabled              bool          `yaml:"enabled"`
	RequireMTLS          bool          `yaml:"require_mtls"`
	RequireAttestation   bool          `yaml:"require_attestation"`
	SessionTTL           time.Duration `yaml:"session_ttl"`
	AttestationTTL       time.Duration `yaml:"attestation_ttl"`
	TrustedCAPath        string        `yaml:"trusted_ca_path"`
	DeviceTrustThreshold string        `yaml:"device_trust_threshold"`
	AllowBypassPaths     []string      `yaml:"allow_bypass_paths"`
}

// CacheConfig controls cache layer settings.
type CacheConfig struct {
	Enabled              bool          `yaml:"enabled"`
	Backend              string        `yaml:"backend"` // "memory", "redis"
	TTL                  time.Duration `yaml:"ttl"`
	MaxSize              int           `yaml:"max_size"` // For memory backend (MB)
	RedisAddr            string        `yaml:"redis_addr"`
	RedisPass            string        `yaml:"redis_password"`
	RedisDB              int           `yaml:"redis_db"`
	Prefix               string        `yaml:"prefix"`
	CacheMethods         []string      `yaml:"cache_methods"`
	CacheStatusCodes     []int         `yaml:"cache_status_codes"`
	SkipPaths            []string      `yaml:"skip_paths"`
	MaxCacheSize         int           `yaml:"max_cache_size"` // KB per entry
	StaleWhileRevalidate bool          `yaml:"stale_while_revalidate"`
}

// ReplayConfig controls request recording and replay settings.
type ReplayConfig struct {
	Enabled         bool          `yaml:"enabled"`
	StoragePath     string        `yaml:"storage_path"`
	Format          string        `yaml:"format"` // "json", "binary"
	MaxFileSize     int64         `yaml:"max_file_size"` // MB
	MaxFiles        int           `yaml:"max_files"`
	RetentionDays   int           `yaml:"retention_days"`
	CaptureRequest  bool          `yaml:"capture_request"`
	CaptureResponse bool          `yaml:"capture_response"`
	CaptureHeaders  []string      `yaml:"capture_headers"`
	SkipPaths       []string      `yaml:"skip_paths"`
	SkipMethods     []string      `yaml:"skip_methods"`
	Compress        bool          `yaml:"compress"`
	Replay          ReplayEngineConfig `yaml:"replay"`
}

// ReplayEngineConfig controls replay engine behavior.
type ReplayEngineConfig struct {
	Enabled         bool              `yaml:"enabled"`
	TargetBaseURL   string            `yaml:"target_base_url"`
	RateLimit       int               `yaml:"rate_limit"`
	Concurrency     int               `yaml:"concurrency"`
	Timeout         time.Duration     `yaml:"timeout"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	ModifyHost      bool              `yaml:"modify_host"`
	PreserveIDs     bool              `yaml:"preserve_ids"`
	DryRun          bool              `yaml:"dry_run"`
	Headers         map[string]string `yaml:"headers"`
}

// CanaryConfig controls canary release settings.
type CanaryConfig struct {
	Enabled          bool              `yaml:"enabled"`
	CanaryVersion    string            `yaml:"canary_version"`
	StableUpstream   string            `yaml:"stable_upstream"`
	CanaryUpstream   string            `yaml:"canary_upstream"`
	Strategy         string            `yaml:"strategy"`
	Percentage       int               `yaml:"percentage"`
	HeaderName       string            `yaml:"header_name"`
	HeaderValue      string            `yaml:"header_value"`
	CookieName       string            `yaml:"cookie_name"`
	CookieValue      string            `yaml:"cookie_value"`
	Regions          []string          `yaml:"regions"`
	AutoRollback     bool              `yaml:"auto_rollback"`
	ErrorThreshold   float64           `yaml:"error_threshold"`
	LatencyThreshold time.Duration     `yaml:"latency_threshold"`
	HealthCheckPath  string            `yaml:"health_check_path"`
	Metadata         map[string]string `yaml:"metadata"`
}

// AnalyticsConfig controls analytics and metrics collection.
type AnalyticsConfig struct {
	Enabled          bool          `yaml:"enabled"`
	StoragePath      string        `yaml:"storage_path"`
	RetentionDays    int           `yaml:"retention_days"`
	FlushInterval    time.Duration `yaml:"flush_interval"`
	MaxDataPoints    int           `yaml:"max_data_points"`
	EnableTimeSeries bool          `yaml:"enable_time_series"`
}

// ClusterNodeConfig defines a peer node in the cluster.
type ClusterNodeConfig struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	Address string `yaml:"address"` // https://host:port
}

// ClusterSyncConfig controls data synchronization between clusters.
type ClusterSyncConfig struct {
	Enabled            bool                `yaml:"enabled"`
	NodeID             string              `yaml:"node_id"`
	NodeName           string              `yaml:"node_name"`
	Listen             string              `yaml:"listen"`      // Bind address for sync API
	Port               int                 `yaml:"port"`        // Default: 9444
	SharedSecret       string              `yaml:"shared_secret"`
	Clusters           []ClusterMembership `yaml:"clusters"`
	SyncInterval       time.Duration       `yaml:"sync_interval"`
	ConflictResolution string              `yaml:"conflict_resolution"` // "last_write_wins", "source_priority", "manual"
	MaxRetries         int                 `yaml:"max_retries"`
	RetryDelay         time.Duration       `yaml:"retry_delay"`
}

// ClusterConfig controls the cluster layer (distributed coordination).
type ClusterConfig struct {
	Enabled bool `yaml:"enabled"`
	// Config is the cluster package config (internal/cluster.Config).
	// Stored as any to avoid circular import; parsed from YAML as an interface{} node.
	Config any `yaml:"cluster_config"`
}

// DeepCopy returns a complete copy of the Config, isolating shared slices and maps.
// This replaces the json.Marshal/Unmarshal approach which causes GC pressure for large configs.
func (c *Config) DeepCopy() *Config {
	if c == nil {
		return nil
	}
	out := *c // shallow copy of scalar fields

	// Scalars copied by assignment above.
	// Structs need field-by-field copy:
	out.TLS = c.TLS.DeepCopy()
	out.WAF = c.WAF.DeepCopy()
	out.Dashboard = c.Dashboard.DeepCopy()
	out.MCP = c.MCP.DeepCopy()
	out.Docker = c.Docker.DeepCopy()
	out.Alerting = c.Alerting.DeepCopy()
	out.Logging = c.Logging.DeepCopy()
	out.Events = c.Events.DeepCopy()
	out.Tenant = c.Tenant.DeepCopy()

	// Slices need element-by-element deep copy:
	if c.Upstreams != nil {
		out.Upstreams = make([]UpstreamConfig, len(c.Upstreams))
		for i := range c.Upstreams {
			out.Upstreams[i] = c.Upstreams[i].DeepCopy()
		}
	}
	if c.Routes != nil {
		out.Routes = make([]RouteConfig, len(c.Routes))
		for i := range c.Routes {
			out.Routes[i] = c.Routes[i].DeepCopy()
		}
	}
	if c.VirtualHosts != nil {
		out.VirtualHosts = make([]VirtualHostConfig, len(c.VirtualHosts))
		for i := range c.VirtualHosts {
			out.VirtualHosts[i] = c.VirtualHosts[i].DeepCopy()
		}
	}
	if c.TrustedProxies != nil {
		out.TrustedProxies = make([]string, len(c.TrustedProxies))
		copy(out.TrustedProxies, c.TrustedProxies)
	}

	return &out
}

func (c *TLSConfig) DeepCopy() TLSConfig {
	out := *c
	out.ACME = c.ACME.DeepCopy()
	out.HTTP3 = c.HTTP3.DeepCopy()
	return out
}

func (c *ACMEConfig) DeepCopy() ACMEConfig {
	out := *c
	if c.Domains != nil {
		out.Domains = make([]string, len(c.Domains))
		copy(out.Domains, c.Domains)
	}
	return out
}

func (c *HTTP3Config) DeepCopy() HTTP3Config {
	return *c
}

func (c *UpstreamConfig) DeepCopy() UpstreamConfig {
	out := *c
	if c.Targets != nil {
		out.Targets = make([]TargetConfig, len(c.Targets))
		copy(out.Targets, c.Targets)
	}
	out.HealthCheck = c.HealthCheck.DeepCopy()
	return out
}

func (c *TargetConfig) DeepCopy() TargetConfig {
	return *c
}

func (c *HealthCheckConfig) DeepCopy() HealthCheckConfig {
	return *c
}

func (c *RouteConfig) DeepCopy() RouteConfig {
	out := *c
	if c.Methods != nil {
		out.Methods = make([]string, len(c.Methods))
		copy(out.Methods, c.Methods)
	}
	return out
}

func (c *VirtualHostConfig) DeepCopy() VirtualHostConfig {
	out := *c
	if c.Domains != nil {
		out.Domains = make([]string, len(c.Domains))
		copy(out.Domains, c.Domains)
	}
	if c.Routes != nil {
		out.Routes = make([]RouteConfig, len(c.Routes))
		for i := range c.Routes {
			out.Routes[i] = c.Routes[i].DeepCopy()
		}
	}
	if c.WAF != nil {
		waf := c.WAF.DeepCopy()
		out.WAF = &waf
	}
	return out
}

func (c *VHostTLSConfig) DeepCopy() VHostTLSConfig {
	return *c
}

func (c *DashboardConfig) DeepCopy() DashboardConfig {
	return *c
}

func (c *MCPConfig) DeepCopy() MCPConfig {
	return *c
}

func (c *LogConfig) DeepCopy() LogConfig {
	return *c
}

func (c *EventsConfig) DeepCopy() EventsConfig {
	return *c
}

func (c *AlertingConfig) DeepCopy() AlertingConfig {
	return *c
}

func (c *DockerConfig) DeepCopy() DockerConfig {
	return *c
}

func (c *TenantConfig) DeepCopy() TenantConfig {
	out := *c
	if c.Tenants != nil {
		out.Tenants = make([]TenantDefinition, len(c.Tenants))
		for i := range c.Tenants {
			out.Tenants[i] = c.Tenants[i].DeepCopy()
		}
	}
	out.DefaultQuota = c.DefaultQuota.DeepCopy()
	return out
}

func (c *TenantDefinition) DeepCopy() TenantDefinition {
	out := *c
	if c.Domains != nil {
		out.Domains = make([]string, len(c.Domains))
		copy(out.Domains, c.Domains)
	}
	out.Quota = c.Quota.DeepCopy()
	return out
}

func (c *ResourceQuotaConfig) DeepCopy() ResourceQuotaConfig {
	return *c
}

func (c *CustomRulesConfig) DeepCopy() CustomRulesConfig {
	out := *c
	if c.Rules != nil {
		out.Rules = make([]CustomRule, len(c.Rules))
		for i := range c.Rules {
			out.Rules[i] = c.Rules[i].DeepCopy()
		}
	}
	return out
}

func (c *CustomRule) DeepCopy() CustomRule {
	out := *c
	if c.Conditions != nil {
		out.Conditions = make([]RuleCondition, len(c.Conditions))
		copy(out.Conditions, c.Conditions)
	}
	return out
}

func (c *RuleCondition) DeepCopy() RuleCondition {
	out := *c
	// Value is any, shallow copy handles scalar strings
	return out
}

func (c *GeoIPConfig) DeepCopy() GeoIPConfig {
	return *c
}

func (c *SIEMConfig) DeepCopy() SIEMConfig {
	out := *c
	if c.Fields != nil {
		out.Fields = make(map[string]string, len(c.Fields))
		for k, v := range c.Fields {
			out.Fields[k] = v
		}
	}
	return out
}

func (c *RemediationConfig) DeepCopy() RemediationConfig {
	out := *c
	if c.ExcludedPaths != nil {
		out.ExcludedPaths = make([]string, len(c.ExcludedPaths))
		copy(out.ExcludedPaths, c.ExcludedPaths)
	}
	return out
}

func (c *WebSocketConfig) DeepCopy() WebSocketConfig {
	out := *c
	if c.AllowedOrigins != nil {
		out.AllowedOrigins = make([]string, len(c.AllowedOrigins))
		copy(out.AllowedOrigins, c.AllowedOrigins)
	}
	if c.BlockedExtensions != nil {
		out.BlockedExtensions = make([]string, len(c.BlockedExtensions))
		copy(out.BlockedExtensions, c.BlockedExtensions)
	}
	return out
}

func (c *ClusterMembership) DeepCopy() ClusterMembership {
	out := *c
	if c.Nodes != nil {
		out.Nodes = make([]ClusterNodeConfig, len(c.Nodes))
		copy(out.Nodes, c.Nodes)
	}
	return out
}

func (c *ClusterNodeConfig) DeepCopy() ClusterNodeConfig {
	return *c
}

func (c *ClusterSyncConfig) DeepCopy() ClusterSyncConfig {
	out := *c
	if c.Clusters != nil {
		out.Clusters = make([]ClusterMembership, len(c.Clusters))
		for i := range c.Clusters {
			out.Clusters[i] = c.Clusters[i].DeepCopy()
		}
	}
	return out
}

func (c *IPACLConfig) DeepCopy() IPACLConfig {
	out := *c
	if c.Whitelist != nil {
		out.Whitelist = make([]string, len(c.Whitelist))
		copy(out.Whitelist, c.Whitelist)
	}
	if c.Blacklist != nil {
		out.Blacklist = make([]string, len(c.Blacklist))
		copy(out.Blacklist, c.Blacklist)
	}
	out.AutoBan = c.AutoBan.DeepCopy()
	return out
}

func (c *AutoBanConfig) DeepCopy() AutoBanConfig {
	return *c
}

func (c *RateLimitConfig) DeepCopy() RateLimitConfig {
	out := *c
	if c.Rules != nil {
		out.Rules = make([]RateLimitRule, len(c.Rules))
		for i := range c.Rules {
			out.Rules[i] = c.Rules[i].DeepCopy()
		}
	}
	return out
}

func (c *RateLimitRule) DeepCopy() RateLimitRule {
	out := *c
	if c.Paths != nil {
		out.Paths = make([]string, len(c.Paths))
		copy(out.Paths, c.Paths)
	}
	return out
}

func (c *SanitizerConfig) DeepCopy() SanitizerConfig {
	out := *c
	if c.AllowedMethods != nil {
		out.AllowedMethods = make([]string, len(c.AllowedMethods))
		copy(out.AllowedMethods, c.AllowedMethods)
	}
	if c.PathOverrides != nil {
		out.PathOverrides = make([]PathOverride, len(c.PathOverrides))
		copy(out.PathOverrides, c.PathOverrides)
	}
	return out
}

func (c *PathOverride) DeepCopy() PathOverride {
	return *c
}

func (c *ThreatIntelConfig) DeepCopy() ThreatIntelConfig {
	out := *c
	if c.Feeds != nil {
		out.Feeds = make([]ThreatFeedConfig, len(c.Feeds))
		copy(out.Feeds, c.Feeds)
	}
	return out
}

func (c *ThreatFeedConfig) DeepCopy() ThreatFeedConfig {
	return *c
}

func (c *CORSConfig) DeepCopy() CORSConfig {
	out := *c
	if c.AllowOrigins != nil {
		out.AllowOrigins = make([]string, len(c.AllowOrigins))
		copy(out.AllowOrigins, c.AllowOrigins)
	}
	if c.AllowMethods != nil {
		out.AllowMethods = make([]string, len(c.AllowMethods))
		copy(out.AllowMethods, c.AllowMethods)
	}
	if c.AllowHeaders != nil {
		out.AllowHeaders = make([]string, len(c.AllowHeaders))
		copy(out.AllowHeaders, c.AllowHeaders)
	}
	if c.ExposeHeaders != nil {
		out.ExposeHeaders = make([]string, len(c.ExposeHeaders))
		copy(out.ExposeHeaders, c.ExposeHeaders)
	}
	return out
}

func (c *ATOProtectionConfig) DeepCopy() ATOProtectionConfig {
	out := *c
	if c.LoginPaths != nil {
		out.LoginPaths = make([]string, len(c.LoginPaths))
		copy(out.LoginPaths, c.LoginPaths)
	}
	out.BruteForce = c.BruteForce.DeepCopy()
	out.CredStuffing = c.CredStuffing.DeepCopy()
	out.PasswordSpray = c.PasswordSpray.DeepCopy()
	out.Travel = c.Travel.DeepCopy()
	return out
}

func (c *BruteForceConfig) DeepCopy() BruteForceConfig { return *c }
func (c *CredentialStuffingConfig) DeepCopy() CredentialStuffingConfig { return *c }
func (c *PasswordSprayConfig) DeepCopy() PasswordSprayConfig { return *c }
func (c *ImpossibleTravelConfig) DeepCopy() ImpossibleTravelConfig { return *c }

func (c *APISecurityConfig) DeepCopy() APISecurityConfig {
	out := *c
	if c.SkipPaths != nil {
		out.SkipPaths = make([]string, len(c.SkipPaths))
		copy(out.SkipPaths, c.SkipPaths)
	}
	out.JWT = c.JWT.DeepCopy()
	out.APIKeys = c.APIKeys.DeepCopy()
	return out
}

func (c *JWTConfig) DeepCopy() JWTConfig {
	out := *c
	if c.Algorithms != nil {
		out.Algorithms = make([]string, len(c.Algorithms))
		copy(out.Algorithms, c.Algorithms)
	}
	return out
}

func (c *APIKeysConfig) DeepCopy() APIKeysConfig {
	out := *c
	if c.Keys != nil {
		out.Keys = make([]APIKeyConfig, len(c.Keys))
		copy(out.Keys, c.Keys)
	}
	return out
}

func (c *APIKeyConfig) DeepCopy() APIKeyConfig { return *c }

func (c *APIValidationConfig) DeepCopy() APIValidationConfig {
	out := *c
	if c.Schemas != nil {
		out.Schemas = make([]SchemaSourceConfig, len(c.Schemas))
		copy(out.Schemas, c.Schemas)
	}
	return out
}

func (c *SchemaSourceConfig) DeepCopy() SchemaSourceConfig { return *c }

func (c *DetectionConfig) DeepCopy() DetectionConfig {
	out := *c
	if c.Detectors != nil {
		out.Detectors = make(map[string]DetectorConfig, len(c.Detectors))
		for k, v := range c.Detectors {
			out.Detectors[k] = v
		}
	}
	if c.Exclusions != nil {
		out.Exclusions = make([]ExclusionConfig, len(c.Exclusions))
		copy(out.Exclusions, c.Exclusions)
	}
	return out
}

func (c *ExclusionConfig) DeepCopy() ExclusionConfig {
	out := *c
	if c.Detectors != nil {
		out.Detectors = make([]string, len(c.Detectors))
		copy(out.Detectors, c.Detectors)
	}
	return out
}

func (c *BotDetectionConfig) DeepCopy() BotDetectionConfig {
	out := *c
	out.TLSFingerprint = c.TLSFingerprint.DeepCopy()
	out.UserAgent = c.UserAgent.DeepCopy()
	out.Behavior = c.Behavior.DeepCopy()
	out.Enhanced = c.Enhanced.DeepCopy()
	return out
}

func (c *TLSFingerprintConfig) DeepCopy() TLSFingerprintConfig { return *c }
func (c *UAConfig) DeepCopy() UAConfig { return *c }
func (c *BehaviorConfig) DeepCopy() BehaviorConfig { return *c }

func (c *EnhancedBotDetectionConfig) DeepCopy() EnhancedBotDetectionConfig {
	out := *c
	out.Biometric = c.Biometric.DeepCopy()
	out.BrowserFingerprint = c.BrowserFingerprint.DeepCopy()
	out.Captcha = c.Captcha.DeepCopy()
	return out
}

func (c *BiometricDetectionConfig) DeepCopy() BiometricDetectionConfig { return *c }
func (c *BrowserFingerprintConfig) DeepCopy() BrowserFingerprintConfig { return *c }
func (c *CaptchaChallengeConfig) DeepCopy() CaptchaChallengeConfig { return *c }

func (c *ChallengeConfig) DeepCopy() ChallengeConfig { return *c }

func (c *ResponseConfig) DeepCopy() ResponseConfig {
	out := *c
	out.SecurityHeaders = c.SecurityHeaders.DeepCopy()
	out.DataMasking = c.DataMasking.DeepCopy()
	out.ErrorPages = c.ErrorPages.DeepCopy()
	return out
}

func (c *SecurityHeadersConfig) DeepCopy() SecurityHeadersConfig {
	out := *c
	out.HSTS = c.HSTS.DeepCopy()
	return out
}

func (c *HSTSConfig) DeepCopy() HSTSConfig { return *c }
func (c *DataMaskingConfig) DeepCopy() DataMaskingConfig { return *c }
func (c *ErrorPagesConfig) DeepCopy() ErrorPagesConfig { return *c }

func (c *ClientSideConfig) DeepCopy() ClientSideConfig {
	out := *c
	if c.Exclusions != nil {
		out.Exclusions = make([]string, len(c.Exclusions))
		copy(out.Exclusions, c.Exclusions)
	}
	out.MagecartDetection = c.MagecartDetection.DeepCopy()
	out.AgentInjection = c.AgentInjection.DeepCopy()
	out.CSP = c.CSP.DeepCopy()
	return out
}

func (c *MagecartDetectionConfig) DeepCopy() MagecartDetectionConfig {
	out := *c
	if c.KnownSkimmingDomains != nil {
		out.KnownSkimmingDomains = make([]string, len(c.KnownSkimmingDomains))
		copy(out.KnownSkimmingDomains, c.KnownSkimmingDomains)
	}
	return out
}

func (c *AgentInjectionConfig) DeepCopy() AgentInjectionConfig {
	out := *c
	if c.ProtectedPaths != nil {
		out.ProtectedPaths = make([]string, len(c.ProtectedPaths))
		copy(out.ProtectedPaths, c.ProtectedPaths)
	}
	return out
}

func (c *CSPHeaderConfig) DeepCopy() CSPHeaderConfig {
	out := *c
	copyStringSlice := func(src []string) []string {
		if src == nil {
			return nil
		}
		dst := make([]string, len(src))
		copy(dst, src)
		return dst
	}
	out.DefaultSrc = copyStringSlice(c.DefaultSrc)
	out.ScriptSrc = copyStringSlice(c.ScriptSrc)
	out.StyleSrc = copyStringSlice(c.StyleSrc)
	out.ImgSrc = copyStringSlice(c.ImgSrc)
	out.ConnectSrc = copyStringSlice(c.ConnectSrc)
	out.FontSrc = copyStringSlice(c.FontSrc)
	out.ObjectSrc = copyStringSlice(c.ObjectSrc)
	out.MediaSrc = copyStringSlice(c.MediaSrc)
	out.FrameSrc = copyStringSlice(c.FrameSrc)
	out.FrameAncestors = copyStringSlice(c.FrameAncestors)
	out.FormAction = copyStringSlice(c.FormAction)
	return out
}

func (c *DLPConfig) DeepCopy() DLPConfig {
	out := *c
	if c.Patterns != nil {
		out.Patterns = make([]string, len(c.Patterns))
		copy(out.Patterns, c.Patterns)
	}
	return out
}

func (c *ZeroTrustConfig) DeepCopy() ZeroTrustConfig {
	out := *c
	if c.AllowBypassPaths != nil {
		out.AllowBypassPaths = make([]string, len(c.AllowBypassPaths))
		copy(out.AllowBypassPaths, c.AllowBypassPaths)
	}
	return out
}

func (c *CacheConfig) DeepCopy() CacheConfig {
	out := *c
	if c.CacheMethods != nil {
		out.CacheMethods = make([]string, len(c.CacheMethods))
		copy(out.CacheMethods, c.CacheMethods)
	}
	if c.SkipPaths != nil {
		out.SkipPaths = make([]string, len(c.SkipPaths))
		copy(out.SkipPaths, c.SkipPaths)
	}
	return out
}

func (c *ReplayConfig) DeepCopy() ReplayConfig {
	out := *c
	if c.CaptureHeaders != nil {
		out.CaptureHeaders = make([]string, len(c.CaptureHeaders))
		copy(out.CaptureHeaders, c.CaptureHeaders)
	}
	if c.SkipPaths != nil {
		out.SkipPaths = make([]string, len(c.SkipPaths))
		copy(out.SkipPaths, c.SkipPaths)
	}
	if c.SkipMethods != nil {
		out.SkipMethods = make([]string, len(c.SkipMethods))
		copy(out.SkipMethods, c.SkipMethods)
	}
	out.Replay = c.Replay.DeepCopy()
	return out
}

func (c *ReplayEngineConfig) DeepCopy() ReplayEngineConfig {
	out := *c
	if c.Headers != nil {
		out.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			out.Headers[k] = v
		}
	}
	return out
}

func (c *CanaryConfig) DeepCopy() CanaryConfig {
	out := *c
	if c.Regions != nil {
		out.Regions = make([]string, len(c.Regions))
		copy(out.Regions, c.Regions)
	}
	if c.Metadata != nil {
		out.Metadata = make(map[string]string, len(c.Metadata))
		for k, v := range c.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}

func (c *AnalyticsConfig) DeepCopy() AnalyticsConfig { return *c }

func (c *AIAnalysisConfig) DeepCopy() AIAnalysisConfig { return *c }

func (c *MLAnomalyConfig) DeepCopy() MLAnomalyConfig { return *c }

func (c *APIDiscoveryConfig) DeepCopy() APIDiscoveryConfig { return *c }

func (c *GraphQLConfig) DeepCopy() GraphQLConfig {
	out := *c
	if c.AllowEndpoints != nil {
		out.AllowEndpoints = make([]string, len(c.AllowEndpoints))
		copy(out.AllowEndpoints, c.AllowEndpoints)
	}
	return out
}

func (c *GRPCConfig) DeepCopy() GRPCConfig {
	out := *c
	if c.ProtoPaths != nil {
		out.ProtoPaths = make([]string, len(c.ProtoPaths))
		copy(out.ProtoPaths, c.ProtoPaths)
	}
	if c.AllowedServices != nil {
		out.AllowedServices = make([]string, len(c.AllowedServices))
		copy(out.AllowedServices, c.AllowedServices)
	}
	if c.BlockedServices != nil {
		out.BlockedServices = make([]string, len(c.BlockedServices))
		copy(out.BlockedServices, c.BlockedServices)
	}
	if c.AllowedMethods != nil {
		out.AllowedMethods = make([]string, len(c.AllowedMethods))
		copy(out.AllowedMethods, c.AllowedMethods)
	}
	if c.BlockedMethods != nil {
		out.BlockedMethods = make([]string, len(c.BlockedMethods))
		copy(out.BlockedMethods, c.BlockedMethods)
	}
	if c.MethodRateLimits != nil {
		out.MethodRateLimits = make([]GRPCRateLimit, len(c.MethodRateLimits))
		copy(out.MethodRateLimits, c.MethodRateLimits)
	}
	return out
}

func (c *GRPCRateLimit) DeepCopy() GRPCRateLimit { return *c }

func (c *VirtualPatchConfig) DeepCopy() VirtualPatchConfig {
	out := *c
	if c.BlockSeverity != nil {
		out.BlockSeverity = make([]string, len(c.BlockSeverity))
		copy(out.BlockSeverity, c.BlockSeverity)
	}
	return out
}

func (c *CRSConfig) DeepCopy() CRSConfig {
	out := *c
	if c.Exclusions != nil {
		out.Exclusions = make([]string, len(c.Exclusions))
		copy(out.Exclusions, c.Exclusions)
	}
	if c.DisabledRules != nil {
		out.DisabledRules = make([]string, len(c.DisabledRules))
		copy(out.DisabledRules, c.DisabledRules)
	}
	return out
}

func (c *WAFConfig) DeepCopy() WAFConfig {
	out := *c
	out.IPACL = c.IPACL.DeepCopy()
	out.CustomRules = c.CustomRules.DeepCopy()
	out.GeoIP = c.GeoIP.DeepCopy()
	out.ThreatIntel = c.ThreatIntel.DeepCopy()
	out.CORS = c.CORS.DeepCopy()
	out.RateLimit = c.RateLimit.DeepCopy()
	out.ATOProtection = c.ATOProtection.DeepCopy()
	out.APISecurity = c.APISecurity.DeepCopy()
	out.APIValidation = c.APIValidation.DeepCopy()
	out.Sanitizer = c.Sanitizer.DeepCopy()
	out.Detection = c.Detection.DeepCopy()
	out.BotDetection = c.BotDetection.DeepCopy()
	out.Challenge = c.Challenge.DeepCopy()
	out.Response = c.Response.DeepCopy()
	out.ClientSide = c.ClientSide.DeepCopy()
	out.AIAnalysis = c.AIAnalysis.DeepCopy()
	out.MLAnomaly = c.MLAnomaly.DeepCopy()
	out.APIDiscovery = c.APIDiscovery.DeepCopy()
	out.GraphQL = c.GraphQL.DeepCopy()
	out.GRPC = c.GRPC.DeepCopy()
	out.Tenant = c.Tenant.DeepCopy()
	out.DLP = c.DLP.DeepCopy()
	out.ZeroTrust = c.ZeroTrust.DeepCopy()
	out.SIEM = c.SIEM.DeepCopy()
	out.Cache = c.Cache.DeepCopy()
	out.Replay = c.Replay.DeepCopy()
	out.Canary = c.Canary.DeepCopy()
	out.Analytics = c.Analytics.DeepCopy()
	out.ClusterSync = c.ClusterSync.DeepCopy()
	out.Remediation = c.Remediation.DeepCopy()
	out.WebSocket = c.WebSocket.DeepCopy()
	out.CRS = c.CRS.DeepCopy()
	out.VirtualPatch = c.VirtualPatch.DeepCopy()
	return out
}

type ClusterMembership struct {
	ID            string            `yaml:"id"`
	Name          string            `yaml:"name"`
	Nodes         []ClusterNodeConfig `yaml:"nodes"`
	SyncScope     string            `yaml:"sync_scope"`     // "tenants", "rules", "config", "all"
	Bidirectional bool              `yaml:"bidirectional"`
}

// RemediationConfig controls AI auto-remediation settings.
type RemediationConfig struct {
	Enabled             bool          `yaml:"enabled"`
	AutoApply           bool          `yaml:"auto_apply"`
	ConfidenceThreshold int           `yaml:"confidence_threshold"`
	MaxRulesPerDay      int           `yaml:"max_rules_per_day"`
	RuleTTL             time.Duration `yaml:"rule_ttl"`
	ExcludedPaths       []string      `yaml:"excluded_paths"`
	StoragePath         string        `yaml:"storage_path"`
}

// WebSocketConfig controls WebSocket security settings.
type WebSocketConfig struct {
	Enabled             bool          `yaml:"enabled"`
	MaxMessageSize      int64         `yaml:"max_message_size"`
	MaxFrameSize        int64         `yaml:"max_frame_size"`
	RateLimitPerSecond  int           `yaml:"rate_limit_per_second"`
	RateLimitBurst      int           `yaml:"rate_limit_burst"`
	AllowedOrigins      []string      `yaml:"allowed_origins"`
	BlockedExtensions   []string      `yaml:"blocked_extensions"`
	BlockEmptyMessages  bool          `yaml:"block_empty_messages"`
	BlockBinaryMessages bool          `yaml:"block_binary_messages"`
	MaxConcurrentPerIP  int           `yaml:"max_concurrent_per_ip"`
	HandshakeTimeout    time.Duration `yaml:"handshake_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
	ScanPayloads        bool          `yaml:"scan_payloads"`
}

// SIEMConfig controls SIEM integration settings.
type SIEMConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Endpoint      string            `yaml:"endpoint"`
	Format        string            `yaml:"format"` // cef, leef, json, splunk, elastic
	APIKey        string            `yaml:"api_key"`
	Index         string            `yaml:"index"`
	BatchSize     int               `yaml:"batch_size"`
	FlushInterval time.Duration     `yaml:"flush_interval"`
	Timeout       time.Duration     `yaml:"timeout"`
	SkipVerify    bool              `yaml:"skip_verify"`
	Fields        map[string]string `yaml:"fields"`
}

type IPACLConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Whitelist []string      `yaml:"whitelist"`
	Blacklist []string      `yaml:"blacklist"`
	AutoBan   AutoBanConfig `yaml:"auto_ban"`
}

// AutoBanConfig controls automatic IP banning behavior.
type AutoBanConfig struct {
	Enabled           bool          `yaml:"enabled"`
	DefaultTTL        time.Duration `yaml:"default_ttl"`
	MaxTTL            time.Duration `yaml:"max_ttl"`
	MaxAutoBanEntries int           `yaml:"max_auto_ban_entries"` // 0 = unlimited
}

// RateLimitConfig holds the global rate-limiting toggle and individual rules.
type RateLimitConfig struct {
	Enabled bool            `yaml:"enabled"`
	Rules   []RateLimitRule `yaml:"rules"`
}

// RateLimitRule defines a single rate-limiting rule.
type RateLimitRule struct {
	ID           string        `yaml:"id"`
	Scope        string        `yaml:"scope"` // "ip", "ip+path"
	Paths        []string      `yaml:"paths"`
	Limit        int           `yaml:"limit"`
	Window       time.Duration `yaml:"window"`
	Burst        int           `yaml:"burst"`
	Action       string        `yaml:"action"` // "block", "log"
	AutoBanAfter int           `yaml:"auto_ban_after"`
}

// SanitizerConfig controls request sanitisation limits and behavior.
type SanitizerConfig struct {
	Enabled           bool           `yaml:"enabled"`
	MaxURLLength      int            `yaml:"max_url_length"`
	MaxHeaderSize     int            `yaml:"max_header_size"`
	MaxHeaderCount    int            `yaml:"max_header_count"`
	MaxBodySize       int64          `yaml:"max_body_size"`
	MaxCookieSize     int            `yaml:"max_cookie_size"`
	BlockNullBytes    bool           `yaml:"block_null_bytes"`
	NormalizeEncoding bool           `yaml:"normalize_encoding"`
	StripHopByHop     bool           `yaml:"strip_hop_by_hop"`
	AllowedMethods    []string       `yaml:"allowed_methods"`
	PathOverrides     []PathOverride `yaml:"path_overrides"`
}

// PathOverride allows per-path customisation of sanitiser limits.
type PathOverride struct {
	Path        string `yaml:"path"`
	MaxBodySize int64  `yaml:"max_body_size"`
}

// DetectionConfig controls the tokenizer-based attack detection engine.
type DetectionConfig struct {
	Enabled    bool                      `yaml:"enabled"`
	Threshold  ThresholdConfig           `yaml:"threshold"`
	Detectors  map[string]DetectorConfig `yaml:"detectors"` // keyed by: sqli, xss, lfi, cmdi, xxe, ssrf
	Exclusions []ExclusionConfig         `yaml:"exclusions"`
}

// ThresholdConfig defines scoring thresholds that trigger blocking or logging.
type ThresholdConfig struct {
	Block int `yaml:"block"`
	Log   int `yaml:"log"`
}

// DetectorConfig toggles an individual detector and sets its score multiplier.
type DetectorConfig struct {
	Enabled    bool    `yaml:"enabled"`
	Multiplier float64 `yaml:"multiplier"`
}

// ExclusionConfig allows specific paths to bypass certain detectors.
type ExclusionConfig struct {
	Path      string   `yaml:"path"`
	Detectors []string `yaml:"detectors"`
	Reason    string   `yaml:"reason"`
}

// BotDetectionConfig controls automated-client detection.
type BotDetectionConfig struct {
	Enabled        bool                      `yaml:"enabled"`
	Mode           string                    `yaml:"mode"`
	TLSFingerprint TLSFingerprintConfig      `yaml:"tls_fingerprint"`
	UserAgent      UAConfig                  `yaml:"user_agent"`
	Behavior       BehaviorConfig            `yaml:"behavior"`
	Enhanced       EnhancedBotDetectionConfig `yaml:"enhanced"`
}

// EnhancedBotDetectionConfig controls advanced bot detection with ML-based behavioral analysis.
type EnhancedBotDetectionConfig struct {
	Enabled            bool                         `yaml:"enabled"`
	Mode               string                       `yaml:"mode"` // "monitor" or "enforce"
	Biometric          BiometricDetectionConfig     `yaml:"biometric"`
	BrowserFingerprint BrowserFingerprintConfig     `yaml:"browser_fingerprint"`
	Captcha            CaptchaChallengeConfig       `yaml:"captcha"`
}

// BiometricDetectionConfig controls mouse/keyboard behavioral biometrics.
type BiometricDetectionConfig struct {
	Enabled        bool          `yaml:"enabled"`
	MinEvents      int           `yaml:"min_events"`
	ScoreThreshold float64       `yaml:"score_threshold"`
	TimeWindow     time.Duration `yaml:"time_window"`
}

// BrowserFingerprintConfig controls browser fingerprinting for bot detection.
type BrowserFingerprintConfig struct {
	Enabled       bool `yaml:"enabled"`
	CheckCanvas   bool `yaml:"check_canvas"`
	CheckWebGL    bool `yaml:"check_webgl"`
	CheckFonts    bool `yaml:"check_fonts"`
	CheckHeadless bool `yaml:"check_headless"`
}

// CaptchaChallengeConfig controls CAPTCHA challenge integration.
type CaptchaChallengeConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Provider  string        `yaml:"provider"` // "hcaptcha" or "turnstile"
	SiteKey   string        `yaml:"site_key"`
	SecretKey string        `yaml:"secret_key"`
	Timeout   time.Duration `yaml:"timeout"`
}

// TLSFingerprintConfig controls JA3/JA4 TLS fingerprint analysis.
type TLSFingerprintConfig struct {
	Enabled         bool   `yaml:"enabled"`
	KnownBotsAction string `yaml:"known_bots_action"`
	UnknownAction   string `yaml:"unknown_action"`
	MismatchAction  string `yaml:"mismatch_action"`
}

// UAConfig controls User-Agent header analysis.
type UAConfig struct {
	Enabled            bool `yaml:"enabled"`
	BlockEmpty         bool `yaml:"block_empty"`
	BlockKnownScanners bool `yaml:"block_known_scanners"`
}

// BehaviorConfig controls behavioral analysis for bot detection.
type BehaviorConfig struct {
	Enabled            bool          `yaml:"enabled"`
	Window             time.Duration `yaml:"window"`
	RPSThreshold       int           `yaml:"rps_threshold"`
	ErrorRateThreshold int           `yaml:"error_rate_threshold"`
}

// ChallengeConfig controls JavaScript proof-of-work challenges for bot mitigation.
type ChallengeConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Difficulty int           `yaml:"difficulty"`  // leading zero bits required (default: 20)
	CookieTTL  time.Duration `yaml:"cookie_ttl"`  // challenge cookie lifetime
	CookieName string        `yaml:"cookie_name"` // challenge cookie name
	SecretKey  string        `yaml:"secret_key"`  // HMAC signing key (hex-encoded, auto-generated if empty)
}

// ResponseConfig groups all response-side protections.
type ResponseConfig struct {
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
	DataMasking     DataMaskingConfig     `yaml:"data_masking"`
	ErrorPages      ErrorPagesConfig      `yaml:"error_pages"`
}

// ClientSideConfig controls client-side protection settings.
type ClientSideConfig struct {
	Enabled           bool                     `yaml:"enabled"`
	Mode              string                   `yaml:"mode"` // "monitor", "block", "inject"
	MagecartDetection MagecartDetectionConfig  `yaml:"magecart_detection"`
	AgentInjection    AgentInjectionConfig     `yaml:"agent_injection"`
	CSP               CSPHeaderConfig          `yaml:"csp"`
	Exclusions        []string                 `yaml:"exclusions"`
}

// MagecartDetectionConfig controls Magecart/skimming detection.
type MagecartDetectionConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	DetectObfuscatedJS      bool     `yaml:"detect_obfuscated_js"`
	DetectSuspiciousDomains bool     `yaml:"detect_suspicious_domains"`
	DetectFormExfiltration  bool     `yaml:"detect_form_exfiltration"`
	DetectKeyloggers        bool     `yaml:"detect_keyloggers"`
	KnownSkimmingDomains    []string `yaml:"known_skimming_domains"`
	BlockScore              int      `yaml:"block_score"`
	AlertScore              int      `yaml:"alert_score"`
}

// AgentInjectionConfig controls security agent injection.
type AgentInjectionConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ScriptURL       string   `yaml:"script_url"`
	InjectInHTML    bool     `yaml:"inject_in_html"`
	InjectPosition  string   `yaml:"inject_position"` // "head", "body-start", "body-end"
	MonitorDOM      bool     `yaml:"monitor_dom"`
	MonitorNetwork  bool     `yaml:"monitor_network"`
	MonitorForms    bool     `yaml:"monitor_forms"`
	ProtectedPaths  []string `yaml:"protected_paths"`
}

// CSPHeaderConfig controls Content Security Policy headers.
type CSPHeaderConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ReportOnly      bool     `yaml:"report_only"`
	DefaultSrc      []string `yaml:"default_src"`
	ScriptSrc       []string `yaml:"script_src"`
	StyleSrc        []string `yaml:"style_src"`
	ImgSrc          []string `yaml:"img_src"`
	ConnectSrc      []string `yaml:"connect_src"`
	FontSrc         []string `yaml:"font_src"`
	ObjectSrc       []string `yaml:"object_src"`
	MediaSrc        []string `yaml:"media_src"`
	FrameSrc        []string `yaml:"frame_src"`
	FrameAncestors  []string `yaml:"frame_ancestors"`
	FormAction      []string `yaml:"form_action"`
	BaseURI         []string `yaml:"base_uri"`
	ReportURI       string   `yaml:"report_uri"`
	UpgradeInsecure bool     `yaml:"upgrade_insecure_requests"`
}

// SecurityHeadersConfig controls injection of protective HTTP headers.
type SecurityHeadersConfig struct {
	Enabled             bool       `yaml:"enabled"`
	HSTS                HSTSConfig `yaml:"hsts"`
	XContentTypeOptions bool       `yaml:"x_content_type_options"`
	XFrameOptions       string     `yaml:"x_frame_options"`
	ReferrerPolicy      string     `yaml:"referrer_policy"`
	PermissionsPolicy   string     `yaml:"permissions_policy"`
}

// HSTSConfig controls HTTP Strict Transport Security header emission.
type HSTSConfig struct {
	Enabled           bool `yaml:"enabled"`
	MaxAge            int  `yaml:"max_age"`
	IncludeSubDomains bool `yaml:"include_subdomains"`
}

// DataMaskingConfig controls masking of sensitive data in responses.
type DataMaskingConfig struct {
	Enabled          bool `yaml:"enabled"`
	MaskCreditCards  bool `yaml:"mask_credit_cards"`
	MaskSSN          bool `yaml:"mask_ssn"`
	MaskAPIKeys      bool `yaml:"mask_api_keys"`
	StripStackTraces bool `yaml:"strip_stack_traces"`
}

// ErrorPagesConfig controls custom error page behavior.
type ErrorPagesConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // "production", "development"
}

// MLAnomalyConfig controls ML-based real-time anomaly detection.
type MLAnomalyConfig struct {
	Enabled         bool          `yaml:"enabled"`
	Mode            string        `yaml:"mode"` // "monitor" or "enforce"
	Threshold       float64       `yaml:"threshold"`
	WindowSize      int           `yaml:"window_size"`
	MinSamples      int           `yaml:"min_samples"`
	FeatureBuckets  int           `yaml:"feature_buckets"`
	AutoBlock       bool          `yaml:"auto_block"`
	BlockThreshold  float64       `yaml:"block_threshold"`
}

// APIDiscoveryConfig controls automatic API endpoint discovery and OpenAPI generation.
type APIDiscoveryConfig struct {
	Enabled          bool          `yaml:"enabled"`
	CaptureMode      string        `yaml:"capture_mode"` // "passive", "active"
	RingBufferSize   int           `yaml:"ring_buffer_size"`
	MinSamples       int           `yaml:"min_samples"`
	ClusterThreshold float64       `yaml:"cluster_threshold"`
	ExportPath       string        `yaml:"export_path"`
	ExportFormat     string        `yaml:"export_format"` // "openapi" or "json"
	AutoExport       bool          `yaml:"auto_export"`
	ExportInterval   time.Duration `yaml:"export_interval"`
}

// GraphQLConfig controls GraphQL security layer settings.
type GraphQLConfig struct {
	Enabled            bool     `yaml:"enabled"`
	MaxDepth           int      `yaml:"max_depth"`
	MaxComplexity      int      `yaml:"max_complexity"`
	BlockIntrospection bool     `yaml:"block_introspection"`
	AllowEndpoints     []string `yaml:"allow_endpoints"`
}

// GRPCConfig controls gRPC/gRPC-Web proxy settings.
type GRPCConfig struct {
	Enabled              bool            `yaml:"enabled"`
	GRPCWebEnabled       bool            `yaml:"grpc_web_enabled"`       // gRPC-Web bridge support
	ProtoPaths           []string        `yaml:"proto_paths"`            // Paths to .proto files
	AllowedServices      []string        `yaml:"allowed_services"`       // Empty = allow all
	BlockedServices      []string        `yaml:"blocked_services"`       // Block specific services
	AllowedMethods       []string        `yaml:"allowed_methods"`        // Format: "service/method"
	BlockedMethods       []string        `yaml:"blocked_methods"`        // Format: "service/method"
	ValidateProto        bool            `yaml:"validate_proto"`         // Validate protobuf messages
	ReflectionEnabled    bool            `yaml:"reflection_enabled"`     // Enable gRPC reflection
	MaxMessageSize       int             `yaml:"max_message_size"`       // Max request/response size
	MaxStreamDuration    time.Duration   `yaml:"max_stream_duration"`    // Max streaming duration
	MaxConcurrentStreams int             `yaml:"max_concurrent_streams"` // Max concurrent streams per connection
	MethodRateLimits     []GRPCRateLimit `yaml:"method_rate_limits"`     // Per-method rate limits
	RequireTLS           bool            `yaml:"require_tls"`            // Require TLS for gRPC
}

// GRPCRateLimit defines rate limiting for a specific gRPC method.
type GRPCRateLimit struct {
	Method            string `yaml:"method"` // Full method name: "package.service/method"
	RequestsPerSecond int    `yaml:"requests_per_second"`
	BurstSize         int    `yaml:"burst_size"`
}

// TenantConfig controls multi-tenancy settings.
type TenantConfig struct {
	Enabled      bool              `yaml:"enabled"`
	MaxTenants   int               `yaml:"max_tenants"`
	HeaderName   string            `yaml:"header_name"`
	DefaultQuota ResourceQuotaConfig `yaml:"default_quota"`
        StorePath    string              `yaml:"store_path"`
	Tenants      []TenantDefinition `yaml:"tenants"`
}

// ResourceQuotaConfig defines resource limits for tenants.
type ResourceQuotaConfig struct {
	MaxRequestsPerMinute int64 `yaml:"max_requests_per_minute"`
	MaxRequestsPerHour   int64 `yaml:"max_requests_per_hour"`
	MaxBandwidthMbps     int   `yaml:"max_bandwidth_mbps"`
	MaxRules             int   `yaml:"max_rules"`
	MaxRateLimitRules    int   `yaml:"max_rate_limit_rules"`
	MaxIPACLs            int   `yaml:"max_ip_acls"`
}

// TenantDefinition defines a static tenant configuration.
type TenantDefinition struct {
	ID          string              `yaml:"id"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Domains     []string            `yaml:"domains"`
	APIKey      string              `yaml:"api_key"`
	Active      bool                `yaml:"active"`
	Quota       ResourceQuotaConfig `yaml:"quota"`
}

// DashboardConfig controls the built-in web dashboard.
type DashboardConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	APIKey   string `yaml:"api_key"`
	AdminKey string `yaml:"admin_key"` // System admin key for cross-tenant management
	TLS      bool   `yaml:"tls"`
}

// MCPConfig controls the Model Context Protocol server.
type MCPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Transport string `yaml:"transport"`
}

// LogConfig controls logging output.
type LogConfig struct {
	Level      string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format     string `yaml:"format"` // "json", "text"
	Output     string `yaml:"output"` // "stdout", "stderr", or file path
	LogAllowed bool   `yaml:"log_allowed"`
	LogBlocked bool   `yaml:"log_blocked"`
	LogBody    bool   `yaml:"log_body"`
	MaxSizeMB  int    `yaml:"max_size_mb"`  // Max log file size before rotation (default: 100)
	MaxBackups int    `yaml:"max_backups"`  // Max rotated files to keep (default: 5)
	MaxAgeDays int    `yaml:"max_age_days"` // Max days to keep rotated files (default: 30)
}

// EventsConfig controls security event storage.
type EventsConfig struct {
	Storage   string `yaml:"storage"` // "memory", "file"
	MaxEvents int    `yaml:"max_events"`
	FilePath  string `yaml:"file_path"`
}

// ThreatIntelConfig controls threat intelligence feed checking.
type ThreatIntelConfig struct {
	Enabled      bool                   `yaml:"enabled"`
	IPReputation IPReputationConfig     `yaml:"ip_reputation"`
	DomainRep    DomainReputationConfig `yaml:"domain_reputation"`
	CacheSize    int                    `yaml:"cache_size"`
	CacheTTL     time.Duration          `yaml:"cache_ttl"`
	Feeds        []ThreatFeedConfig     `yaml:"feeds"`
}

// IPReputationConfig controls IP reputation checking.
type IPReputationConfig struct {
	Enabled        bool `yaml:"enabled"`
	BlockMalicious bool `yaml:"block_malicious"`
	ScoreThreshold int  `yaml:"score_threshold"`
}

// DomainReputationConfig controls domain reputation checking.
type DomainReputationConfig struct {
	Enabled        bool `yaml:"enabled"`
	BlockMalicious bool `yaml:"block_malicious"`
	CheckRedirects bool `yaml:"check_redirects"`
}

// ThreatFeedConfig configures a threat intelligence feed source.
type ThreatFeedConfig struct {
	Type    string        `yaml:"type"`    // "file" or "url"
	Path    string        `yaml:"path"`    // File path for type="file"
	URL     string        `yaml:"url"`     // URL for type="url"
	Refresh time.Duration `yaml:"refresh"` // Refresh interval
	Format  string        `yaml:"format"`  // "json", "jsonl", "csv"
}

// CORSConfig controls Cross-Origin Resource Sharing validation.
type CORSConfig struct {
	Enabled               bool     `yaml:"enabled"`
	AllowOrigins          []string `yaml:"allow_origins"`
	AllowMethods          []string `yaml:"allow_methods"`
	AllowHeaders          []string `yaml:"allow_headers"`
	ExposeHeaders         []string `yaml:"expose_headers"`
	AllowCredentials      bool     `yaml:"allow_credentials"`
	MaxAgeSeconds         int      `yaml:"max_age_seconds"`
	StrictMode            bool     `yaml:"strict_mode"`
	PreflightCacheSeconds int      `yaml:"preflight_cache_seconds"`
}

// ATOProtectionConfig controls Account Takeover Protection.
type ATOProtectionConfig struct {
	Enabled       bool                     `yaml:"enabled"`
	LoginPaths    []string                 `yaml:"login_paths"`
	BruteForce    BruteForceConfig         `yaml:"brute_force"`
	CredStuffing  CredentialStuffingConfig `yaml:"credential_stuffing"`
	PasswordSpray PasswordSprayConfig      `yaml:"password_spray"`
	Travel        ImpossibleTravelConfig   `yaml:"impossible_travel"`
	GeoDBPath     string                   `yaml:"geodb_path"`
}

// BruteForceConfig controls brute force detection.
type BruteForceConfig struct {
	Enabled             bool          `yaml:"enabled"`
	Window              time.Duration `yaml:"window"`
	MaxAttemptsPerIP    int           `yaml:"max_attempts_per_ip"`
	MaxAttemptsPerEmail int           `yaml:"max_attempts_per_email"`
	BlockDuration       time.Duration `yaml:"block_duration"`
}

// CredentialStuffingConfig controls credential stuffing detection.
type CredentialStuffingConfig struct {
	Enabled              bool          `yaml:"enabled"`
	DistributedThreshold int           `yaml:"distributed_threshold"`
	Window               time.Duration `yaml:"window"`
	BlockDuration        time.Duration `yaml:"block_duration"`
}

// PasswordSprayConfig controls password spray detection.
type PasswordSprayConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Threshold     int           `yaml:"threshold"`
	Window        time.Duration `yaml:"window"`
	BlockDuration time.Duration `yaml:"block_duration"`
}

// ImpossibleTravelConfig controls impossible travel detection.
type ImpossibleTravelConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxDistanceKm float64       `yaml:"max_distance_km"`
	MaxTimeHours  float64       `yaml:"max_time_hours"`
	BlockDuration time.Duration `yaml:"block_duration"`
}

// APISecurityConfig controls API authentication and authorization.
type APISecurityConfig struct {
	Enabled    bool          `yaml:"enabled"`
	JWT        JWTConfig     `yaml:"jwt"`
	APIKeys    APIKeysConfig `yaml:"api_keys"`
	SkipPaths  []string      `yaml:"skip_paths"`
	HeaderName string        `yaml:"header_name"`
	QueryParam string        `yaml:"query_param"`
}

// JWTConfig controls JWT validation.
type JWTConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Issuer           string   `yaml:"issuer"`
	Audience         string   `yaml:"audience"`
	Algorithms       []string `yaml:"algorithms"`
	PublicKeyFile    string   `yaml:"public_key_file"`
	JWKSURL          string   `yaml:"jwks_url"`
	ClockSkewSeconds int      `yaml:"clock_skew_seconds"`
	PublicKeyPEM     string   `yaml:"public_key_pem"`
}

// APIKeysConfig controls API key authentication.
type APIKeysConfig struct {
	Enabled    bool           `yaml:"enabled"`
	HeaderName string         `yaml:"header_name"`
	QueryParam string         `yaml:"query_param"`
	Keys       []APIKeyConfig `yaml:"keys"`
}

// APIKeyConfig represents a single API key configuration.
type APIKeyConfig struct {
	Name         string   `yaml:"name"`
	KeyHash      string   `yaml:"key_hash"`
	KeyPrefix    string   `yaml:"key_prefix"`
	RateLimit    int      `yaml:"rate_limit"`
	AllowedPaths []string `yaml:"allowed_paths"`
	Enabled      bool     `yaml:"enabled"`
}

// APIValidationConfig controls OpenAPI schema validation.
type APIValidationConfig struct {
	Enabled          bool                 `yaml:"enabled"`
	ValidateRequest  bool                 `yaml:"validate_request"`
	ValidateResponse bool                 `yaml:"validate_response"`
	StrictMode       bool                 `yaml:"strict_mode"`
	BlockOnViolation bool                 `yaml:"block_on_violation"`
	ViolationScore   int                  `yaml:"violation_score"`
	CacheSize        int                  `yaml:"cache_size"`
	Schemas          []SchemaSourceConfig `yaml:"schemas"`
}

// SchemaSourceConfig represents a schema source configuration.
type SchemaSourceConfig struct {
	Path      string `yaml:"path"`
	Type      string `yaml:"type"`
	AutoLearn bool   `yaml:"auto_learn"`
}

// TracingConfig controls built-in distributed tracing.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled"`
	ServiceName  string  `yaml:"service_name"`
	SamplingRate float64 `yaml:"sampling_rate"` // 0.0-1.0
	ExporterType string  `yaml:"exporter_type"` // "stdout", "noop"
}


// FindVirtualHost finds a virtual host configuration by domain.
// It checks exact match first, then wildcard patterns (e.g., *.example.com).
// Returns nil if no match is found.
func FindVirtualHost(vhosts []VirtualHostConfig, host string) *VirtualHostConfig {
	if host == "" || len(vhosts) == 0 {
		return nil
	}

	// Remove port from host if present (bracket-aware for IPv6)
	host = stripHostPort(host)

	for i := range vhosts {
		vh := &vhosts[i]
		for _, domain := range vh.Domains {
			if domain == host {
				return vh
			}
			// Check wildcard match
			if len(domain) > 0 && domain[0] == '*' {
				suffix := domain[1:] // Remove leading *
				if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
					return vh
				}
			}
		}
	}
	return nil
}

// stripHostPort removes the port suffix from a host string, handling IPv6 brackets.
func stripHostPort(host string) string {
	if strings.Contains(host, "]") {
		// IPv6: [::1]:8088
		bracket := strings.LastIndex(host, "]")
		if idx := strings.LastIndex(host, ":"); idx > bracket {
			return host[:idx]
		}
		return host
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}
