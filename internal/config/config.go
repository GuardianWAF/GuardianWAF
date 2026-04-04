// Package config provides configuration types and loading for GuardianWAF.
// All structs mirror the YAML configuration schema defined in SPECIFICATION.md.
// The yaml struct tags are documentary — actual loading uses the YAML parser's Node tree.
package config

import "time"

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
	Logging   LogConfig       `yaml:"logging"`
	Events    EventsConfig    `yaml:"events"`
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
}

// ACMEConfig holds automatic certificate management settings.
type ACMEConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Email    string   `yaml:"email"`
	Domains  []string `yaml:"domains"`
	CacheDir string   `yaml:"cache_dir"`
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
	Sanitizer        SanitizerConfig        `yaml:"sanitizer"`
	Detection        DetectionConfig        `yaml:"detection"`
	BotDetection     BotDetectionConfig     `yaml:"bot_detection"`
	Challenge        ChallengeConfig        `yaml:"challenge"`
	Response         ResponseConfig         `yaml:"response"`
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
	Enabled    bool          `yaml:"enabled"`
	DefaultTTL time.Duration `yaml:"default_ttl"`
	MaxTTL     time.Duration `yaml:"max_ttl"`
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
	Enabled        bool     `yaml:"enabled"`
	GRPCWebEnabled bool     `yaml:"grpc_web_enabled"`
	ProtoPaths     []string `yaml:"proto_paths"`
	AllowedMethods []string `yaml:"allowed_methods"`
	BlockedMethods []string `yaml:"blocked_methods"`
	ValidateProto  bool     `yaml:"validate_proto"`
	MaxMessageSize int      `yaml:"max_message_size"`
}

// TenantConfig controls multi-tenancy settings.
type TenantConfig struct {
	Enabled      bool              `yaml:"enabled"`
	MaxTenants   int               `yaml:"max_tenants"`
	HeaderName   string            `yaml:"header_name"`
	DefaultQuota ResourceQuotaConfig `yaml:"default_quota"`
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
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	APIKey  string `yaml:"api_key"`
	TLS     bool   `yaml:"tls"`
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
