// Package config provides configuration types and loading for GuardianWAF.
// All structs mirror the YAML configuration schema defined in SPECIFICATION.md.
// The yaml struct tags are documentary — actual loading uses the YAML parser's Node tree.
package config

import "time"

// Config is the top-level configuration for GuardianWAF.
type Config struct {
	Mode   string    `yaml:"mode"`   // "enforce", "monitor", "disabled"
	Listen string    `yaml:"listen"` // Listen address (e.g., ":8080")
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

// AlertingConfig controls webhook-based alert delivery.
type AlertingConfig struct {
	Enabled  bool                `yaml:"enabled"`
	Webhooks []WebhookConfig     `yaml:"webhooks"`
}

// WebhookConfig defines a single webhook target.
type WebhookConfig struct {
	Name     string            `yaml:"name"`
	URL      string            `yaml:"url"`
	Type     string            `yaml:"type"`     // "slack", "discord", "generic"
	Events   []string          `yaml:"events"`   // "block", "challenge", "log", "all"
	MinScore int               `yaml:"min_score"`
	Cooldown time.Duration     `yaml:"cooldown"`
	Headers  map[string]string `yaml:"headers"`
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
	Enabled bool             `yaml:"enabled"`
	Rules   []CustomRule     `yaml:"rules"`
}

// CustomRule defines a single custom WAF rule.
type CustomRule struct {
	ID         string            `yaml:"id"`
	Name       string            `yaml:"name"`
	Enabled    bool              `yaml:"enabled"`
	Priority   int               `yaml:"priority"`
	Conditions []RuleCondition   `yaml:"conditions"`
	Action     string            `yaml:"action"` // "block", "log", "challenge", "pass"
	Score      int               `yaml:"score"`
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
	IPACL         IPACLConfig         `yaml:"ip_acl"`
	CustomRules   CustomRulesConfig   `yaml:"custom_rules"`
	GeoIP         GeoIPConfig         `yaml:"geoip"`
	ThreatIntel   ThreatIntelConfig   `yaml:"threat_intel"`
	CORS          CORSConfig          `yaml:"cors"`
	RateLimit     RateLimitConfig     `yaml:"rate_limit"`
	ATOProtection ATOProtectionConfig `yaml:"ato_protection"`
	APISecurity   APISecurityConfig   `yaml:"api_security"`
	Sanitizer     SanitizerConfig     `yaml:"sanitizer"`
	Detection     DetectionConfig     `yaml:"detection"`
	BotDetection  BotDetectionConfig  `yaml:"bot_detection"`
	Challenge     ChallengeConfig     `yaml:"challenge"`
	Response      ResponseConfig      `yaml:"response"`
	AIAnalysis    AIAnalysisConfig    `yaml:"ai_analysis"`
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

// IPACLConfig controls IP-based allow/deny lists and automatic banning.
type IPACLConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Whitelist []string      `yaml:"whitelist"`
	Blacklist []string      `yaml:"blacklist"`
	AutoBan   AutoBanConfig `yaml:"auto_ban"`
}

// AutoBanConfig controls automatic IP banning behaviour.
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

// SanitizerConfig controls request sanitisation limits and behaviour.
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
	Enabled        bool                 `yaml:"enabled"`
	Mode           string               `yaml:"mode"`
	TLSFingerprint TLSFingerprintConfig `yaml:"tls_fingerprint"`
	UserAgent      UAConfig             `yaml:"user_agent"`
	Behavior       BehaviorConfig       `yaml:"behavior"`
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

// BehaviorConfig controls behavioural analysis for bot detection.
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

// ErrorPagesConfig controls custom error page behaviour.
type ErrorPagesConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // "production", "development"
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
	Enabled        bool              `yaml:"enabled"`
	IPReputation   IPReputationConfig   `yaml:"ip_reputation"`
	DomainRep      DomainReputationConfig `yaml:"domain_reputation"`
	CacheSize      int               `yaml:"cache_size"`
	CacheTTL       time.Duration     `yaml:"cache_ttl"`
	Feeds          []ThreatFeedConfig `yaml:"feeds"`
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
	Type     string        `yaml:"type"`     // "file" or "url"
	Path     string        `yaml:"path"`     // File path for type="file"
	URL      string        `yaml:"url"`      // URL for type="url"
	Refresh  time.Duration `yaml:"refresh"`  // Refresh interval
	Format   string        `yaml:"format"`   // "json", "jsonl", "csv"
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
	Enabled        bool                    `yaml:"enabled"`
	LoginPaths     []string                `yaml:"login_paths"`
	BruteForce     BruteForceConfig        `yaml:"brute_force"`
	CredStuffing   CredentialStuffingConfig `yaml:"credential_stuffing"`
	PasswordSpray  PasswordSprayConfig     `yaml:"password_spray"`
	Travel         ImpossibleTravelConfig  `yaml:"impossible_travel"`
	GeoDBPath      string                  `yaml:"geodb_path"`
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
	Enabled     bool            `yaml:"enabled"`
	JWT         JWTConfig       `yaml:"jwt"`
	APIKeys     APIKeysConfig   `yaml:"api_keys"`
	SkipPaths   []string        `yaml:"skip_paths"`
	HeaderName  string          `yaml:"header_name"`
	QueryParam  string          `yaml:"query_param"`
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
