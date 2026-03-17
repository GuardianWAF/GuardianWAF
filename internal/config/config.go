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

	Upstreams []UpstreamConfig `yaml:"upstreams"`
	Routes    []RouteConfig    `yaml:"routes"`

	WAF       WAFConfig       `yaml:"waf"`
	Dashboard DashboardConfig `yaml:"dashboard"`
	MCP       MCPConfig       `yaml:"mcp"`
	Logging   LogConfig       `yaml:"logging"`
	Events    EventsConfig    `yaml:"events"`
}

// TLSConfig holds TLS/SSL settings including optional ACME auto-certificate.
type TLSConfig struct {
	Enabled  bool       `yaml:"enabled"`
	Listen   string     `yaml:"listen"`
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	ACME     ACMEConfig `yaml:"acme"`
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

// WAFConfig is the top-level container for all WAF protection settings.
type WAFConfig struct {
	IPACL        IPACLConfig        `yaml:"ip_acl"`
	RateLimit    RateLimitConfig    `yaml:"rate_limit"`
	Sanitizer    SanitizerConfig    `yaml:"sanitizer"`
	Detection    DetectionConfig    `yaml:"detection"`
	BotDetection BotDetectionConfig `yaml:"bot_detection"`
	Challenge    ChallengeConfig    `yaml:"challenge"`
	Response     ResponseConfig     `yaml:"response"`
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
