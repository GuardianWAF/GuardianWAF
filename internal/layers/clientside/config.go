// Package clientside provides client-side protection against Magecart and other client-side attacks.
package clientside

import (
	"regexp"
	"time"
)

// Config holds client-side protection configuration.
type Config struct {
	Enabled           bool               `yaml:"enabled"`
	Mode              string             `yaml:"mode"` // "monitor", "block", "inject"
	MagecartDetection MagecartConfig     `yaml:"magecart_detection"`
	AgentInjection    AgentConfig        `yaml:"agent_injection"`
	CSP               CSPConfig          `yaml:"csp"`
	JavaScriptPolicy  JavaScriptPolicy   `yaml:"javascript_policy"`
	Exclusions        []string           `yaml:"exclusions"` // Paths to exclude
}

// DefaultConfig returns default client-side protection configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		Mode:    "monitor",
		MagecartDetection: MagecartConfig{
			Enabled:                true,
			DetectObfuscatedJS:     true,
			DetectSuspiciousDomains: true,
			DetectFormExfiltration: true,
			DetectKeyloggers:       true,
			BlockScore:             50,
			AlertScore:             25,
		},
		AgentInjection: AgentConfig{
			Enabled:       false,
			ScriptURL:     "/_guardian/agent.js",
			InjectInHTML:  true,
			InjectInJS:    false,
			MonitorDOM:    true,
			MonitorNetwork: true,
		},
		CSP: CSPConfig{
			Enabled:             false,
			ReportOnly:          true,
			DefaultSrc:          []string{"'self'"},
			ScriptSrc:           []string{"'self'"},
			StyleSrc:            []string{"'self'", "'unsafe-inline'"},
			ImgSrc:              []string{"'self'", "data:", "https:"},
			ConnectSrc:          []string{"'self'"},
			FontSrc:             []string{"'self'"},
			ObjectSrc:           []string{"'none'"},
			MediaSrc:            []string{"'self'"},
			FrameSrc:            []string{"'self'"},
			FrameAncestors:      []string{"'none'"},
			FormAction:          []string{"'self'"},
			BaseURI:             []string{"'self'"},
			ReportURI:           "/_guardian/csp-report",
			UpgradeInsecure:     true,
		},
		JavaScriptPolicy: JavaScriptPolicy{
			BlockInlineScripts:  false,
			BlockEval:           false,
			BlockNewFunction:    false,
			BlockSetTimeoutString: false,
			BlockSetIntervalString: false,
			BlockWebAssembly:    false,
		},
		Exclusions: []string{"/health", "/metrics"},
	}
}

// MagecartConfig controls Magecart/skimming detection.
type MagecartConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	DetectObfuscatedJS      bool     `yaml:"detect_obfuscated_js"`
	DetectSuspiciousDomains bool     `yaml:"detect_suspicious_domains"`
	DetectFormExfiltration  bool     `yaml:"detect_form_exfiltration"`
	DetectKeyloggers        bool     `yaml:"detect_keyloggers"`
	KnownSkimmingDomains    []string `yaml:"known_skimming_domains"`
	SuspiciousPatterns      []string `yaml:"suspicious_patterns"`
	BlockScore              int      `yaml:"block_score"`
	AlertScore              int      `yaml:"alert_score"`
}

// AgentConfig controls security agent injection.
type AgentConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ScriptURL       string   `yaml:"script_url"`
	InjectInHTML    bool     `yaml:"inject_in_html"`
	InjectInJS      bool     `yaml:"inject_in_js"`
	InjectPosition  string   `yaml:"inject_position"` // "head", "body-start", "body-end"
	MonitorDOM      bool     `yaml:"monitor_dom"`
	MonitorNetwork  bool     `yaml:"monitor_network"`
	MonitorForms    bool     `yaml:"monitor_forms"`
	ProtectedPaths  []string `yaml:"protected_paths"` // Empty = all paths
}

// CSPConfig controls Content Security Policy headers.
type CSPConfig struct {
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

// JavaScriptPolicy controls JavaScript execution policies.
type JavaScriptPolicy struct {
	BlockInlineScripts     bool `yaml:"block_inline_scripts"`
	BlockEval              bool `yaml:"block_eval"`
	BlockNewFunction       bool `yaml:"block_new_function"`
	BlockSetTimeoutString  bool `yaml:"block_settimeout_string"`
	BlockSetIntervalString bool `yaml:"block_setinterval_string"`
	BlockWebAssembly       bool `yaml:"block_webassembly"`
}

// DetectionResult holds the result of a Magecart detection scan.
type DetectionResult struct {
	Detected    bool              `json:"detected"`
	ThreatType  string            `json:"threat_type"`
	Score       int               `json:"score"`
	Matches     []PatternMatch    `json:"matches"`
	Timestamp   time.Time         `json:"timestamp"`
}

// PatternMatch holds details of a pattern match.
type PatternMatch struct {
	Pattern     string `json:"pattern"`
	MatchedText string `json:"matched_text"`
	Position    int    `json:"position"`
	Severity    string `json:"severity"` // "low", "medium", "high", "critical"
}

// CompiledPatterns holds compiled regex patterns for detection.
type CompiledPatterns struct {
	ObfuscationPatterns    []*regexp.Regexp
	SkimmingPatterns       []*regexp.Regexp
	KeyloggerPatterns      []*regexp.Regexp
	FormExfilPatterns      []*regexp.Regexp
	SuspiciousDomains      map[string]bool
	KnownSkimmingDomains   map[string]bool
}

// CompilePatterns compiles detection patterns.
func CompilePatterns(cfg *MagecartConfig) *CompiledPatterns {
	cp := &CompiledPatterns{
		SuspiciousDomains:    make(map[string]bool),
		KnownSkimmingDomains: make(map[string]bool),
	}

	// Obfuscation detection patterns
	if cfg.DetectObfuscatedJS {
		cp.ObfuscationPatterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)(eval\s*\(|function\s*\w*\s*\([^)]*\)\s*\{[^}]*eval)`),
			regexp.MustCompile(`(?i)(atob|btoa)\s*\(`),
			regexp.MustCompile(`(?i)unescape\s*\(`),
			regexp.MustCompile(`(?i)fromCharCode\s*\(`),
			regexp.MustCompile(`(?i)\\x[0-9a-fA-F]{2}`), // Hex encoding
			regexp.MustCompile(`(?i)\\u[0-9a-fA-F]{4}`), // Unicode encoding
			regexp.MustCompile(`(?i)String\.fromCharCode`),
			regexp.MustCompile(`(?i)document\.write\s*\(`),
			regexp.MustCompile(`(?i)(\\[0-7]{1,3}){4,}`), // Octal encoding
		}
	}

	// Skimming detection patterns
	if cfg.DetectSuspiciousDomains {
		cp.SkimmingPatterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)https?://[^/"'\s]*(?:skim|track|analytic|metric|pixel|beacon|collect)[^/"'\s]*`),
			regexp.MustCompile(`(?i)(google-analytics|googletagmanager)\.com.*[?&](tid|gtm)=G-[A-Z0-9]+`),
			regexp.MustCompile(`(?i)document\.(forms?|querySelector)\s*\([^)]*(?:login|password|card|cvv|ssn)`),
			regexp.MustCompile(`(?i)(?:credit.?card|payment|billing).{0,50}(?:input|field|form)`),
		}
	}

	// Keylogger patterns
	if cfg.DetectKeyloggers {
		cp.KeyloggerPatterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)addEventListener\s*\(\s*['"]key(down|up|press)['"]`),
			regexp.MustCompile(`(?i)(?:key|char|which)\s*===?\s*[0-9]+`),
			regexp.MustCompile(`(?i)document\.(onkey|attachEvent)`),
			regexp.MustCompile(`(?i)input.*type\s*[=:]\s*['"]password['"]`),
		}
	}

	// Form exfiltration patterns
	if cfg.DetectFormExfiltration {
		cp.FormExfilPatterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)fetch\s*\([^)]*\).*(?:post|put|patch)`),
			regexp.MustCompile(`(?i)XMLHttpRequest.*send\s*\(`),
			regexp.MustCompile(`(?i)(?:navigator|window)\.(sendBeacon|fetch)`),
			regexp.MustCompile(`(?i)formData\.(?:append|set)\s*\(`),
			regexp.MustCompile(`(?i)\.value\s*[^=]*=.*(?:password|card|cvv|ssn)`),
			regexp.MustCompile(`(?i)localStorage\.(?:setItem|removeItem)`),
			regexp.MustCompile(`(?i)sessionStorage\.(?:setItem|removeItem)`),
		}
	}

	// Load suspicious domains
	for _, domain := range cfg.KnownSkimmingDomains {
		cp.KnownSkimmingDomains[domain] = true
	}

	return cp
}

// DefaultKnownSkimmingDomains returns a list of known skimming domains.
func DefaultKnownSkimmingDomains() []string {
	return []string{
		// Known Magecart domains (examples - should be updated regularly)
		"jquery-min.us",
		"jquery-min.su",
		"google-analitics.com",
		"googletagmanager.com.cm",
		"googletagmanager.eu",
		// Add more known malicious domains here
	}
}

// DefaultSuspiciousPatterns returns default suspicious patterns.
func DefaultSuspiciousPatterns() []string {
	return []string{
		`(?i)(?:skimmer|skimming|carding)`,
		`(?i)(?:magecart|magneto)`,
		`(?i)(?:payment.*exfil|exfil.*payment)`,
	}
}
