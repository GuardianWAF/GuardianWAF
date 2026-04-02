// Package guardianwaf provides a zero-dependency Web Application Firewall for Go.
//
// GuardianWAF can be used as an HTTP middleware to protect web applications
// from SQL injection, XSS, path traversal, command injection, XXE, SSRF,
// and bot attacks using a tokenizer-based scoring engine.
//
// Quick start:
//
//	engine, err := guardianwaf.NewFromFile("guardianwaf.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	http.ListenAndServe(":8088", engine.Middleware(myHandler))
//
// Using the programmatic API:
//
//	waf, err := guardianwaf.New(guardianwaf.Config{
//	    Mode: guardianwaf.ModeEnforce,
//	    Threshold: guardianwaf.ThresholdConfig{Block: 50, Log: 25},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer waf.Close()
//	http.ListenAndServe(":8088", waf.Middleware(myHandler))
package guardianwaf

import (
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// Mode constants for WAF operation mode.
const (
	ModeEnforce  = "enforce"
	ModeMonitor  = "monitor"
	ModeDisabled = "disabled"
)

// Config is the public configuration for the WAF engine.
type Config struct {
	Mode      string
	Detection DetectionConfig
	Threshold ThresholdConfig
	Sanitizer SanitizerConfig
	IPACL     IPACLConfig
	RateLimit RateLimitConfig
	Bot       BotConfig
	Challenge ChallengeConfig
	Response  ResponseConfig
	Events    EventsConfig
}

// DetectionConfig configures the attack detection detectors.
type DetectionConfig struct {
	SQLi          DetectorConfig
	XSS           DetectorConfig
	PathTraversal DetectorConfig
	CmdInjection  DetectorConfig
	XXE           DetectorConfig
	SSRF          DetectorConfig
}

// DetectorConfig toggles a single detector and sets its score multiplier.
type DetectorConfig struct {
	Enabled    bool
	Multiplier float64
}

// ThresholdConfig defines scoring thresholds that trigger blocking or logging.
type ThresholdConfig struct {
	Block int
	Log   int
}

// Config controls request sanitization limits.
type SanitizerConfig struct {
	MaxURLLength  int
	MaxHeaderSize int
	MaxBodySize   int64
}

// IPACLConfig controls IP-based allow/deny lists.
type IPACLConfig struct {
	Whitelist []string
	Blacklist []string
}

// RateLimitConfig controls rate limiting.
type RateLimitConfig struct {
	Enabled bool
	Rules   []RateLimitRule
}

// RateLimitRule defines a single rate limiting rule.
type RateLimitRule struct {
	ID     string
	Scope  string
	Limit  int
	Window time.Duration
	Burst  int
	Action string
}

// BotConfig controls bot detection.
type BotConfig struct {
	Enabled            bool
	BlockEmpty         bool
	BlockKnownScanners bool
}

// ChallengeConfig controls JavaScript proof-of-work challenges.
type ChallengeConfig struct {
	Enabled    bool
	Difficulty int           // leading zero bits (default: 20)
	CookieTTL  time.Duration // challenge cookie lifetime (default: 1h)
	CookieName string        // cookie name (default: "__gwaf_challenge")
	SecretKey  string        // HMAC signing key (auto-generated if empty)
}

// ResponseConfig controls response protections.
type ResponseConfig struct {
	SecurityHeaders bool
	DataMasking     bool
}

// EventsConfig controls event storage.
type EventsConfig struct {
	MaxEvents int
}

// Result is returned by Engine.Check.
type Result struct {
	Blocked    bool
	Logged     bool
	TotalScore int
	Action     string
	Findings   []Finding
	RequestID  string
	Duration   time.Duration
}

// Finding represents a detection result.
type Finding struct {
	Detector    string
	Category    string
	Score       int
	Description string
	Location    string
	Severity    string
}

// Event represents a WAF event.
type Event = engine.Event

// Engine is the WAF engine.
type Engine struct {
	internal *engine.Engine
	cfg      *config.Config
}

// New creates a new WAF engine with the given configuration.
func New(cfg Config, opts ...Option) (*Engine, error) {
	internalCfg := convertConfig(cfg)

	for _, opt := range opts {
		opt(internalCfg)
	}

	store := events.NewMemoryStore(internalCfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(internalCfg, store, bus)
	if err != nil {
		return nil, err
	}

	addDefaultLayers(eng, internalCfg)

	// Wire challenge service if enabled
	if internalCfg.WAF.Challenge.Enabled {
		chCfg := challenge.Config{
			Enabled:    true,
			Difficulty: internalCfg.WAF.Challenge.Difficulty,
			CookieTTL:  internalCfg.WAF.Challenge.CookieTTL,
			CookieName: internalCfg.WAF.Challenge.CookieName,
		}
		if internalCfg.WAF.Challenge.SecretKey != "" {
			chCfg.SecretKey = []byte(internalCfg.WAF.Challenge.SecretKey)
		}
		eng.SetChallengeService(challenge.NewService(chCfg))
	}

	return &Engine{internal: eng, cfg: internalCfg}, nil
}

// NewFromFile creates a new WAF engine from a YAML config file.
func NewFromFile(path string, opts ...Option) (*Engine, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	config.LoadEnv(cfg)

	for _, opt := range opts {
		opt(cfg)
	}

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		return nil, err
	}

	addDefaultLayers(eng, cfg)

	return &Engine{internal: eng, cfg: cfg}, nil
}

// NewWithDefaults creates a new WAF engine with sensible defaults.
// Equivalent to New(Config{}) but more explicit.
func NewWithDefaults(opts ...Option) (*Engine, error) {
	return New(Config{}, opts...)
}

// Middleware returns an http.Handler that wraps next with WAF protection.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return e.internal.Middleware(next)
}

// Check checks a request against the WAF without proxying.
func (e *Engine) Check(r *http.Request) Result {
	event := e.internal.Check(r)
	return convertResult(event)
}

// OnEvent registers a callback for WAF events.
// The callback runs in a separate goroutine to avoid blocking the pipeline.
func (e *Engine) OnEvent(fn func(Event)) {
	ch := make(chan engine.Event, 64)
	e.internal.EventBus().Subscribe(ch)
	go func() {
		for event := range ch {
			fn(event)
		}
	}()
}

// Stats returns runtime statistics.
func (e *Engine) Stats() Stats {
	s := e.internal.Stats()
	return Stats{
		TotalRequests:      s.TotalRequests,
		BlockedRequests:    s.BlockedRequests,
		ChallengedRequests: s.ChallengedRequests,
		LoggedRequests:     s.LoggedRequests,
		PassedRequests:     s.PassedRequests,
		AvgLatencyUs:       s.AvgLatencyUs,
	}
}

// Stats holds runtime statistics for the engine.
type Stats struct {
	TotalRequests      int64
	BlockedRequests    int64
	ChallengedRequests int64
	LoggedRequests     int64
	PassedRequests     int64
	AvgLatencyUs       int64
}

// Close shuts down the engine and releases resources.
func (e *Engine) Close() error {
	return e.internal.Close()
}

// convertConfig converts the public Config to the internal config.Config.
func convertConfig(cfg Config) *config.Config {
	c := config.DefaultConfig()

	if cfg.Mode != "" {
		c.Mode = cfg.Mode
	}

	// Thresholds
	if cfg.Threshold.Block > 0 {
		c.WAF.Detection.Threshold.Block = cfg.Threshold.Block
	}
	if cfg.Threshold.Log > 0 {
		c.WAF.Detection.Threshold.Log = cfg.Threshold.Log
	}

	// Detection detectors
	detectors := make(map[string]config.DetectorConfig)
	detectors["sqli"] = toInternalDetector(cfg.Detection.SQLi, true)
	detectors["xss"] = toInternalDetector(cfg.Detection.XSS, true)
	detectors["lfi"] = toInternalDetector(cfg.Detection.PathTraversal, true)
	detectors["cmdi"] = toInternalDetector(cfg.Detection.CmdInjection, true)
	detectors["xxe"] = toInternalDetector(cfg.Detection.XXE, true)
	detectors["ssrf"] = toInternalDetector(cfg.Detection.SSRF, true)
	c.WAF.Detection.Detectors = detectors

	// Sanitizer
	if cfg.Sanitizer.MaxURLLength > 0 {
		c.WAF.Sanitizer.MaxURLLength = cfg.Sanitizer.MaxURLLength
	}
	if cfg.Sanitizer.MaxHeaderSize > 0 {
		c.WAF.Sanitizer.MaxHeaderSize = cfg.Sanitizer.MaxHeaderSize
	}
	if cfg.Sanitizer.MaxBodySize > 0 {
		c.WAF.Sanitizer.MaxBodySize = cfg.Sanitizer.MaxBodySize
	}

	// IP ACL
	if len(cfg.IPACL.Whitelist) > 0 {
		c.WAF.IPACL.Whitelist = cfg.IPACL.Whitelist
	}
	if len(cfg.IPACL.Blacklist) > 0 {
		c.WAF.IPACL.Blacklist = cfg.IPACL.Blacklist
	}

	// Rate Limit
	if cfg.RateLimit.Enabled {
		c.WAF.RateLimit.Enabled = true
		rules := make([]config.RateLimitRule, len(cfg.RateLimit.Rules))
		for i, r := range cfg.RateLimit.Rules {
			rules[i] = config.RateLimitRule{
				ID:     r.ID,
				Scope:  r.Scope,
				Limit:  r.Limit,
				Window: r.Window,
				Burst:  r.Burst,
				Action: r.Action,
			}
		}
		if len(rules) > 0 {
			c.WAF.RateLimit.Rules = rules
		}
	}

	// Bot detection
	if !cfg.Bot.Enabled {
		c.WAF.BotDetection.Enabled = false
	}
	c.WAF.BotDetection.UserAgent.BlockEmpty = cfg.Bot.BlockEmpty
	c.WAF.BotDetection.UserAgent.BlockKnownScanners = cfg.Bot.BlockKnownScanners

	// Challenge
	if cfg.Challenge.Enabled {
		c.WAF.Challenge.Enabled = true
		if cfg.Challenge.Difficulty > 0 {
			c.WAF.Challenge.Difficulty = cfg.Challenge.Difficulty
		}
		if cfg.Challenge.CookieTTL > 0 {
			c.WAF.Challenge.CookieTTL = cfg.Challenge.CookieTTL
		}
		if cfg.Challenge.CookieName != "" {
			c.WAF.Challenge.CookieName = cfg.Challenge.CookieName
		}
		c.WAF.Challenge.SecretKey = cfg.Challenge.SecretKey
	}

	// Response
	c.WAF.Response.SecurityHeaders.Enabled = cfg.Response.SecurityHeaders
	c.WAF.Response.DataMasking.Enabled = cfg.Response.DataMasking

	// Events
	if cfg.Events.MaxEvents > 0 {
		c.Events.MaxEvents = cfg.Events.MaxEvents
	}

	return c
}

// toInternalDetector converts a public DetectorConfig to an internal one.
// If the detector is zero-valued and defaultEnabled is true, it enables it with 1.0 multiplier.
func toInternalDetector(dc DetectorConfig, defaultEnabled bool) config.DetectorConfig {
	if dc.Multiplier == 0 && !dc.Enabled {
		return config.DetectorConfig{Enabled: defaultEnabled, Multiplier: 1.0}
	}
	m := dc.Multiplier
	if m == 0 {
		m = 1.0
	}
	return config.DetectorConfig{Enabled: dc.Enabled, Multiplier: m}
}

// convertResult converts an internal engine event to a public Result.
func convertResult(event *engine.Event) Result {
	findings := make([]Finding, len(event.Findings))
	for i, f := range event.Findings {
		findings[i] = Finding{
			Detector:    f.DetectorName,
			Category:    f.Category,
			Score:       f.Score,
			Description: f.Description,
			Location:    f.Location,
			Severity:    f.Severity.String(),
		}
	}
	return Result{
		Blocked:    event.Action == engine.ActionBlock,
		Logged:     event.Action == engine.ActionLog,
		TotalScore: event.Score,
		Action:     event.Action.String(),
		Findings:   findings,
		RequestID:  event.RequestID,
		Duration:   event.Duration,
	}
}

// addDefaultLayers wires all WAF layers based on the internal config.
func addDefaultLayers(eng *engine.Engine, cfg *config.Config) {
	// 1. IP ACL layer (Order 100)
	if cfg.WAF.IPACL.Enabled {
		ipaclLayer, err := ipacl.NewLayer(ipacl.Config{
			Enabled:   cfg.WAF.IPACL.Enabled,
			Whitelist: cfg.WAF.IPACL.Whitelist,
			Blacklist: cfg.WAF.IPACL.Blacklist,
			AutoBan: ipacl.AutoBanConfig{
				Enabled:    cfg.WAF.IPACL.AutoBan.Enabled,
				DefaultTTL: cfg.WAF.IPACL.AutoBan.DefaultTTL,
				MaxTTL:     cfg.WAF.IPACL.AutoBan.MaxTTL,
			},
		})
		if err == nil {
			eng.AddLayer(engine.OrderedLayer{Layer: ipaclLayer, Order: engine.OrderIPACL})
		}
	}

	// 2. Rate Limit layer (Order 200)
	if cfg.WAF.RateLimit.Enabled {
		rules := make([]ratelimit.Rule, len(cfg.WAF.RateLimit.Rules))
		for i, r := range cfg.WAF.RateLimit.Rules {
			rules[i] = ratelimit.Rule{
				ID:           r.ID,
				Scope:        r.Scope,
				Paths:        r.Paths,
				Limit:        r.Limit,
				Window:       r.Window,
				Burst:        r.Burst,
				Action:       r.Action,
				AutoBanAfter: r.AutoBanAfter,
			}
		}
		rlLayer := ratelimit.NewLayer(ratelimit.Config{
			Enabled: true,
			Rules:   rules,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: rlLayer, Order: engine.OrderRateLimit})
	}

	// 3. Sanitizer layer (Order 300)
	if cfg.WAF.Sanitizer.Enabled {
		sanLayer := sanitizer.NewLayer(sanitizer.Config{
			MaxURLLength:   cfg.WAF.Sanitizer.MaxURLLength,
			MaxHeaderSize:  cfg.WAF.Sanitizer.MaxHeaderSize,
			MaxHeaderCount: cfg.WAF.Sanitizer.MaxHeaderCount,
			MaxBodySize:    cfg.WAF.Sanitizer.MaxBodySize,
			MaxCookieSize:  cfg.WAF.Sanitizer.MaxCookieSize,
			AllowedMethods: cfg.WAF.Sanitizer.AllowedMethods,
			BlockNullBytes: cfg.WAF.Sanitizer.BlockNullBytes,
			StripHopByHop:  cfg.WAF.Sanitizer.StripHopByHop,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: sanLayer, Order: engine.OrderSanitizer})
	}

	// 4. Detection layer (Order 400)
	if cfg.WAF.Detection.Enabled {
		detConfigs := make(map[string]detection.DetectorConfig, len(cfg.WAF.Detection.Detectors))
		for name, dc := range cfg.WAF.Detection.Detectors {
			detConfigs[name] = detection.DetectorConfig{
				Enabled:    dc.Enabled,
				Multiplier: dc.Multiplier,
			}
		}
		var exclusions []detection.Exclusion
		for _, exc := range cfg.WAF.Detection.Exclusions {
			exclusions = append(exclusions, detection.Exclusion{
				PathPrefix: exc.Path,
				Detectors:  exc.Detectors,
				Reason:     exc.Reason,
			})
		}
		detLayer := detection.NewLayer(detection.Config{
			Enabled:    true,
			Detectors:  detConfigs,
			Exclusions: exclusions,
		})
		eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: engine.OrderDetection})
	}

	// 5. Bot Detection layer (Order 500)
	if cfg.WAF.BotDetection.Enabled {
		bdLayer := botdetect.NewLayer(botdetect.Config{
			Enabled: true,
			Mode:    cfg.WAF.BotDetection.Mode,
			TLSFingerprint: botdetect.TLSFingerprintConfig{
				Enabled:         cfg.WAF.BotDetection.TLSFingerprint.Enabled,
				KnownBotsAction: cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction,
				UnknownAction:   cfg.WAF.BotDetection.TLSFingerprint.UnknownAction,
				MismatchAction:  cfg.WAF.BotDetection.TLSFingerprint.MismatchAction,
			},
			UserAgent: botdetect.UAConfig{
				Enabled:            cfg.WAF.BotDetection.UserAgent.Enabled,
				BlockEmpty:         cfg.WAF.BotDetection.UserAgent.BlockEmpty,
				BlockKnownScanners: cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
			},
			Behavior: botdetect.BehaviorAnalysisConfig{
				Enabled:            cfg.WAF.BotDetection.Behavior.Enabled,
				Window:             cfg.WAF.BotDetection.Behavior.Window,
				RPSThreshold:       cfg.WAF.BotDetection.Behavior.RPSThreshold,
				ErrorRateThreshold: cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
			},
		})
		eng.AddLayer(engine.OrderedLayer{Layer: bdLayer, Order: engine.OrderBotDetect})
	}

	// 6. Response layer (Order 600)
	respCfg := response.Config{
		SecurityHeadersEnabled: cfg.WAF.Response.SecurityHeaders.Enabled,
		DataMaskingEnabled:     cfg.WAF.Response.DataMasking.Enabled,
		MaskCreditCards:        cfg.WAF.Response.DataMasking.MaskCreditCards,
		MaskSSN:                cfg.WAF.Response.DataMasking.MaskSSN,
		MaskAPIKeys:            cfg.WAF.Response.DataMasking.MaskAPIKeys,
		StripStackTraces:       cfg.WAF.Response.DataMasking.StripStackTraces,
		ErrorPageMode:          cfg.WAF.Response.ErrorPages.Mode,
	}
	if cfg.WAF.Response.SecurityHeaders.Enabled {
		respCfg.Headers = response.SecurityHeaders{
			XContentTypeOptions: "nosniff",
			XFrameOptions:       cfg.WAF.Response.SecurityHeaders.XFrameOptions,
			ReferrerPolicy:      cfg.WAF.Response.SecurityHeaders.ReferrerPolicy,
			PermissionsPolicy:   cfg.WAF.Response.SecurityHeaders.PermissionsPolicy,
		}
	}
	respLayer := response.NewLayer(respCfg)
	eng.AddLayer(engine.OrderedLayer{Layer: respLayer, Order: engine.OrderResponse})
}
