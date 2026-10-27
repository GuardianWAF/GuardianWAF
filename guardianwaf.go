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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/challenge"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
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
	SSTI          DetectorConfig
	NoSQLi        DetectorConfig
	Smuggling     DetectorConfig
	OpenRedirect  DetectorConfig
	GraphQL       DetectorConfig
	Exclusions    []ExclusionConfig
}

// ExclusionConfig defines paths that skip specific detectors.
type ExclusionConfig struct {
	Path      string
	Detectors []string
	Reason    string
}

// DetectorConfig toggles a single detector and sets its score multiplier.
// A zero value inherits the enabled default. To disable a detector, use
// WithDetector(name, false, 1) or set Enabled:false with Multiplier:1.
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
	internal    *engine.Engine
	cfg         *config.Config
	cleanupStop chan struct{}
	cleanupWG   sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

// libraryCleanupInterval is how often stale per-IP/per-tenant layer state is
// swept in library mode so long-running embedded processes don't accumulate
// unbounded rate-limit buckets, bot trackers, or ATO/IP-ACL entries.
var libraryCleanupInterval = 5 * time.Minute

// libraryCleanupMaxAge is the age past which idle tracked entries are evicted.
const libraryCleanupMaxAge = 30 * time.Minute

var (
	newInternalEngine   = engine.NewEngine
	newChallengeService = challenge.NewService
)

type staleCleaner interface{ CleanupExpired(time.Duration) }
type expiryCleaner interface{ CleanupExpired() }
type simpleCleaner interface{ Cleanup() }
type eventSubscriptionAcceptor interface {
	TrySubscribe(chan<- engine.Event) bool
}

// startCleanup launches the periodic layer-state cleanup goroutine.
func (e *Engine) startCleanup() {
	e.cleanupStop = make(chan struct{})
	e.cleanupWG.Add(1)
	go func() {
		defer e.cleanupWG.Done()
		ticker := time.NewTicker(libraryCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				e.runCleanup()
			case <-e.cleanupStop:
				return
			}
		}
	}()
}

// runCleanup sweeps stale state from the layers that accumulate per-key maps.
func (e *Engine) runCleanup() {
	if rl := e.internal.FindLayer("ratelimit"); rl != nil {
		if c, ok := rl.(staleCleaner); ok {
			c.CleanupExpired(libraryCleanupMaxAge)
		}
	}
	if acl := e.internal.FindLayer("ipacl"); acl != nil {
		if c, ok := acl.(expiryCleaner); ok {
			c.CleanupExpired()
		}
	}
	if ato := e.internal.FindLayer("ato_protection"); ato != nil {
		if c, ok := ato.(simpleCleaner); ok {
			c.Cleanup()
		}
	}
	if bot := e.internal.FindLayer("botdetect"); bot != nil {
		if c, ok := bot.(simpleCleaner); ok {
			c.Cleanup()
		}
	}
}

// wireChallengeService builds and registers the challenge service when the
// config enables it. Shared by New and NewFromFile so both constructors
// honor challenge.enabled — without this, NewFromFile silently degraded
// every ActionChallenge verdict to the block fallback in Middleware.
func wireChallengeService(eng *engine.Engine, cfg *config.Config) error {
	if !cfg.WAF.Challenge.Enabled {
		return nil
	}
	chCfg := challenge.Config{
		Enabled:    true,
		Difficulty: cfg.WAF.Challenge.Difficulty,
		CookieTTL:  cfg.WAF.Challenge.CookieTTL,
		CookieName: cfg.WAF.Challenge.CookieName,
	}
	if cfg.WAF.Challenge.SecretKey != "" {
		chCfg.SecretKey = []byte(cfg.WAF.Challenge.SecretKey)
	}
	chCfg.ClientIPExtractor = engine.ExtractClientIP
	challengeSvc, err := newChallengeService(chCfg)
	if err != nil {
		return fmt.Errorf("creating challenge service: %w", err)
	}
	eng.SetChallengeService(challengeSvc)
	return nil
}

// New creates a new WAF engine with the given configuration.
func New(cfg Config, opts ...Option) (*Engine, error) {
	internalCfg := convertConfig(cfg)

	for _, opt := range opts {
		opt(internalCfg)
	}
	if err := config.Validate(internalCfg); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	store := events.NewMemoryStore(internalCfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := newInternalEngine(internalCfg, store, bus)
	if err != nil {
		return nil, fmt.Errorf("creating engine: %w", err)
	}

	if err := addDefaultLayers(eng, internalCfg); err != nil {
		_ = stopLibraryLayers(eng)
		_ = eng.Close()
		return nil, err
	}

	if err := wireChallengeService(eng, internalCfg); err != nil {
		_ = stopLibraryLayers(eng)
		_ = eng.Close()
		return nil, err
	}

	e := &Engine{internal: eng, cfg: internalCfg}
	e.startCleanup()
	return e, nil
}

// NewFromFile creates a new WAF engine from a YAML config file.
func NewFromFile(path string, opts ...Option) (*Engine, error) {
	cfg, err := config.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading config file %q: %w", path, err)
	}
	if envErr := config.LoadEnv(cfg); envErr != nil {
		return nil, fmt.Errorf("loading environment configuration: %w", envErr)
	}

	for _, opt := range opts {
		opt(cfg)
	}
	if validateErr := config.Validate(cfg); validateErr != nil {
		return nil, fmt.Errorf("validating configuration: %w", validateErr)
	}

	store := events.NewMemoryStore(cfg.Events.MaxEvents)
	bus := events.NewEventBus()
	eng, err := newInternalEngine(cfg, store, bus)
	if err != nil {
		return nil, fmt.Errorf("creating engine: %w", err)
	}

	if err := addDefaultLayers(eng, cfg); err != nil {
		_ = stopLibraryLayers(eng)
		_ = eng.Close()
		return nil, err
	}

	if err := wireChallengeService(eng, cfg); err != nil {
		_ = stopLibraryLayers(eng)
		_ = eng.Close()
		return nil, err
	}

	e := &Engine{internal: eng, cfg: cfg}
	e.startCleanup()
	return e, nil
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
// A panicking callback is recovered per event, so the pump survives and
// subsequent events keep flowing — a goroutine-scope recover here let one
// panic end the pump permanently, silently dropping every later event for
// the subscriber (the bus drops on full channels).
func (e *Engine) OnEvent(fn func(Event)) {
	ch := make(chan engine.Event, 64)
	bus := e.internal.EventBus()
	if acceptor, ok := bus.(eventSubscriptionAcceptor); ok {
		if !acceptor.TrySubscribe(ch) {
			return
		}
	} else {
		bus.Subscribe(ch)
	}
	go func() {
		for event := range ch {
			invokeEventCallback(fn, event)
		}
	}()
}

// invokeEventCallback calls fn with per-invocation panic isolation: a panic
// in user callback code must end neither the pump nor event delivery.
func invokeEventCallback(fn func(Event), event Event) {
	defer func() {
		if r := recover(); r != nil {
			slog.Default().Error("GuardianWAF event callback panic recovered", "panic", r)
		}
	}()
	fn(event)
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
	e.closeOnce.Do(func() {
		if e.cleanupStop != nil {
			close(e.cleanupStop)
			e.cleanupWG.Wait()
		}
		e.closeErr = errors.Join(stopLibraryLayers(e.internal), e.internal.Close())
	})
	return e.closeErr
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
	detectors := c.WAF.Detection.Detectors
	detectors["sqli"] = toInternalDetector(cfg.Detection.SQLi, true)
	detectors["xss"] = toInternalDetector(cfg.Detection.XSS, true)
	detectors["lfi"] = toInternalDetector(cfg.Detection.PathTraversal, true)
	detectors["cmdi"] = toInternalDetector(cfg.Detection.CmdInjection, true)
	detectors["xxe"] = toInternalDetector(cfg.Detection.XXE, true)
	detectors["ssrf"] = toInternalDetector(cfg.Detection.SSRF, true)
	detectors["ssti"] = toInternalDetector(cfg.Detection.SSTI, true)
	detectors["nosqli"] = toInternalDetector(cfg.Detection.NoSQLi, true)
	detectors["smuggling"] = toInternalDetector(cfg.Detection.Smuggling, true)
	detectors["openredirect"] = toInternalDetector(cfg.Detection.OpenRedirect, true)
	detectors["graphql"] = toInternalDetector(cfg.Detection.GraphQL, true)

	for _, exc := range cfg.Detection.Exclusions {
		c.WAF.Detection.Exclusions = append(c.WAF.Detection.Exclusions, config.ExclusionConfig{
			Path:      exc.Path,
			Detectors: exc.Detectors,
			Reason:    exc.Reason,
		})
	}

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
	} else {
		c.WAF.RateLimit.Enabled = false
	}

	// Bot detection. The public BotConfig has no independent mode, so inherit
	// the global WAF mode. Otherwise New(ModeEnforce) leaves the bot layer in
	// the internal default "monitor" mode and its block/challenge actions are
	// unreachable for programmatic users.
	if cfg.Bot.Enabled {
		c.WAF.BotDetection.Enabled = true
		if c.Mode == ModeEnforce {
			c.WAF.BotDetection.Mode = ModeEnforce
		} else {
			c.WAF.BotDetection.Mode = ModeMonitor
		}
	} else {
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
	if event == nil {
		return Result{}
	}
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

// addDefaultLayers uses the same builders as standalone mode. Reject enabled
// layers requiring standalone services rather than silently dropping protection.
func addDefaultLayers(eng *engine.Engine, cfg *config.Config) error {
	supported := map[string]bool{
		"ip_acl": true, "rate_limit": true, "api_security": true,
		"sanitizer": true, "detection": true, "bot_detection": true, "response": true,
	}
	for _, d := range layerregistry.DefaultRegistry() {
		if !supported[d.Name] && d.Enabled(cfg) {
			return fmt.Errorf("WAF layer %q is not supported in library mode; use guardianwaf serve or disable this layer", d.Name)
		}
	}
	buildCtx := &layerregistry.BuildContext{}
	for _, d := range layerregistry.DefaultRegistry() {
		if !supported[d.Name] {
			continue
		}
		layer, ok, err := layerregistry.BuildLayerWithContext(d.Name, cfg, buildCtx)
		if err != nil {
			return err
		}
		if ok {
			eng.AddLayer(layer)
		}
	}
	return nil
}

// stopLibraryLayers releases background persistence and JWKS refresh workers,
// including when a later builder or challenge-service constructor fails.
func stopLibraryLayers(eng *engine.Engine) error {
	var errs []error
	for _, name := range []string{"api_security", "ipacl"} {
		layer := eng.FindLayer(name)
		if stopper, ok := layer.(interface{ StopWithContext(context.Context) error }); ok {
			errs = append(errs, stopper.StopWithContext(context.Background()))
		} else if stopper, ok := layer.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}
	return errors.Join(errs...)
}
