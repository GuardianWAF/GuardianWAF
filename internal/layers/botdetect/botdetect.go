package botdetect

import (
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TLSFingerprintConfig controls TLS fingerprint analysis behavior.
type TLSFingerprintConfig struct {
	Enabled         bool
	KnownBotsAction string // "block" or "log"
	UnknownAction   string // "block", "log", or "pass"
	MismatchAction  string // "block" or "log"
}

// UAConfig controls User-Agent analysis behavior.
type UAConfig struct {
	Enabled            bool
	BlockEmpty         bool
	BlockKnownScanners bool
}

// BehaviorAnalysisConfig controls behavioral analysis.
type BehaviorAnalysisConfig struct {
	Enabled            bool
	Window             time.Duration
	RPSThreshold       int
	ErrorRateThreshold int
	UniquePathsPerMin  int
	TimingStdDevMs     int
}

// Config holds the full bot detection layer configuration.
type Config struct {
	Enabled        bool
	Mode           string // "monitor" or "enforce"
	TLSFingerprint TLSFingerprintConfig
	UserAgent      UAConfig
	Behavior       BehaviorAnalysisConfig
}

// DefaultConfig returns a default bot detection configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Mode:    "enforce",
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
		Behavior: BehaviorAnalysisConfig{
			Enabled:            true,
			Window:             60 * time.Second,
			RPSThreshold:       10,
			ErrorRateThreshold: 30,
			UniquePathsPerMin:  50,
			TimingStdDevMs:     10,
		},
	}
}

// Layer implements the bot detection WAF layer.
type Layer struct {
	config   Config
	behavior *BehaviorManager
	mu       sync.RWMutex
}

// NewLayer creates a new bot detection layer with the given configuration.
func NewLayer(cfg *Config) *Layer {
	var bm *BehaviorManager
	if cfg.Behavior.Enabled {
		bm = NewBehaviorManager(BehaviorConfig{
			Window:             cfg.Behavior.Window,
			RPSThreshold:       cfg.Behavior.RPSThreshold,
			UniquePathsPerMin:  cfg.Behavior.UniquePathsPerMin,
			ErrorRateThreshold: cfg.Behavior.ErrorRateThreshold,
			TimingStdDevMs:     cfg.Behavior.TimingStdDevMs,
		})
	}
	return &Layer{
		config:   *cfg,
		behavior: bm,
	}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "botdetect"
}

// Order returns the execution order.
func (l *Layer) Order() int { return engine.OrderBotDetect }

// Cleanup evicts stale behavioral trackers so the tracker map does not grow
// without bound over long uptimes. Safe to call when behavioral analysis is
// disabled (the manager is nil).
func (l *Layer) Cleanup() {
	if l.behavior != nil {
		l.behavior.Cleanup()
	}
}

// snapshotConfig returns a copy of the current config under RLock.
func (l *Layer) snapshotConfig() Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// Process analyzes the request for bot indicators using JA3 fingerprinting,
// User-Agent analysis, and behavioral patterns.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	// Check if bot detection is enabled (tenant config takes precedence)
	cfg := l.snapshotConfig()
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.BotDetection.Enabled {
		cfg.Enabled = false
	}
	if !cfg.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	start := time.Now()
	var findings []engine.Finding
	totalScore := 0

	// 1. TLS Fingerprint analysis
	if cfg.TLSFingerprint.Enabled && ctx.TLSVersion > 0 {
		fpScore, fpFindings := l.analyzeTLSFingerprint(ctx)
		totalScore += fpScore
		findings = append(findings, fpFindings...)
	}

	// 2. User-Agent analysis
	if cfg.UserAgent.Enabled {
		uaScore, uaFindings := l.analyzeUA(ctx)
		totalScore += uaScore
		findings = append(findings, uaFindings...)
	}

	// 3. Behavioral analysis
	if cfg.Behavior.Enabled && l.behavior != nil {
		ip := ""
		if ctx.ClientIP != nil {
			ip = ctx.ClientIP.String()
		}
		if ip != "" {
			// Record this request
			l.behavior.Record(ip, ctx.Path, false, time.Since(ctx.StartTime))

			// Register the post-response outcome hook: the outcome is unknown
			// here — every request is recorded as a non-error — so a failed
			// request is amended once the upstream status is known (see
			// markRequestOutcome). The closure captures the IP, never ctx: the
			// context returns to the pool before the upstream call.
			ctx.PostResponseHook = func(success bool) {
				l.markRequestOutcome(ip, success)
			}

			behaviorScore, behaviorDescs := l.behavior.Analyze(ip)
			if behaviorScore > 0 {
				totalScore += behaviorScore
				for _, desc := range behaviorDescs {
					findings = append(findings, engine.Finding{
						DetectorName: "botdetect-behavior",
						Category:     "bot",
						Severity:     scoreToBehaviorSeverity(behaviorScore),
						Score:        behaviorScore,
						Description:  desc,
						Location:     "behavior",
						Confidence:   0.7,
					})
				}
			}
		}
	}

	// Determine action based on score and mode
	action := engine.ActionPass
	if totalScore > 0 {
		switch cfg.Mode {
		case "enforce":
			switch {
			case totalScore >= 80:
				action = engine.ActionBlock
			case totalScore >= 40:
				action = engine.ActionChallenge
			default:
				action = engine.ActionLog
			}
		default:
			// Monitor mode: log only
			action = engine.ActionLog
		}
	}

	// Add findings to the request context accumulator
	for i := range findings {
		ctx.Accumulator.Add(&findings[i])
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
		Duration: time.Since(start),
	}
}

// analyzeTLSFingerprint checks the TLS fingerprint against the database.
// It uses JA4 when full ClientHello data is available, otherwise falls back to JA3.
// PostProcess amends the behavioral tracker once the response outcome is
// known: a failed request counts as an error for the error-rate analysis.
// Process records every request with isError=false because the outcome is
// unknown at request time; without this amendment the ErrorRateThreshold
// detection can never fire.
func (l *Layer) PostProcess(ctx *engine.RequestContext, success bool) {
	if !l.config.Enabled || !l.config.Behavior.Enabled {
		return
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.BotDetection.Enabled {
		return
	}
	if ctx.ClientIP == nil {
		return
	}
	l.markRequestOutcome(ctx.ClientIP.String(), success)
}

// markRequestOutcome counts a failed request for the error-rate analysis. It is
// the single implementation behind both PostProcess (embedder API) and the
// RequestContext.PostResponseHook that Process registers, so the live path and
// the exported method cannot drift apart.
func (l *Layer) markRequestOutcome(ip string, success bool) {
	if success || ip == "" {
		return
	}
	l.behavior.MarkError(ip)
}

func (l *Layer) analyzeTLSFingerprint(ctx *engine.RequestContext) (int, []engine.Finding) {
	// Try JA4 first if we have full ClientHello data
	if len(ctx.JA4Ciphers) > 0 {
		ja4fp := ComputeJA4(JA4Params{
			Protocol:         ctx.JA4Protocol,
			TLSVersion:       ctx.TLSVersion,
			SNI:              ctx.JA4SNI || ctx.ServerName != "",
			CipherSuites:     ctx.JA4Ciphers,
			Extensions:       ctx.JA4Exts,
			ALPN:             ctx.JA4ALPN,
			SignatureAlgs:    ctx.JA4SigAlgs,
			SupportedVersion: ctx.JA4Ver,
		})
		info := LookupJA4Fingerprint(ja4fp.Full)

		if info.Category != FingerprintUnknown && info.Score > 0 {
			severity := engine.SeverityMedium
			if info.Category == FingerprintBad {
				severity = engine.SeverityHigh
			}
			return info.Score, []engine.Finding{{
				DetectorName: "botdetect-ja4",
				Category:     "bot",
				Severity:     severity,
				Score:        info.Score,
				Description:  "TLS JA4 fingerprint matched: " + info.Name + " (" + info.Category.String() + ")",
				MatchedValue: ja4fp.Full,
				Location:     "tls",
				Confidence:   0.9, // Higher confidence for JA4
			}}
		}
		// If JA4 unknown, continue to try JA3
	}

	// Fall back to JA3 fingerprint from limited TLS data
	// In a real scenario, full ClientHello parameters would be available.
	// Here we use the TLS version and cipher suite as partial fingerprint data.
	fp := ComputeJA3(ctx.TLSVersion, []uint16{ctx.TLSCipherSuite}, nil, nil, nil)
	info := LookupFingerprint(fp.Hash)

	if info.Category == FingerprintUnknown {
		return 0, nil
	}

	if info.Score > 0 {
		severity := engine.SeverityMedium
		if info.Category == FingerprintBad {
			severity = engine.SeverityHigh
		}
		return info.Score, []engine.Finding{{
			DetectorName: "botdetect-ja3",
			Category:     "bot",
			Severity:     severity,
			Score:        info.Score,
			Description:  "TLS JA3 fingerprint matched: " + info.Name + " (" + info.Category.String() + ")",
			MatchedValue: fp.Hash,
			Location:     "tls",
			Confidence:   0.8,
		}}
	}

	return 0, nil
}

// analyzeUA runs User-Agent analysis and returns score and findings.
// The engine preserves EVERY transmitted User-Agent value, and backend
// parsers disagree on which one they surface (Go first-wins, PHP/Python
// last-wins) — scoring only vals[0] lets the attacker pick which UA the
// WAF sees by header ordering (the round-20/81 multi-value family). The
// strongest unsuppressed value wins, regardless of header ordering.
func (l *Layer) analyzeUA(ctx *engine.RequestContext) (int, []engine.Finding) {
	cfg := l.snapshotConfig()
	var uas []string
	if vals, ok := ctx.Headers["User-Agent"]; ok {
		uas = append(uas, vals...)
	}
	if len(uas) == 0 {
		// No User-Agent header at all: the server-side view is an empty
		// UA — keep scoring it so BlockEmpty still fires for missing
		// headers (the pre-fix semantic).
		uas = append(uas, "")
	}

	var bestScore int
	var bestFinding engine.Finding
	for _, ua := range uas {
		score, desc := AnalyzeUserAgent(ua)
		if score == 0 {
			continue
		}
		if ua == "" && !cfg.UserAgent.BlockEmpty {
			continue
		}
		if !cfg.UserAgent.BlockKnownScanners {
			if _, isScanner := matchKnownScanner(strings.ToLower(ua)); isScanner {
				// block_known_scanners: false — scanner UAs are detected but not
				// escalated to the block-tier score.
				continue
			}
		}
		if score <= bestScore {
			continue
		}

		severity := engine.SeverityLow
		if score >= 80 {
			severity = engine.SeverityHigh
		} else if score >= 40 {
			severity = engine.SeverityMedium
		}

		bestScore = score
		bestFinding = engine.Finding{
			DetectorName: "botdetect-ua",
			Category:     "bot",
			Severity:     severity,
			Score:        score,
			Description:  desc,
			MatchedValue: truncateUA(ua, 200),
			Location:     "header",
			Confidence:   0.6,
		}
	}

	if bestScore == 0 {
		return 0, nil
	}
	return bestScore, []engine.Finding{bestFinding}
}

// truncateUA truncates a user-agent string for finding evidence.
//
// MatchedValue carries a fully attacker-controlled, unbounded User-Agent into
// events, the dashboard, and traces. The previous `ua[:maxLen-3] + "..."` byte
// slice split any multi-byte rune straddling the cut and stored an invalid
// final sequence, and the engine's canonical re-truncation in
// ScoreAccumulator.Add could not repair it: TruncateEvidence returns early once
// len(s) <= maxLen, and maxLen-3 + len("...") == maxLen, so it was a no-op.
// Delegate to the shared rune-safe helper, matching the sibling detectors
// already fixed for this defect (xss, sqli, lfi, ssrf, xxe, sanitizer).
func truncateUA(ua string, maxLen int) string {
	return engine.TruncateEvidence(ua, maxLen)
}

// scoreToBehaviorSeverity maps a behavioral score to a severity level.
func scoreToBehaviorSeverity(score int) engine.Severity {
	switch {
	case score >= 80:
		return engine.SeverityHigh
	case score >= 40:
		return engine.SeverityMedium
	case score >= 20:
		return engine.SeverityLow
	default:
		return engine.SeverityInfo
	}
}

// BehaviorManager accessor for external use (e.g., recording errors).
func (l *Layer) BehaviorMgr() *BehaviorManager {
	return l.behavior
}
