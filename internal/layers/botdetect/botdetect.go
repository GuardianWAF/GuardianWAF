package botdetect

import (
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
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
}

// NewLayer creates a new bot detection layer with the given configuration.
func NewLayer(cfg Config) *Layer {
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
		config:   cfg,
		behavior: bm,
	}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "botdetect"
}

// Process analyzes the request for bot indicators using JA3 fingerprinting,
// User-Agent analysis, and behavioral patterns.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	start := time.Now()
	var findings []engine.Finding
	totalScore := 0

	// 1. TLS Fingerprint analysis
	if l.config.TLSFingerprint.Enabled && ctx.TLSVersion > 0 {
		fpScore, fpFindings := l.analyzeTLSFingerprint(ctx)
		totalScore += fpScore
		findings = append(findings, fpFindings...)
	}

	// 2. User-Agent analysis
	if l.config.UserAgent.Enabled {
		uaScore, uaFindings := l.analyzeUA(ctx)
		totalScore += uaScore
		findings = append(findings, uaFindings...)
	}

	// 3. Behavioral analysis
	if l.config.Behavior.Enabled && l.behavior != nil {
		ip := ""
		if ctx.ClientIP != nil {
			ip = ctx.ClientIP.String()
		}
		if ip != "" {
			// Record this request
			l.behavior.Record(ip, ctx.Path, false, time.Since(ctx.StartTime))

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
		if l.config.Mode == "enforce" {
			if totalScore >= 80 {
				action = engine.ActionBlock
			} else if totalScore >= 40 {
				action = engine.ActionChallenge
			} else {
				action = engine.ActionLog
			}
		} else {
			// Monitor mode: log only
			action = engine.ActionLog
		}
	}

	// Add findings to the request context accumulator
	for _, f := range findings {
		ctx.Accumulator.Add(f)
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
		Duration: time.Since(start),
	}
}

// analyzeTLSFingerprint checks the TLS fingerprint against the database.
func (l *Layer) analyzeTLSFingerprint(ctx *engine.RequestContext) (int, []engine.Finding) {
	// Build a JA3 fingerprint from what we have in context.
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
			Description:  "TLS fingerprint matched: " + info.Name + " (" + info.Category.String() + ")",
			MatchedValue: fp.Hash,
			Location:     "tls",
			Confidence:   0.8,
		}}
	}

	return 0, nil
}

// analyzeUA runs User-Agent analysis and returns score and findings.
func (l *Layer) analyzeUA(ctx *engine.RequestContext) (int, []engine.Finding) {
	ua := ""
	if vals, ok := ctx.Headers["User-Agent"]; ok && len(vals) > 0 {
		ua = vals[0]
	}

	score, desc := AnalyzeUserAgent(ua)
	if score == 0 {
		return 0, nil
	}

	// Apply config filters
	if ua == "" && !l.config.UserAgent.BlockEmpty {
		return 0, nil
	}

	severity := engine.SeverityLow
	if score >= 80 {
		severity = engine.SeverityHigh
	} else if score >= 40 {
		severity = engine.SeverityMedium
	}

	return score, []engine.Finding{{
		DetectorName: "botdetect-ua",
		Category:     "bot",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: truncateUA(ua, 200),
		Location:     "header",
		Confidence:   0.6,
	}}
}

// truncateUA truncates a user-agent string for finding evidence.
func truncateUA(ua string, maxLen int) string {
	if len(ua) <= maxLen {
		return ua
	}
	if maxLen <= 3 {
		return ua[:maxLen]
	}
	return ua[:maxLen-3] + "..."
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
