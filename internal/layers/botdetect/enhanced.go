package botdetect

import (
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect/biometric"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect/challenge"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect/fingerprint"
)

// EnhancedConfig holds the enhanced bot detection configuration.
type EnhancedConfig struct {
	Enabled bool
	Mode    string // "monitor" or "enforce"

	// Existing features
	TLSFingerprint TLSFingerprintConfig
	UserAgent      UAConfig
	Behavior       BehaviorAnalysisConfig

	// New features
	Challenge        ChallengeConfig
	Biometric        BiometricConfig
	BrowserFingerprint BrowserFingerprintConfig
}

// ChallengeConfig for CAPTCHA providers.
type ChallengeConfig struct {
	Enabled   bool
	Provider  string // "hcaptcha" or "turnstile"
	SiteKey   string
	SecretKey string
	Timeout   time.Duration
}

// BiometricConfig for biometric detection.
type BiometricConfig struct {
	Enabled       bool
	MinEvents     int
	ScoreThreshold float64
	TimeWindow    time.Duration
}

// BrowserFingerprintConfig for browser fingerprinting.
type BrowserFingerprintConfig struct {
	Enabled          bool
	CheckCanvas      bool
	CheckWebGL       bool
	CheckFonts       bool
	CheckHeadless    bool
}

// DefaultEnhancedConfig returns default enhanced configuration.
func DefaultEnhancedConfig() EnhancedConfig {
	return EnhancedConfig{
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
		Challenge: ChallengeConfig{
			Enabled:  false,
			Provider: "hcaptcha",
			Timeout:  30 * time.Second,
		},
		Biometric: BiometricConfig{
			Enabled:        false,
			MinEvents:      20,
			ScoreThreshold: 50,
			TimeWindow:     5 * time.Minute,
		},
		BrowserFingerprint: BrowserFingerprintConfig{
			Enabled:       true,
			CheckCanvas:   true,
			CheckWebGL:    true,
			CheckFonts:    true,
			CheckHeadless: true,
		},
	}
}

// EnhancedLayer implements the enhanced bot detection layer.
type EnhancedLayer struct {
	config   EnhancedConfig
	behavior *BehaviorManager
	cfgMu    sync.RWMutex

	// New components
	challengeProvider challenge.Provider
	biometricDetector *biometric.Detector
	fingerprinter     *fingerprint.Fingerprinter

	// Session storage for biometric analysis
	sessions     map[string]*biometric.Session
	sessionsMu   sync.RWMutex
	sessionTTL   time.Duration
	maxSessions  int // cap to prevent OOM
}

// NewEnhancedLayer creates a new enhanced bot detection layer.
func NewEnhancedLayer(cfg *EnhancedConfig) *EnhancedLayer {
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

	l := &EnhancedLayer{
		config:      *cfg,
		behavior:    bm,
		sessions:    make(map[string]*biometric.Session),
		sessionTTL:  30 * time.Minute,
		maxSessions: 100000, // Cap at 100K sessions to prevent OOM
	}

	// Initialize challenge provider
	if cfg.Challenge.Enabled {
		switch cfg.Challenge.Provider {
		case "hcaptcha":
			l.challengeProvider = challenge.NewHCaptcha(challenge.HCaptchaConfig{
				SecretKey: cfg.Challenge.SecretKey,
				SiteKey:   cfg.Challenge.SiteKey,
				Timeout:   cfg.Challenge.Timeout,
			})
		case "turnstile":
			l.challengeProvider = challenge.NewTurnstile(challenge.TurnstileConfig{
				SecretKey: cfg.Challenge.SecretKey,
				SiteKey:   cfg.Challenge.SiteKey,
				Timeout:   cfg.Challenge.Timeout,
			})
		}
	}

	// Initialize biometric detector
	if cfg.Biometric.Enabled {
		l.biometricDetector = biometric.NewDetector()
	}

	// Initialize fingerprinter
	if cfg.BrowserFingerprint.Enabled {
		l.fingerprinter = fingerprint.New()
	}

	return l
}

// Name returns the layer name.
func (l *EnhancedLayer) Name() string {
	return "botdetect-enhanced"
}

// snapshotConfig returns a copy of the current config under RLock.
func (l *EnhancedLayer) snapshotConfig() EnhancedConfig {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()
	return l.config
}

// Process analyzes the request for bot indicators.
func (l *EnhancedLayer) Process(ctx *engine.RequestContext) engine.LayerResult {
	cfg := l.snapshotConfig()
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
		behaviorScore, behaviorFindings := l.analyzeBehavior(ctx)
		totalScore += behaviorScore
		findings = append(findings, behaviorFindings...)
	}

	// 4. Browser fingerprinting (NEW)
	if cfg.BrowserFingerprint.Enabled && l.fingerprinter != nil {
		fpData := l.fingerprinter.ExtractFromRequest(ctx.Request)
		fpAnalysis := l.fingerprinter.Analyze(fpData)

		if fpAnalysis.IsBot {
			totalScore += fpAnalysis.Score
			for _, indicator := range fpAnalysis.Indicators {
				findings = append(findings, engine.Finding{
					DetectorName: "botdetect-fingerprint",
					Category:     "bot",
					Severity:     engine.SeverityHigh,
					Score:        fpAnalysis.Score,
					Description:  "Browser fingerprint: " + indicator,
					Location:     "fingerprint",
					Confidence:   0.85,
				})
			}
		}
	}

	// 5. Biometric analysis (NEW) - if session data exists
	if cfg.Biometric.Enabled && l.biometricDetector != nil {
		sessionID := ctx.Request.Header.Get("X-Session-ID")
		if sessionID != "" {
			session := l.getSession(sessionID)
			if session != nil && len(session.MouseEvents) >= cfg.Biometric.MinEvents {
				bioAnalysis := l.biometricDetector.AnalyzeSession(session)
				if bioAnalysis.IsBot {
					totalScore += int(100 - bioAnalysis.HumanScore)
					for _, indicator := range bioAnalysis.Indicators {
						findings = append(findings, engine.Finding{
							DetectorName: "botdetect-biometric",
							Category:     "bot",
							Severity:     engine.SeverityHigh,
							Score:        int(100 - bioAnalysis.HumanScore),
							Description:  "Biometric: " + indicator.Description,
							Location:     "biometric",
							Confidence:   bioAnalysis.Confidence,
						})
					}
				}
			}
		}
	}

	// Determine action
	action := engine.ActionPass
	if totalScore > 0 {
		switch cfg.Mode {
		case "enforce":
			switch {
			case totalScore >= 80:
				action = engine.ActionBlock
			case totalScore >= 50:
				// Challenge if CAPTCHA is configured
				if cfg.Challenge.Enabled && l.challengeProvider != nil {
					action = engine.ActionChallenge
				} else {
					action = engine.ActionLog
				}
			default:
				action = engine.ActionLog
			}
		default:
			action = engine.ActionLog
		}
	}

	// Add findings
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

// VerifyCaptcha verifies a CAPTCHA token.
func (l *EnhancedLayer) VerifyCaptcha(token string, remoteIP string) (*challenge.VerificationResult, error) {
	if l.challengeProvider == nil {
		return nil, nil
	}
	return l.challengeProvider.VerifyToken(token, remoteIP)
}

// GetCaptchaSiteKey returns the CAPTCHA site key.
func (l *EnhancedLayer) GetCaptchaSiteKey() string {
	if l.challengeProvider == nil {
		return ""
	}
	return l.challengeProvider.GetSiteKey()
}

// RecordBiometricEvent records a biometric event for a session.
func (l *EnhancedLayer) RecordBiometricEvent(sessionID string, event any) {
	l.sessionsMu.Lock()
	defer l.sessionsMu.Unlock()

	session, exists := l.sessions[sessionID]
	if !exists {
		// Enforce session cap to prevent OOM
		if l.maxSessions > 0 && len(l.sessions) >= l.maxSessions {
			return
		}
		session = &biometric.Session{
			ID:        sessionID,
			CreatedAt: time.Now(),
		}
		l.sessions[sessionID] = session
	}

	// Cap events per session to prevent memory exhaustion from a single session
	const maxEventsPerSession = 10000
	switch e := event.(type) {
	case biometric.MouseEvent:
		if len(session.MouseEvents) < maxEventsPerSession {
			session.MouseEvents = append(session.MouseEvents, e)
		}
	case biometric.KeyEvent:
		if len(session.KeyEvents) < maxEventsPerSession {
			session.KeyEvents = append(session.KeyEvents, e)
		}
	case biometric.ScrollEvent:
		if len(session.ScrollEvents) < maxEventsPerSession {
			session.ScrollEvents = append(session.ScrollEvents, e)
		}
	}
}

// getSession retrieves a session.
func (l *EnhancedLayer) getSession(sessionID string) *biometric.Session {
	l.sessionsMu.RLock()
	defer l.sessionsMu.RUnlock()

	session, exists := l.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check TTL
	if time.Since(session.CreatedAt) > l.sessionTTL {
		return nil
	}

	return session
}

// CleanupSessions removes expired sessions.
func (l *EnhancedLayer) CleanupSessions() {
	l.sessionsMu.Lock()
	defer l.sessionsMu.Unlock()

	for id, session := range l.sessions {
		if time.Since(session.CreatedAt) > l.sessionTTL {
			delete(l.sessions, id)
		}
	}
}

// analyzeTLSFingerprint analyzes TLS fingerprint.
func (l *EnhancedLayer) analyzeTLSFingerprint(ctx *engine.RequestContext) (int, []engine.Finding) {
	// Use existing implementation from botdetect.go
	// This is a simplified version
	return 0, nil
}

// analyzeUA analyzes User-Agent.
func (l *EnhancedLayer) analyzeUA(ctx *engine.RequestContext) (int, []engine.Finding) {
	ua := ""
	if vals, ok := ctx.Headers["User-Agent"]; ok && len(vals) > 0 {
		ua = vals[0]
	}

	score, desc := AnalyzeUserAgent(ua)
	if score == 0 {
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
		Location:     "header",
		Confidence:   0.6,
	}}
}

// analyzeBehavior analyzes behavioral patterns.
func (l *EnhancedLayer) analyzeBehavior(ctx *engine.RequestContext) (int, []engine.Finding) {
	ip := ""
	if ctx.ClientIP != nil {
		ip = ctx.ClientIP.String()
	}
	if ip == "" {
		return 0, nil
	}

	l.behavior.Record(ip, ctx.Path, false, time.Since(ctx.StartTime))

	behaviorScore, behaviorDescs := l.behavior.Analyze(ip)
	if behaviorScore == 0 {
		return 0, nil
	}

	var findings []engine.Finding
	for _, desc := range behaviorDescs {
		findings = append(findings, engine.Finding{
			DetectorName: "botdetect-behavior",
			Category:     "bot",
			Severity:     scoreToSeverity(behaviorScore),
			Score:        behaviorScore,
			Description:  desc,
			Location:     "behavior",
			Confidence:   0.7,
		})
	}

	return behaviorScore, findings
}

// scoreToSeverity maps score to severity.
func scoreToSeverity(score int) engine.Severity {
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
