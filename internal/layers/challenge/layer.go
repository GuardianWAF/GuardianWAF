package challenge

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer wraps ChallengeService as an engine.Layer.
// It runs at Order 430 — between VirtualPatch and ML Anomaly — checking for
// a valid challenge cookie and returning ActionChallenge if no valid cookie
// is present. The engine's challenge service handles serving the challenge page.
type Layer struct {
	svc    *Service
	config *Config
}

// NewLayer creates a new challenge layer.
func NewLayer(cfg *Config) (*Layer, error) {
	if cfg == nil {
		cfg = &Config{Enabled: false}
	}

	svc, err := NewService(*cfg)
	if err != nil {
		return nil, err
	}

	return &Layer{
		svc:    svc,
		config: cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "js-challenge"
}

// Order returns the layer execution order.
func (l *Layer) Order() int {
	return 430
}

// Process checks for a valid challenge cookie.
// Returns ActionPass if a valid cookie is present (user solved challenge).
// Returns ActionChallenge if no valid cookie (browser must solve proof-of-work).
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	result := engine.LayerResult{Action: engine.ActionPass}

	if !l.config.Enabled || l.svc == nil {
		return result
	}

	if ctx.Request == nil {
		return result
	}

	// Check if valid challenge cookie is present
	if l.svc.HasValidCookie(ctx.Request, ctx.ClientIP) {
		// Valid cookie — user already solved challenge, allow through
		return result
	}

	// No valid cookie — require challenge
	result.Action = engine.ActionChallenge
	result.Score = 40
	result.Findings = append(result.Findings, engine.Finding{
		DetectorName: "js-challenge",
		Category:     "bot",
		Severity:     engine.SeverityMedium,
		Score:         40,
		Description:  "No valid challenge cookie — browser must solve proof-of-work",
	})

	return result
}

// Service returns the underlying challenge service (for HTTP handler wiring).
func (l *Layer) Service() *Service {
	return l.svc
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)
