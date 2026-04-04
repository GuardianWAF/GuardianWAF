package sanitizer

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer implements the engine.Layer interface for request sanitization.
type Layer struct {
	config  Config
	enabled bool
}

// NewLayer creates a new sanitizer layer with the given configuration.
func NewLayer(cfg *Config) *Layer {
	return &Layer{
		config:  *cfg,
		enabled: true,
	}
}

// Name returns "sanitizer".
func (l *Layer) Name() string { return "sanitizer" }

// SetEnabled enables or disables the sanitizer layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.enabled = enabled
}

// Process normalizes and validates the request.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Step 1: Normalize all inputs
	ctx.NormalizedPath = NormalizeAll(ctx.Path)

	// Normalize query params
	ctx.NormalizedQuery = make(map[string][]string, len(ctx.QueryParams))
	for k, vs := range ctx.QueryParams {
		normalized := make([]string, len(vs))
		for i, v := range vs {
			normalized[i] = NormalizeAll(v)
		}
		ctx.NormalizedQuery[k] = normalized
	}

	// Normalize body
	ctx.NormalizedBody = NormalizeAll(ctx.BodyString)

	// Normalize headers
	ctx.NormalizedHeaders = make(map[string][]string, len(ctx.Headers))
	for k, vs := range ctx.Headers {
		normalized := make([]string, len(vs))
		for i, v := range vs {
			normalized[i] = NormalizeAll(v)
		}
		ctx.NormalizedHeaders[k] = normalized
	}

	// Step 2: Validate
	findings := ValidateRequest(ctx, l.config)

	// Step 3: Strip hop-by-hop if enabled
	if l.config.StripHopByHop {
		StripHopByHopHeaders(ctx)
	}

	// Determine action
	action := engine.ActionPass
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore >= 50 {
		action = engine.ActionBlock
	} else if len(findings) > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
	}
}
