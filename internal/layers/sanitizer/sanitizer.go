package sanitizer

import (
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer implements the engine.Layer interface for request sanitization.
type Layer struct {
	config  Config
	enabled bool
	mu      sync.RWMutex
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
func (l *Layer) Order() int   { return engine.OrderSanitizer }

// SetEnabled enables or disables the sanitizer layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.mu.Lock()
	l.enabled = enabled
	l.mu.Unlock()
}

// Process normalizes and validates the request.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Check if sanitizer is enabled (tenant config takes precedence)
	l.mu.RLock()
	enabled := l.enabled
	l.mu.RUnlock()
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.Sanitizer.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
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

	// Normalize body.
	//
	// NOTE (measured): NormalizeAll is a multi-pass decoder allocating ~17x its
	// input — 1 MiB of "/" costs 12.3 ms and 17.8 MB (BenchmarkNormalizeAllLarge).
	// The engine reads up to waf.max_body_size (10 MiB default) while the
	// sanitizer's own max_body_size defaults to 1 MiB, so a 10 MiB body of "/"
	// costs roughly 123 ms and 178 MB here before ValidateRequest below ever
	// checks the size.
	//
	// Skipping normalization for over-limit bodies was tried and reverted: an
	// oversized body scores 40, which is under the block threshold, so it is
	// only logged and still proxied. Not normalizing it would leave
	// NormalizedBody empty and blind every detector that reads it for bodies
	// between the two limits — trading a capacity problem for a detection gap.
	// Closing this properly needs a policy decision (block on oversize, or
	// lower the engine's read cap), not a silent change here.
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

	// NOTE: hop-by-hop stripping (strip_hop_by_hop) previously mutated
	// ctx.Headers here. That blinded the order-400 smuggling detector (it
	// reads ctx.Headers["Transfer-Encoding"] for four of its five vectors)
	// while never affecting what the backend receives — the reverse proxy
	// forwards the original *http.Request and never reads ctx.Headers. The
	// mutation was removed; hop-by-hop removal toward the backend needs
	// proxy-forward-side wiring if it is ever wanted.

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
		Duration: time.Since(start),
	}
}
