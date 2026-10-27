package sanitizer

import (
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
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

// InspectionBodyLimit publishes the request's effective size limit before
// the engine reads the body, using exactly the sanitizer's path view.
func (l *Layer) InspectionBodyLimit(path string, tenant *config.WAFConfig) int64 {
	if !l.config.SkipNormalization {
		path = NormalizeAll(path)
	}
	if tenant == nil {
		return l.config.effectiveMaxBodySize(path)
	}
	limit, matched := tenant.Sanitizer.MaxBodySize, 0
	for _, override := range tenant.Sanitizer.PathOverrides {
		if override.Path != "" && strings.HasPrefix(path, override.Path) && len(override.Path) > matched {
			limit, matched = override.MaxBodySize, len(override.Path)
		}
	}
	return limit
}

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

	// Step 1: Normalize all inputs — gated by skip_normalization (the
	// layer view of normalize_encoding: false).
	//
	// With the gate on (normalize_encoding: false) the Normalized* fields
	// carry the RAW values unchanged — raw passthrough, never empty: ctx
	// fields are the shared detector view, and leaving them empty would
	// blind every downstream detector that reads them (the round-30
	// hop-by-hop lesson). Identical raw values dedup in the detectors'
	// both-forms scans, so coverage of unencoded payloads is unchanged;
	// percent/unicode-encoded payloads are accepted as-is — the documented
	// operator trade-off of the gate.
	if !l.config.SkipNormalization {
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
		// The engine reads only the effective per-path budget plus a sentinel.
		// Oversized bodies are rejected independently of their finding score;
		// the complete original stream is retained for monitor-mode forwarding.
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
	} else {
		ctx.NormalizedPath = ctx.Path
		ctx.NormalizedQuery = make(map[string][]string, len(ctx.QueryParams))
		for k, vs := range ctx.QueryParams {
			ctx.NormalizedQuery[k] = append([]string(nil), vs...)
		}
		ctx.NormalizedBody = ctx.BodyString
		ctx.NormalizedHeaders = make(map[string][]string, len(ctx.Headers))
		for k, vs := range ctx.Headers {
			ctx.NormalizedHeaders[k] = append([]string(nil), vs...)
		}
	}

	// Step 2: Validate
	validationConfig := l.config
	validationConfig.MaxBodySize = l.InspectionBodyLimit(ctx.Path, ctx.TenantWAFConfig)
	validationConfig.PathOverrides = nil
	findings := ValidateRequest(ctx, validationConfig)

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
	if maxBody := validationConfig.MaxBodySize; maxBody > 0 && int64(len(ctx.Body)) > maxBody {
		// A body limit is an inspection boundary, not a scoring hint: the
		// unread tail may contain an attack that no detector could inspect.
		action = engine.ActionBlock
		ctx.BodyLimitExceeded = true
	} else if totalScore >= 50 {
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
