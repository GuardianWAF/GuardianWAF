package response

import (
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Config holds the response protection layer configuration.
type Config struct {
	SecurityHeadersEnabled bool
	Headers                SecurityHeaders
	DataMaskingEnabled     bool
	MaskCreditCards        bool
	MaskSSN                bool
	MaskAPIKeys            bool
	StripStackTraces       bool
	ErrorPageMode          string // "production" or "development"
}

// DefaultConfig returns a default response protection configuration.
func DefaultConfig() Config {
	return Config{
		SecurityHeadersEnabled: true,
		Headers:                DefaultSecurityHeaders(),
		DataMaskingEnabled:     true,
		MaskCreditCards:        true,
		MaskSSN:                true,
		MaskAPIKeys:            true,
		StripStackTraces:       true,
		ErrorPageMode:          "production",
	}
}

// Layer implements the response protection WAF layer.
type Layer struct {
	config Config
}

// NewLayer creates a new response protection layer with the given configuration.
func NewLayer(cfg *Config) *Layer {
	return &Layer{config: *cfg}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "response"
}

// Order returns the execution order.
func (l *Layer) Order() int { return engine.OrderResponse }

// Process stores the response configuration and a header-application hook
// in context metadata. The engine's Middleware calls the hook to inject
// security headers into every response (both blocked and passed).
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Use tenant config if available, otherwise use global config
	cfg := l.config
	if ctx.TenantWAFConfig != nil {
		tenantResp := &ctx.TenantWAFConfig.Response
		// Tenant can disable security headers via config
		if !tenantResp.SecurityHeaders.Enabled {
			cfg.SecurityHeadersEnabled = false
		}
		// Tenant can disable data masking via config
		if !tenantResp.DataMasking.Enabled {
			cfg.DataMaskingEnabled = false
		}
	}

	// Store the config in context metadata for use by the response writer
	ctx.Metadata["response_config"] = cfg

	// Register a masking function for the engine to apply to response bodies.
	// Uses func(string) string to avoid circular imports between engine and response.
	if cfg.DataMaskingEnabled {
		ctx.ResponseMaskFn = func(body string) string {
			return l.applyMasking(body)
		}
	}

	// Register a hook that the engine middleware will call to apply headers.
	// This avoids circular imports: the engine calls the hook via func type,
	// without importing the response package.
	if cfg.SecurityHeadersEnabled {
		headers := cfg.Headers
		ctx.ResponseHook = func(w http.ResponseWriter) {
			headers.Apply(w)
		}
	}

	return engine.LayerResult{
		Action:   engine.ActionPass,
		Duration: time.Since(start),
	}
}

// ApplyToResponse applies all configured response protections to a response body.
// This is called during response writing, not during layer processing.
func (l *Layer) ApplyToResponse(body string) string {
	if !l.config.DataMaskingEnabled {
		return body
	}
	return l.applyMasking(body)
}

// applyMasking applies all enabled masking patterns to the body.
func (l *Layer) applyMasking(body string) string {
	result := body
	if l.config.MaskCreditCards {
		result = MaskCreditCards(result)
	}
	if l.config.MaskSSN {
		result = MaskSSN(result)
	}
	if l.config.MaskAPIKeys {
		result = MaskAPIKeys(result)
	}
	if l.config.StripStackTraces {
		result = StripStackTraces(result)
	}
	return result
}

// GetConfig returns the layer configuration.
func (l *Layer) GetConfig() Config {
	return l.config
}
