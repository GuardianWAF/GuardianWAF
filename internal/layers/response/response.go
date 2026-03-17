package response

import (
	"time"

	"github.com/ersinkoc/guardianwaf/internal/engine"
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
func NewLayer(cfg Config) *Layer {
	return &Layer{config: cfg}
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "response"
}

// Process stores the response configuration in context metadata for use
// during response writing. The response layer is a post-processing layer
// that does not block requests.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Store the config in context metadata for use by the response writer
	ctx.Metadata["response_config"] = l.config

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
