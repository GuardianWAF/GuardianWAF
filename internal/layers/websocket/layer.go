package websocket

import (
	"fmt"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"time"
)

// Layer provides WebSocket security as a WAF layer.
type Layer struct {
	security *Security
	config   *Config
}

// NewLayer creates a new WebSocket security layer.
func NewLayer(cfg *Config) (*Layer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	security, err := NewSecurity(cfg)
	if err != nil {
		return nil, err
	}

	return &Layer{
		security: security,
		config:   cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "websocket"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 76
}

// Process implements the layer interface.
// Validates WebSocket handshake requests.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	result := engine.LayerResult{
		Action: engine.ActionPass,
	}

	if !l.config.Enabled || l.security == nil {
		result.Duration = time.Since(start)
	return result
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.WebSocket.Enabled {
		result.Duration = time.Since(start)
	return result
	}

	// Check if this is a WebSocket upgrade request
	if !isWebSocketUpgrade(ctx.Request) {
		result.Duration = time.Since(start)
	return result
	}

	// Validate the handshake
	if err := l.security.ValidateHandshake(ctx.Request); err != nil {
		result.Action = engine.ActionBlock
		result.Score = 100
		result.Findings = append(result.Findings, engine.Finding{
			DetectorName: "websocket",
			Category:     "protocol",
			Description:  fmt.Sprintf("Invalid WebSocket handshake: %v", err),
			Severity:     engine.SeverityHigh,
		})
		result.Duration = time.Since(start)
	return result
	}

	// Check connection limit
	ip := getClientIP(ctx.Request)
	if l.security.getConnectionCountForIP(ip) >= l.config.MaxConcurrentPerIP {
		result.Action = engine.ActionBlock
		result.Score = 100
		result.Findings = append(result.Findings, engine.Finding{
			DetectorName: "websocket",
			Category:     "rate_limit",
			Description:  fmt.Sprintf("Max concurrent WebSocket connections reached for IP: %s", ip),
			Severity:     engine.SeverityMedium,
		})
		result.Duration = time.Since(start)
	return result
	}

	result.Duration = time.Since(start)
	return result
}

// GetSecurity returns the WebSocket security instance.
func (l *Layer) GetSecurity() *Security {
	return l.security
}

// Stop stops the layer.
func (l *Layer) Stop() {
	if l.security != nil {
		l.security.Stop()
	}
}
