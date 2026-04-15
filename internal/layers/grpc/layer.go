package grpc

import (
	"fmt"
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"time"
)

// Layer provides gRPC security as a WAF layer.
type Layer struct {
	security *Security
	config   *config.GRPCConfig
}

// NewLayer creates a new gRPC security layer.
func NewLayer(cfg *config.GRPCConfig) (*Layer, error) {
	if cfg == nil {
		cfg = &config.GRPCConfig{}
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
	return "grpc"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 78
}

// Process implements the layer interface.
// Validates gRPC requests and enforces security policies.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	result := engine.LayerResult{
		Action: engine.ActionPass,
	}

	if !l.config.Enabled || l.security == nil {
		result.Duration = time.Since(start)
	return result
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.GRPC.Enabled {
		result.Duration = time.Since(start)
	return result
	}

	// Check if this is a gRPC request
	if !IsGRPCRequest(ctx.Request) {
		result.Duration = time.Since(start)
	return result
	}

	// Validate the request
	if err := l.security.ValidateRequest(ctx.Request); err != nil {
		result.Action = engine.ActionBlock
		result.Score = 100
		result.Findings = append(result.Findings, engine.Finding{
			DetectorName: "grpc",
			Category:     "protocol",
			Description:  fmt.Sprintf("gRPC validation failed: %v", err),
			Severity:     engine.SeverityHigh,
		})
		result.Duration = time.Since(start)
	return result
	}

	result.Duration = time.Since(start)
	return result
}

// GetSecurity returns the gRPC security instance.
func (l *Layer) GetSecurity() *Security {
	return l.security
}

// Stop stops the layer.
func (l *Layer) Stop() {
	if l.security != nil {
		l.security.Stop()
	}
}

// IsGRPCRequest checks if a request is a gRPC request.
func (l *Layer) IsGRPCRequest(r *http.Request) bool {
	return IsGRPCRequest(r)
}

// GetRequestInfo extracts gRPC request info.
func (l *Layer) GetRequestInfo(r *http.Request) *RequestInfo {
	return GetRequestInfo(r)
}
