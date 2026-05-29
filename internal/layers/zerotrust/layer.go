package zerotrust

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer wraps a Zero Trust Service as an engine.Layer for pipeline integration.
type Layer struct {
	service *Service
}

// NewLayer creates a pipeline layer from a Zero Trust Service.
func NewLayer(service *Service) *Layer {
	return &Layer{service: service}
}

// Name returns the layer name.
func (l *Layer) Name() string { return "zero_trust" }
func (l *Layer) Order() int { return engine.OrderZeroTrust }

// Process validates Zero Trust identity for the request.
// If Zero Trust is disabled, passes immediately. If the request lacks a valid
// session or client certificate and mTLS is required, the request is blocked.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if l.service == nil || !l.service.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Check bypass paths
	for _, p := range l.service.config.AllowBypassPaths {
		if ctx.Path == p {
			return engine.LayerResult{Action: engine.ActionPass}
		}
	}

	// Try session-based authentication from header
	var sessionID string
	if v := ctx.Headers["X-Zerotrust-Session"]; len(v) > 0 {
		sessionID = v[0]
	}
	if sessionID != "" {
		identity := l.service.GetClientIdentity(sessionID)
		if identity != nil {
			if err := l.service.CheckAccess(identity, ctx.Path); err != nil {
				return engine.LayerResult{
					Action: engine.ActionBlock,
					Findings: []engine.Finding{{
						DetectorName: "zero_trust",
						Category:     "access_control",
						Severity:     engine.SeverityHigh,
						Score:        80,
						Description:  "access denied: " + err.Error(),
						Location:     "path",
					}},
				}
			}
			// Store trust level in metadata for downstream layers
			if ctx.Metadata == nil {
				ctx.Metadata = make(map[string]any)
			}
			ctx.Metadata["zt_trust_level"] = identity.TrustLevel.String()
			ctx.Metadata["zt_client_id"] = identity.ClientID
			return engine.LayerResult{Action: engine.ActionPass}
		}
	}

	// No valid session — if mTLS required, block
	if l.service.config.RequireMTLS {
		return engine.LayerResult{
			Action: engine.ActionBlock,
			Findings: []engine.Finding{{
				DetectorName: "zero_trust",
				Category:     "authentication",
				Severity:     engine.SeverityCritical,
				Score:        100,
				Description:  "mTLS client certificate required",
				Location:     "tls",
			}},
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}
