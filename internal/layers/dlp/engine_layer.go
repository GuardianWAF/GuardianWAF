package dlp

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// EngineLayer wraps the DLP layer for use with the WAF engine.
// This satisfies the engine.Layer interface.
type EngineLayer struct {
	*Layer
}

// NewEngineLayer creates a new DLP layer compatible with the engine.
func NewEngineLayer(cfg *Config) *EngineLayer {
	return &EngineLayer{
		Layer: NewLayer(cfg),
	}
}

// Process implements the engine.Layer interface.
// Note: DLP is typically applied to request/response bodies, so this
// processes the request context and adds findings if PII is detected.
func (el *EngineLayer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !el.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Scan request body if present
	if len(ctx.Body) > 0 && el.scanRequest {
		// Check for file uploads
		contentType := ctx.Headers["Content-Type"]
		if len(contentType) > 0 && el.config.ScanFileUploads {
			result, err := el.Layer.ScanFileUploads(ctx.Body, contentType[0])
			if err == nil && !result.Safe {
				return el.handleScanResult(ctx, result, "file_upload")
			}
		}

		// Scan regular content
		result := el.scanContent(string(ctx.Body))
		if !result.Safe {
			return el.handleScanResult(ctx, result, "body")
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

// handleScanResult processes scan results and returns appropriate LayerResult.
func (el *EngineLayer) handleScanResult(ctx *engine.RequestContext, result *ScanResult, location string) engine.LayerResult {
	// Add findings to context
	for _, match := range result.Matches {
		severity := el.convertSeverity(match.Severity)
		finding := &engine.Finding{
			DetectorName: "dlp",
			Category:     string(match.Type),
			Severity:     severity,
			Score:        el.severityToScore(match.Severity),
			Description:  el.formatFindingDescription(match),
			Location:     location,
			Confidence:   1.0,
		}
		ctx.Accumulator.Add(finding)
	}

	// Block if configured
	if el.config.BlockOnMatch && result.RiskScore >= 50 {
		return engine.LayerResult{
			Action: engine.ActionBlock,
			Score:  result.RiskScore,
		}
	}

	// Log if significant risk
	if result.RiskScore >= 25 {
		return engine.LayerResult{
			Action: engine.ActionLog,
			Score:  result.RiskScore,
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

// convertSeverity converts DLP severity to engine severity.
func (el *EngineLayer) convertSeverity(severity Severity) engine.Severity {
	switch severity {
	case SeverityCritical:
		return engine.SeverityCritical
	case SeverityHigh:
		return engine.SeverityHigh
	case SeverityMedium:
		return engine.SeverityMedium
	case SeverityLow:
		return engine.SeverityLow
	default:
		return engine.SeverityInfo
	}
}

// severityToScore converts DLP severity to engine score.
func (el *EngineLayer) severityToScore(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 40
	case SeverityHigh:
		return 30
	case SeverityMedium:
		return 15
	case SeverityLow:
		return 5
	default:
		return 10
	}
}

// formatFindingDescription creates a human-readable finding description.
func (el *EngineLayer) formatFindingDescription(match Match) string {
	return "Detected " + string(match.Type) + " (" + match.Masked + ")"
}

// ScanHTTPRequest scans an HTTP request for PII (for use outside the engine).
func (el *EngineLayer) ScanHTTPRequest(r *http.Request) (*ScanResult, error) {
	return el.Layer.ScanRequest(r)
}

// ScanHTTPResponse scans an HTTP response body for PII.
func (el *EngineLayer) ScanHTTPResponse(body []byte, contentType string) (*ScanResult, []byte) {
	return el.Layer.ScanResponse(body, contentType)
}

// Ensure EngineLayer implements engine.Layer
var _ engine.Layer = (*EngineLayer)(nil)
