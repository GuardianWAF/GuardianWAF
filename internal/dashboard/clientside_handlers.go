package dashboard

import (
	"net/http"
	"strconv"
)

// ClientSideHandler handles client-side protection management API endpoints.
type ClientSideHandler struct {
	dashboard *Dashboard
}

// NewClientSideHandler creates a new client-side protection handler.
func NewClientSideHandler(d *Dashboard) *ClientSideHandler {
	return &ClientSideHandler{dashboard: d}
}

// RegisterRoutes registers client-side protection routes.
func (h *ClientSideHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/clientside/stats", h.handleStats)
	mux.HandleFunc("/api/clientside/config", h.handleConfig)
	mux.HandleFunc("/api/clientside/skimming-domains", h.handleSkimmingDomains)
	mux.HandleFunc("/api/clientside/csp-reports", h.handleCSPReports)
}

// handleStats handles GET /api/clientside/stats
func (h *ClientSideHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	csLayer := h.getClientSideLayer()
	if csLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
		})
		return
	}

	stats := csLayer.GetStats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":               true,
		"mode":                  stats.Mode,
		"magecart_detections":   stats.MagecartDetections,
		"script_injections":     stats.ScriptInjections,
		"csp_violations":        stats.CSPViolations,
		"blocked_skimmers":      stats.BlockedSkimmers,
		"injected_sessions":     stats.InjectedSessions,
	})
}

// handleConfig handles GET/PUT /api/clientside/config
func (h *ClientSideHandler) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := h.dashboard.engine.Config()
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":             cfg.WAF.ClientSide.Enabled,
			"mode":                cfg.WAF.ClientSide.Mode,
			"magecart_detection":  cfg.WAF.ClientSide.MagecartDetection.Enabled,
			"agent_injection":     cfg.WAF.ClientSide.AgentInjection.Enabled,
			"csp_enabled":         cfg.WAF.ClientSide.CSP.Enabled,
			"csp_report_only":     cfg.WAF.ClientSide.CSP.ReportOnly,
		})

	case http.MethodPut:
		var req struct {
			Mode              *string `json:"mode"`
			MagecartDetection *bool   `json:"magecart_detection"`
			AgentInjection    *bool   `json:"agent_injection"`
			CSPEnabled        *bool   `json:"csp_enabled"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		// Get current config and update settings
		newCfg := h.dashboard.engine.Config()
		if req.Mode != nil {
			newCfg.WAF.ClientSide.Mode = *req.Mode
		}
		if req.MagecartDetection != nil {
			newCfg.WAF.ClientSide.MagecartDetection.Enabled = *req.MagecartDetection
		}
		if req.AgentInjection != nil {
			newCfg.WAF.ClientSide.AgentInjection.Enabled = *req.AgentInjection
		}
		if req.CSPEnabled != nil {
			newCfg.WAF.ClientSide.CSP.Enabled = *req.CSPEnabled
		}

		// Reload config
		if err := h.dashboard.engine.Reload(newCfg); err != nil {
			http.Error(w, sanitizeErr(err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":             "updated",
			"mode":               newCfg.WAF.ClientSide.Mode,
			"magecart_detection": newCfg.WAF.ClientSide.MagecartDetection.Enabled,
			"agent_injection":    newCfg.WAF.ClientSide.AgentInjection.Enabled,
			"csp_enabled":        newCfg.WAF.ClientSide.CSP.Enabled,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSkimmingDomains handles GET/POST /api/clientside/skimming-domains
func (h *ClientSideHandler) handleSkimmingDomains(w http.ResponseWriter, r *http.Request) {
	csLayer := h.getClientSideLayer()
	if csLayer == nil {
		http.Error(w, "Client-side protection layer not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		domains := csLayer.GetBlockedDomains()
		writeJSON(w, http.StatusOK, map[string]any{
			"domains": domains,
			"count":   len(domains),
		})

	case http.MethodPost:
		var req struct {
			Domain string `json:"domain"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		if req.Domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		csLayer.AddBlockedDomain(req.Domain)
		writeJSON(w, http.StatusOK, map[string]any{
			"domain": req.Domain,
			"status": "added",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCSPReports handles GET /api/clientside/csp-reports
func (h *ClientSideHandler) handleCSPReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	csLayer := h.getClientSideLayer()
	if csLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"reports": []any{},
		})
		return
	}

	// Get limit parameter
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 1000)
		}
	}

	reports := csLayer.GetCSPReports(limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"reports": reports,
		"count":   len(reports),
	})
}

// getClientSideLayer returns the client-side protection layer from the engine if available
func (h *ClientSideHandler) getClientSideLayer() ClientSideLayerInterface {
	// This is a simplified version - in production, you'd get this from the engine
	return nil
}

// ClientSideLayerInterface defines the interface for client-side protection layer operations
type ClientSideLayerInterface interface {
	GetStats() ClientSideStats
	GetBlockedDomains() []string
	AddBlockedDomain(domain string)
	GetCSPReports(limit int) []CSPReportInfo
}

// ClientSideStats represents client-side protection statistics
type ClientSideStats struct {
	Mode               string `json:"mode"`
	MagecartDetections int64  `json:"magecart_detections"`
	ScriptInjections   int64  `json:"script_injections"`
	CSPViolations      int64  `json:"csp_violations"`
	BlockedSkimmers    int64  `json:"blocked_skimmers"`
	InjectedSessions   int64  `json:"injected_sessions"`
}

// CSPReportInfo represents a CSP violation report
type CSPReportInfo struct {
	Timestamp   int64  `json:"timestamp"`
	DocumentURI string `json:"document_uri"`
	BlockedURI  string `json:"blocked_uri"`
	ViolatedDir string `json:"violated_directive"`
	SourceFile  string `json:"source_file"`
}
