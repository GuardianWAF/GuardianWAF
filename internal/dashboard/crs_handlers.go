package dashboard

import (
	"net/http"
	"strconv"
)

// CRSHandler handles CRS management API endpoints.
type CRSHandler struct {
	dashboard *Dashboard
}

// NewCRSHandler creates a new CRS handler.
func NewCRSHandler(d *Dashboard) *CRSHandler {
	return &CRSHandler{dashboard: d}
}

// RegisterRoutes registers CRS routes.
func (h *CRSHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/crs/rules", h.handleRules)
	mux.HandleFunc("/api/crs/rules/", h.handleRuleDetail)
	mux.HandleFunc("/api/crs/config", h.handleConfig)
	mux.HandleFunc("/api/crs/stats", h.handleStats)
	mux.HandleFunc("/api/crs/test", h.handleTest)
}

// handleRules handles GET /api/crs/rules
func (h *CRSHandler) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get CRS layer from engine
	crsLayer := h.getCRSLayer()
	if crsLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"rules":   []any{},
		})
		return
	}

	// Get query params
	phase := r.URL.Query().Get("phase")
	severity := r.URL.Query().Get("severity")

	// Build response
	rules := crsLayer.GetAllRules()
	var filtered []map[string]any

	for _, rule := range rules {
		// Filter by phase
		if phase != "" {
			p, _ := strconv.Atoi(phase)
			if rule.Phase != p {
				continue
			}
		}

		// Filter by severity
		if severity != "" && rule.Severity != severity {
			continue
		}

		filtered = append(filtered, map[string]any{
			"id":             rule.ID,
			"phase":          rule.Phase,
			"severity":       rule.Severity,
			"msg":            rule.Msg,
			"tags":           rule.Tags,
			"paranoia_level": rule.ParanoiaLevel,
			"enabled":        crsLayer.IsRuleEnabled(rule.ID),
		})
	}

	cfg := h.dashboard.engine.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":           cfg.WAF.CRS.Enabled,
		"paranoia_level":    cfg.WAF.CRS.ParanoiaLevel,
		"anomaly_threshold": cfg.WAF.CRS.AnomalyThreshold,
		"rules":             filtered,
		"total":             len(rules),
	})
}

// handleRuleDetail handles PUT/DELETE /api/crs/rules/{id}
func (h *CRSHandler) handleRuleDetail(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from path
	path := r.URL.Path[len("/api/crs/rules/"):]
	if path == "" {
		http.Error(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	crsLayer := h.getCRSLayer()
	if crsLayer == nil {
		http.Error(w, "CRS not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		if req.Enabled {
			crsLayer.EnableRule(path)
		} else {
			crsLayer.DisableRule(path)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":      path,
			"enabled": req.Enabled,
		})

	case http.MethodGet:
		rule := crsLayer.GetRule(path)
		if rule == nil {
			http.Error(w, "Rule not found", http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":             rule.ID,
			"phase":          rule.Phase,
			"severity":       rule.Severity,
			"msg":            rule.Msg,
			"tags":           rule.Tags,
			"paranoia_level": rule.ParanoiaLevel,
			"enabled":        crsLayer.IsRuleEnabled(rule.ID),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleConfig handles GET/PUT /api/crs/config
func (h *CRSHandler) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := h.dashboard.engine.Config()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":           cfg.WAF.CRS.Enabled,
			"paranoia_level":    cfg.WAF.CRS.ParanoiaLevel,
			"anomaly_threshold": cfg.WAF.CRS.AnomalyThreshold,
			"rule_path":         cfg.WAF.CRS.RulePath,
			"exclusions":        cfg.WAF.CRS.Exclusions,
			"disabled_rules":    cfg.WAF.CRS.DisabledRules,
		})

	case http.MethodPut:
		var req struct {
			Enabled          bool     `json:"enabled"`
			ParanoiaLevel    int      `json:"paranoia_level"`
			AnomalyThreshold int      `json:"anomaly_threshold"`
			Exclusions       []string `json:"exclusions"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}

		// Get current config and update CRS settings
		newCfg := h.dashboard.engine.Config()
		newCfg.WAF.CRS.Enabled = req.Enabled
		newCfg.WAF.CRS.ParanoiaLevel = req.ParanoiaLevel
		newCfg.WAF.CRS.AnomalyThreshold = req.AnomalyThreshold
		if req.Exclusions != nil {
			newCfg.WAF.CRS.Exclusions = req.Exclusions
		}

		// Reload config
		if err := h.dashboard.engine.Reload(newCfg); err != nil {
			http.Error(w, sanitizeErr(err), http.StatusInternalServerError)
			return
		}

		// Apply paranoia level if CRS layer exists
		if crsLayer := h.getCRSLayer(); crsLayer != nil {
			crsLayer.SetParanoiaLevel(req.ParanoiaLevel)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":           req.Enabled,
			"paranoia_level":    req.ParanoiaLevel,
			"anomaly_threshold": req.AnomalyThreshold,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStats handles GET /api/crs/stats
func (h *CRSHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	crsLayer := h.getCRSLayer()
	if crsLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
		})
		return
	}

	stats := crsLayer.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"stats":   stats,
	})
}

// handleTest handles POST /api/crs/test
func (h *CRSHandler) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	crsLayer := h.getCRSLayer()
	if crsLayer == nil {
		http.Error(w, "CRS not enabled", http.StatusServiceUnavailable)
		return
	}

	// Create test context
	ctx := &TestRequestContext{
		Method:  req.Method,
		Path:    req.Path,
		Headers: req.Headers,
		Body:    req.Body,
	}

	// Test against CRS layer
	result := crsLayer.Process(ctx)

	writeJSON(w, http.StatusOK, map[string]any{
		"score":    result.Score,
		"action":   result.Action.String(),
		"findings": result.Findings,
	})
}

// getCRSLayer returns the CRS layer from the engine if available
func (h *CRSHandler) getCRSLayer() CRSLayerInterface {
	// This is a simplified version - in production, you'd get this from the engine
	return nil
}

// CRSLayerInterface defines the interface for CRS layer operations
type CRSLayerInterface interface {
	GetAllRules() []*CRSRuleInfo
	GetRule(id string) *CRSRuleInfo
	EnableRule(id string)
	DisableRule(id string)
	IsRuleEnabled(id string) bool
	SetParanoiaLevel(level int)
	Stats() map[string]int
	Process(ctx *TestRequestContext) CRSResult
}

// CRSRuleInfo represents CRS rule information
type CRSRuleInfo struct {
	ID             string
	Phase          int
	Severity       string
	Msg            string
	Tags           []string
	ParanoiaLevel  int
}

// TestRequestContext is a simplified request context for testing
type TestRequestContext struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    string
}

// CRSResult represents CRS processing result
type CRSResult struct {
	Score    int
	Action   ActionType
	Findings []FindingInfo
}

// ActionType represents the action taken
type ActionType string

func (a ActionType) String() string { return string(a) }

// FindingInfo represents a security finding
type FindingInfo struct {
	DetectorName string
	Category     string
	Description  string
	Score        int
}
