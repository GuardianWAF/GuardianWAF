package dashboard

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// DLPHandler handles Data Loss Prevention management API endpoints.
type DLPHandler struct {
	dashboard *Dashboard
}

// NewDLPHandler creates a new DLP handler.
func NewDLPHandler(d *Dashboard) *DLPHandler {
	return &DLPHandler{dashboard: d}
}

// RegisterRoutes registers DLP management routes with authentication.
func (h *DLPHandler) RegisterRoutes(mux *http.ServeMux) {
	auth := h.dashboard.authWrap
	mux.HandleFunc("/api/dlp/alerts", auth(h.handleAlerts))
	mux.HandleFunc("/api/dlp/patterns", auth(h.handlePatterns))
	mux.HandleFunc("/api/dlp/patterns/", auth(h.handlePatternDetail))
	mux.HandleFunc("/api/dlp/test", auth(h.handleTestPattern))
}

// handleAlerts handles GET /api/dlp/alerts
func (h *DLPHandler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dlpLayer := h.getDLPLayer()
	if dlpLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"alerts":  []any{},
		})
		return
	}

	// Get query params
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 1000)
		}
	}

	patternType := r.URL.Query().Get("pattern_type")

	alerts := dlpLayer.GetAlerts(limit, patternType)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"alerts":  alerts,
		"count":   len(alerts),
	})
}

// handlePatterns handles GET/POST /api/dlp/patterns
func (h *DLPHandler) handlePatterns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListPatterns(w, r)
	case http.MethodPost:
		h.handleAddPattern(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *DLPHandler) handleListPatterns(w http.ResponseWriter, r *http.Request) {
	dlpLayer := h.getDLPLayer()
	if dlpLayer == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":  false,
			"patterns": []any{},
		})
		return
	}

	patterns := dlpLayer.GetPatterns()
	var result []map[string]any

	for _, pattern := range patterns {
		result = append(result, map[string]any{
			"id":          pattern.ID,
			"name":        pattern.Name,
			"pattern":     pattern.Pattern,
			"description": pattern.Description,
			"action":      pattern.Action,
			"score":       pattern.Score,
			"enabled":     pattern.Enabled,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":  dlpLayer.IsEnabled(),
		"patterns": result,
		"total":    len(patterns),
	})
}

func (h *DLPHandler) handleAddPattern(w http.ResponseWriter, r *http.Request) {
	dlpLayer := h.getDLPLayer()
	if dlpLayer == nil {
		http.Error(w, "DLP layer not enabled", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
		Action      string `json:"action"`
		Score       int    `json:"score"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	if req.ID == "" || req.Name == "" || req.Pattern == "" || req.Action == "" {
		http.Error(w, "id, name, pattern, and action are required", http.StatusBadRequest)
		return
	}
	if len(req.Pattern) > 4096 {
		http.Error(w, "pattern too long (max 4096 chars)", http.StatusBadRequest)
		return
	}
	if req.Score < 0 {
		req.Score = 0
	}

	pattern := &DLPPatternInfo{
		ID:          req.ID,
		Name:        req.Name,
		Pattern:     req.Pattern,
		Description: req.Description,
		Action:      req.Action,
		Score:       req.Score,
		Enabled:     true,
	}

	if err := dlpLayer.AddPattern(pattern); err != nil {
		http.Error(w, sanitizeErr(err), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":     req.ID,
		"status": "created",
	})
}

// handlePatternDetail handles GET/DELETE /api/dlp/patterns/{id}
func (h *DLPHandler) handlePatternDetail(w http.ResponseWriter, r *http.Request) {
	// Extract pattern ID from path
	path := r.URL.Path[len("/api/dlp/patterns/"):]
	if path == "" {
		http.Error(w, "Pattern ID required", http.StatusBadRequest)
		return
	}

	dlpLayer := h.getDLPLayer()
	if dlpLayer == nil {
		http.Error(w, "DLP layer not enabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		pattern := dlpLayer.GetPattern(path)
		if pattern == nil {
			http.Error(w, "Pattern not found", http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":          pattern.ID,
			"name":        pattern.Name,
			"pattern":     pattern.Pattern,
			"description": pattern.Description,
			"action":      pattern.Action,
			"score":       pattern.Score,
			"enabled":     pattern.Enabled,
		})

	case http.MethodDelete:
		if err := dlpLayer.RemovePattern(path); err != nil {
			http.Error(w, sanitizeErr(err), http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"id":     path,
			"status": "removed",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTestPattern handles POST /api/dlp/test
func (h *DLPHandler) handleTestPattern(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dlpLayer := h.getDLPLayer()
	if dlpLayer == nil {
		http.Error(w, "DLP layer not enabled", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Pattern  string `json:"pattern"`
		TestData string `json:"test_data"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	if req.Pattern == "" || req.TestData == "" {
		http.Error(w, "pattern and test_data are required", http.StatusBadRequest)
		return
	}

	result := dlpLayer.TestPattern(req.Pattern, req.TestData)

	writeJSON(w, http.StatusOK, map[string]any{
		"matched": result.Matched,
		"matches": result.Matches,
		"pattern": req.Pattern,
	})
}

// getDLPLayer returns the DLP layer from the engine if available
func (h *DLPHandler) getDLPLayer() DLPLayerInterface {
	if h.dashboard.dlpLayerOverride != nil {
		return h.dashboard.dlpLayerOverride
	}
	if h.dashboard.dlpLayer == nil {
		// Try to get from engine via FindLayer
		if h.dashboard.engine != nil {
			if layer := h.dashboard.engine.FindLayer("dlp"); layer != nil {
				if l, ok := layer.(*dlp.Layer); ok {
					return &dlpAdapter{layer: l}
				}
			}
		}
		return nil
	}
	return &dlpAdapter{layer: h.dashboard.dlpLayer}
}

// dlpAdapter wraps dlp.Layer to satisfy DLPLayerInterface
type dlpAdapter struct {
	layer *dlp.Layer
}

func (a *dlpAdapter) IsEnabled() bool {
	return a.layer != nil
}

func (a *dlpAdapter) GetAlerts(limit int, patternType string) []DLPAlertInfo {
	return nil // Alert history not exposed in current DLP layer
}

func (a *dlpAdapter) GetPatterns() []*DLPPatternInfo {
	if a.layer == nil {
		return nil
	}
	registry := a.layer.GetRegistry()
	if registry == nil {
		return nil
	}
	patterns := registry.GetAllPatterns()
	result := make([]*DLPPatternInfo, 0, len(patterns))
	for _, p := range patterns {
		result = append(result, &DLPPatternInfo{
			ID:      string(p.Type),
			Name:    string(p.Type),
			Pattern: p.Regex.String(),
		})
	}
	return result
}

func (a *dlpAdapter) GetPattern(id string) *DLPPatternInfo {
	patterns := a.GetPatterns()
	for _, p := range patterns {
		if p.ID == id {
			return p
		}
	}
	return nil
}

func (a *dlpAdapter) AddPattern(pattern *DLPPatternInfo) error {
	if a.layer == nil {
		return nil
	}
	regex, err := regexp.Compile(pattern.Pattern)
	if err != nil {
		return err
	}
	a.layer.AddCustomPattern(pattern.Name, &dlp.Pattern{
		Regex:      regex,
		Severity:   dlp.SeverityMedium,
		MaskFormat: "****",
	})
	return nil
}

func (a *dlpAdapter) RemovePattern(id string) error {
	// DLP layer doesn't support removing built-in patterns
	return nil
}

func (a *dlpAdapter) TestPattern(pattern, testData string) DLPTestResult {
	// Simple pattern test without full DLP engine
	matched := false
	var matches []string
	if pattern != "" && testData != "" {
		// Very basic containment test
		if strings.Contains(testData, pattern) {
			matched = true
			matches = append(matches, pattern)
		}
	}
	return DLPTestResult{Matched: matched, Matches: matches}
}

// DLPLayerInterface defines the interface for DLP layer operations
type DLPLayerInterface interface {
	IsEnabled() bool
	GetAlerts(limit int, patternType string) []DLPAlertInfo
	GetPatterns() []*DLPPatternInfo
	GetPattern(id string) *DLPPatternInfo
	AddPattern(pattern *DLPPatternInfo) error
	RemovePattern(id string) error
	TestPattern(pattern, testData string) DLPTestResult
}

// DLPPatternInfo represents DLP pattern information
type DLPPatternInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Score       int    `json:"score"`
	Enabled     bool   `json:"enabled"`
}

// DLPAlertInfo represents a DLP alert
type DLPAlertInfo struct {
	ID           string `json:"id"`
	Timestamp    int64  `json:"timestamp"`
	PatternType  string `json:"pattern_type"`
	PatternName  string `json:"pattern_name"`
	ClientIP     string `json:"client_ip"`
	Path         string `json:"path"`
	MatchedValue string `json:"matched_value"`
	Action       string `json:"action"`
}

// DLPTestResult represents DLP pattern test result
type DLPTestResult struct {
	Matched bool     `json:"matched"`
	Matches []string `json:"matches"`
}
