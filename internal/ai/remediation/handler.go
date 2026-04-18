package remediation

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// maxHandlerBodySize limits the request body for remediation API endpoints.
const maxHandlerBodySize = 1 * 1024 * 1024 // 1 MB

// Handler provides HTTP API for remediation management.
type Handler struct {
	engine *Engine
	apiKey string // required — reject unauthenticated requests
}

// NewHandler creates a new remediation handler.
// apiKey is required for authentication; if empty, all requests are rejected.
func NewHandler(engine *Engine, apiKey ...string) *Handler {
	key := ""
	if len(apiKey) > 0 {
		key = apiKey[0]
	}
	return &Handler{engine: engine, apiKey: key}
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Route based on path
	switch {
	case r.URL.Path == "/api/v1/remediation/rules":
		h.handleRules(w, r)
	case r.URL.Path == "/api/v1/remediation/stats":
		h.handleStats(w, r)
	case r.URL.Path == "/api/v1/remediation/apply":
		h.handleApply(w, r)
	case r.URL.Path == "/api/v1/remediation/revoke":
		h.handleRevoke(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/remediation/rules/"):
		h.handleRuleDetail(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authenticate checks the X-API-Key header against the configured API key.
func (h *Handler) authenticate(r *http.Request) bool {
	if h.apiKey == "" {
		return false // no key configured = reject all
	}
	key := r.Header.Get("X-API-Key")
	if key == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(h.apiKey)) == 1
}

// handleRules handles rule listing and creation.
func (h *Handler) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listRules(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// listRules returns all rules or filtered by status.
func (h *Handler) listRules(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")

	var rules []*GeneratedRule
	switch status {
	case "active":
		rules = h.engine.GetActiveRules()
	case "pending":
		all := h.engine.GetAllRules()
		for _, rule := range all {
			if !rule.Applied {
				rules = append(rules, rule)
			}
		}
	default:
		rules = h.engine.GetAllRules()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"rules": rules,
		"count": len(rules),
	}); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// handleRuleDetail handles individual rule operations.
func (h *Handler) handleRuleDetail(w http.ResponseWriter, r *http.Request) {
	// Extract rule ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/remediation/rules/")
	if path == "" {
		http.Error(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	ruleID := strings.Split(path, "/")[0]

	switch r.Method {
	case http.MethodGet:
		h.getRule(w, ruleID)
	case http.MethodDelete:
		h.deleteRule(w, ruleID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getRule returns a specific rule.
func (h *Handler) getRule(w http.ResponseWriter, ruleID string) {
	rule := h.engine.GetRule(ruleID)
	if rule == nil {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(rule); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// deleteRule deletes a rule.
func (h *Handler) deleteRule(w http.ResponseWriter, ruleID string) {
	if err := h.engine.DeleteRule(ruleID); err != nil {
		http.Error(w, "failed to delete rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleStats returns remediation statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.engine.GetStats()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// handleApply applies a pending rule.
func (h *Handler) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RuleID string `json:"rule_id"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxHandlerBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.RuleID == "" {
		http.Error(w, "rule_id required", http.StatusBadRequest)
		return
	}

	if err := h.engine.ApplyRule(req.RuleID); err != nil {
		http.Error(w, "failed to apply rule", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "applied",
		"rule_id": req.RuleID,
	}); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// handleRevoke revokes an applied rule.
func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RuleID string `json:"rule_id"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxHandlerBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.RuleID == "" {
		http.Error(w, "rule_id required", http.StatusBadRequest)
		return
	}

	if err := h.engine.RevokeRule(req.RuleID); err != nil {
		http.Error(w, "failed to revoke rule", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "revoked",
		"rule_id": req.RuleID,
	}); err != nil {
		// Client disconnected - error ignored intentionally
		_ = err
	}
}

// Layer provides remediation as a WAF layer.
type Layer struct {
	engine *Engine
	config *Config
}

// NewLayer creates a new remediation layer.
func NewLayer(cfg *Config) (*Layer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		return nil, err
	}

	return &Layer{
		engine: engine,
		config: cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "remediation"
}

// Order returns the layer execution order (runs after AI analysis, before response).
func (l *Layer) Order() int {
	return 480
}

// Process implements the engine.Layer interface.
// Checks if request matches any active remediation rules.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	result := engine.LayerResult{Action: engine.ActionPass}

	if !l.config.Enabled || l.engine == nil {
		return result
	}

	// Build remediation request context
	rctx := &RequestContext{
		Path: ctx.Path,
		Body: "",
	}
	if ctx.Request != nil && ctx.Request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, 10*1024*1024))
		if err != nil {
			result.Findings = append(result.Findings, engine.Finding{
				DetectorName: "ai_remediation",
				Score:    0,
				Description: "failed to read request body: " + err.Error(),
			})
			return result
		}
		rctx.Body = string(body)
		ctx.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	// Check against active rules
	for _, rule := range l.engine.GetActiveRules() {
		if l.matchesRule(rctx, rule) {
			result.Action = engine.ActionBlock
			result.Score = 100
			result.Findings = append(result.Findings, engine.Finding{
				DetectorName: "remediation",
				Category:     "ai_remediation",
				Severity:     engine.SeverityCritical,
				Score:        100,
				Description: fmt.Sprintf("Matched remediation rule: %s", rule.Name),
			})
			return result
		}
	}

	return result
}

// matchesRule checks if request matches a rule.
func (l *Layer) matchesRule(ctx *RequestContext, rule *GeneratedRule) bool {
	// Simple pattern matching - in production would use proper regex
	if rule.Pattern == "" {
		return false
	}

	// Check if path matches
	if ctx.Path == rule.Pattern || strings.Contains(ctx.Path, rule.Pattern) {
		return true
	}

	// Check if payload matches
	if ctx.Body != "" && strings.Contains(ctx.Body, rule.Pattern) {
		return true
	}

	return false
}

// GetEngine returns the remediation engine.
func (l *Layer) GetEngine() *Engine {
	return l.engine
}

// GetHandler returns the HTTP handler.
// apiKey is required for authentication on the handler endpoints.
func (l *Layer) GetHandler(apiKey string) *Handler {
	if l.engine == nil {
		return nil
	}
	return NewHandler(l.engine, apiKey)
}

// Stop stops the layer.
func (l *Layer) Stop() {
	if l.engine != nil {
		l.engine.Stop()
	}
}

// RequestContext provides request information for rule matching.
type RequestContext struct {
	IP      string
	Path    string
	Method  string
	Headers http.Header
	Body    string
	Blocked bool
	Reason  string
	Score   int
}

// BlockResult represents a blocking decision.
type BlockResult struct {
	Blocked  bool
	Reason   string
	Score    int
	Response int
}
