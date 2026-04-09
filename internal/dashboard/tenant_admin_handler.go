package dashboard

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

// TenantAdminHandler handles multi-tenant management API.
type TenantAdminHandler struct {
	dashboard *Dashboard
	manager   tenantManagerInterface
}

// NewTenantAdminHandler creates a new tenant admin handler.
func NewTenantAdminHandler(d *Dashboard, manager tenantManagerInterface) *TenantAdminHandler {
	return &TenantAdminHandler{
		dashboard: d,
		manager:   manager,
	}
}

// RegisterRoutes registers tenant admin routes.
func (h *TenantAdminHandler) RegisterRoutes(mux *http.ServeMux) {
	// Admin API routes (require master API key)
	mux.HandleFunc("/api/admin/tenants", h.handleTenants)
	mux.HandleFunc("/api/admin/tenants/", h.handleTenantDetail)
	mux.HandleFunc("/api/admin/stats", h.handleStats)
	mux.HandleFunc("/api/admin/billing", h.handleBilling)
	mux.HandleFunc("/api/admin/billing/", h.handleBillingDetail)
	mux.HandleFunc("/api/admin/alerts", h.handleAlerts)
	mux.HandleFunc("/api/admin/usage", h.handleAllUsage)
	mux.HandleFunc("/api/admin/usage/", h.handleUsageDetail)
	mux.HandleFunc("/api/admin/tenants/rules", h.handleTenantRules)
	mux.HandleFunc("/api/admin/tenants/rules/", h.handleTenantRuleDetail)
}

// handleTenants handles list and create operations.
func (h *TenantAdminHandler) handleTenants(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.listTenants(w, r)
	case http.MethodPost:
		h.createTenant(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

// handleTenantDetail handles get, update, delete operations.
func (h *TenantAdminHandler) handleTenantDetail(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant ID required"})
		return
	}

	parts := strings.Split(path, "/")
	tenantID := parts[0]

	if len(parts) > 1 && parts[1] == "regenerate-key" && r.Method == http.MethodPost {
		h.regenerateAPIKey(w, r, tenantID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getTenant(w, r, tenantID)
	case http.MethodPut:
		h.updateTenant(w, r, tenantID)
	case http.MethodDelete:
		h.deleteTenant(w, r, tenantID)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (h *TenantAdminHandler) verifyAdminKey(r *http.Request) bool {
	adminKey := r.Header.Get("X-Admin-Key")
	if adminKey == "" {
		adminKey = r.Header.Get("X-API-Key")
	}
	return subtle.ConstantTimeCompare([]byte(adminKey), []byte(h.dashboard.apiKey)) == 1
}

func (h *TenantAdminHandler) listTenants(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	tenants := h.manager.ListTenants()
	writeJSON(w, http.StatusOK, map[string]any{
		"tenants": tenants,
		"count":   len(tenants),
	})
}

func (h *TenantAdminHandler) createTenant(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Domains     []string `json:"domains"`
		Quota       any      `json:"quota,omitempty"`
	}

	if !limitedDecodeJSON(w, r, &req) {
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}

	if len(req.Domains) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "at least one domain is required"})
		return
	}

	tenant, err := h.manager.CreateTenant(req.Name, req.Description, req.Domains, req.Quota)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": sanitizeErr(err)})
		return
	}

	// Extract tenant ID for API key regeneration
	tenantMap, ok := tenant.(map[string]any)
	if !ok {
		writeJSON(w, http.StatusCreated, map[string]any{"tenant": tenant})
		return
	}

	tenantID, _ := tenantMap["id"].(string)
	apiKey, _ := h.manager.RegenerateAPIKey(tenantID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant":  tenant,
		"api_key": apiKey,
	})
}

func (h *TenantAdminHandler) getTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "multi-tenant mode not enabled"})
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
		return
	}

	writeJSON(w, http.StatusOK, tenant)
}

func (h *TenantAdminHandler) updateTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "multi-tenant mode not enabled"})
		return
	}

	var update map[string]any
	if !limitedDecodeJSON(w, r, &update) {
		return
	}

	// Validate that update contains only known fields
	allowedKeys := map[string]bool{
		"name": true, "description": true, "domains": true,
		"enabled": true, "billing_plan": true, "quota": true,
		"waf_config": true, "rate_limits": true,
	}
	for k := range update {
		if !allowedKeys[k] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown field: " + k})
			return
		}
	}

	if err := h.manager.UpdateTenant(tenantID, update); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	writeJSON(w, http.StatusOK, tenant)
}

func (h *TenantAdminHandler) deleteTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "multi-tenant mode not enabled"})
		return
	}

	if err := h.manager.DeleteTenant(tenantID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}

	writeJSON(w, http.StatusNoContent, nil)
}

func (h *TenantAdminHandler) regenerateAPIKey(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "multi-tenant mode not enabled"})
		return
	}

	apiKey, err := h.manager.RegenerateAPIKey(tenantID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"api_key": apiKey})
}

func (h *TenantAdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":   "multi-tenant mode not enabled",
			"enabled": false,
		})
		return
	}

	stats := h.manager.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"stats":   stats,
	})
}

func (h *TenantAdminHandler) handleBilling(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil || h.manager.BillingManager() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "billing not enabled",
		})
		return
	}

	// GET - List all invoices
	if r.Method == http.MethodGet {
		invoices := h.manager.BillingManager().GetAllInvoices()
		writeJSON(w, http.StatusOK, map[string]any{
			"invoices": invoices,
		})
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func (h *TenantAdminHandler) handleBillingDetail(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/billing/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant ID required"})
		return
	}

	parts := strings.Split(path, "/")
	tenantID := parts[0]

	// GET - Get tenant invoices and current usage
	if r.Method == http.MethodGet {
		invoices := h.manager.BillingManager().GetInvoices(tenantID)
		usage := h.manager.BillingManager().GetCurrentUsage(tenantID)

		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":     tenantID,
			"invoices":      invoices,
			"current_usage": usage,
		})
		return
	}

	// POST - Generate new invoice
	if r.Method == http.MethodPost {
		tenant := h.manager.GetTenant(tenantID)
		if tenant == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
			return
		}

		// Extract tenant data from map
		tenantMap, ok := tenant.(map[string]any)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "invalid tenant data"})
			return
		}

		// Default to basic plan
		plan := "basic"
		if p, ok := tenantMap["billing_plan"].(string); ok && p != "" {
			plan = p
		}

		tenantName, _ := tenantMap["name"].(string)

		invoice, err := h.manager.BillingManager().GenerateInvoice(
			tenantID,
			tenantName,
			plan,
			time.Now().AddDate(0, -1, 0), // Last month
			time.Now(),
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
			return
		}

		writeJSON(w, http.StatusCreated, invoice)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func (h *TenantAdminHandler) handleAllUsage(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	// GET - Get usage for all tenants
	if r.Method == http.MethodGet {
		usage := h.manager.GetAllUsage()
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants": usage,
			"count":   len(usage),
		})
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func (h *TenantAdminHandler) handleUsageDetail(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/usage/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant ID required"})
		return
	}

	tenantID := strings.Split(path, "/")[0]

	// GET - Get usage for specific tenant
	if r.Method == http.MethodGet {
		usage := h.manager.GetTenantUsage(tenantID)
		if usage == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
			return
		}
		writeJSON(w, http.StatusOK, usage)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func (h *TenantAdminHandler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil || h.manager.AlertManager() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "alerts not enabled",
		})
		return
	}

	// GET - Get recent alerts
	if r.Method == http.MethodGet {
		since := 24 * time.Hour
		alerts := h.manager.AlertManager().GetRecentAlerts(since)
		writeJSON(w, http.StatusOK, map[string]any{
			"alerts": alerts,
			"count":  len(alerts),
		})
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func (h *TenantAdminHandler) handleTenantRules(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List all rules across tenants or filter by tenant_id query param
		tenantID := r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id query parameter required"})
			return
		}
		rules := h.manager.GetTenantRules(tenantID)
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id": tenantID,
			"rules":     rules,
			"count":     len(rules),
		})
	case http.MethodPost:
		// Add a new rule to a tenant
		var req struct {
			TenantID string         `json:"tenant_id"`
			Rule     map[string]any `json:"rule"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}
		if req.TenantID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant_id is required"})
			return
		}
		if err := h.manager.AddTenantRule(req.TenantID, req.Rule); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"status": "ok"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (h *TenantAdminHandler) handleTenantRuleDetail(w http.ResponseWriter, r *http.Request) {
	if !h.verifyAdminKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	// Path format: /api/admin/tenants/rules/{tenantID}/{ruleID}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/rules/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tenant ID and rule ID required"})
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "rule ID required"})
		return
	}
	tenantID := parts[0]
	ruleID := parts[1]

	switch r.Method {
	case http.MethodGet:
		rule := h.manager.GetTenantRule(tenantID, ruleID)
		if rule == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "rule not found"})
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodPut:
		var rule map[string]any
		if !limitedDecodeJSON(w, r, &rule) {
			return
		}
		if err := h.manager.UpdateTenantRule(tenantID, rule); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case http.MethodDelete:
		if err := h.manager.RemoveTenantRule(tenantID, ruleID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
			return
		}
		writeJSON(w, http.StatusNoContent, nil)
	case http.MethodPatch:
		// Toggle rule enabled/disabled
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if !limitedDecodeJSON(w, r, &req) {
			return
		}
		if err := h.manager.ToggleTenantRule(tenantID, ruleID, req.Enabled); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "enabled": req.Enabled})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}
