package dashboard

import (
	"encoding/json"
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
// All admin routes require the system admin API key (X-API-Key header) via
// isAdminAuthenticated. This is separate from per-tenant API key auth and grants
// exclusive access to cross-tenant management operations (tenant CRUD, billing,
// system stats). The admin key is set via Dashboard.SetAdminKey().
func (h *TenantAdminHandler) RegisterRoutes(mux *http.ServeMux) {
	auth := h.dashboard.adminAuthAuditWrap

	// Admin API routes (require the dashboard.admin_key via X-API-Key)
	mux.HandleFunc("/api/admin/tenants", auth(h.handleTenants))
	mux.HandleFunc("/api/admin/tenants/", auth(h.handleTenantDetail))
	mux.HandleFunc("/api/admin/stats", auth(h.handleStats))
	mux.HandleFunc("/api/admin/billing", auth(h.handleBilling))
	mux.HandleFunc("/api/admin/billing/", auth(h.handleBillingDetail))
	mux.HandleFunc("/api/admin/alerts", auth(h.handleAlerts))
	mux.HandleFunc("/api/admin/usage", auth(h.handleAllUsage))
	mux.HandleFunc("/api/admin/usage/", auth(h.handleUsageDetail))
	mux.HandleFunc("/api/admin/tenants/rules", auth(h.handleTenantRules))
	mux.HandleFunc("/api/admin/tenants/rules/", auth(h.handleTenantRuleDetail))
}

// handleTenants handles list and create operations.
func (h *TenantAdminHandler) handleTenants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listTenants(w, r)
	case http.MethodPost:
		h.createTenant(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleTenantDetail handles get, update, delete operations.
func (h *TenantAdminHandler) handleTenantDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "tenant ID required")
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
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *TenantAdminHandler) listTenants(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"tenants": []any{},
			"count":   0,
			"enabled": false,
		})
		return
	}

	tenants := h.manager.ListTenants()
	publicTenants := make([]any, len(tenants))
	for i, tenant := range tenants {
		publicTenants[i] = sanitizeTenantResponse(tenant)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenants": publicTenants,
		"count":   len(publicTenants),
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
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if len(req.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "at least one domain is required")
		return
	}

	tenant, err := h.manager.CreateTenant(req.Name, req.Description, req.Domains, req.Quota)
	if err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}

	// Extract the tenant ID through the JSON-tagged adapter boundary. Production
	// managers return structs while tests and integrations may return maps.
	record, ok := decodeTenantAuthRecord(tenant)
	if !ok {
		writeError(w, http.StatusInternalServerError, "tenant created but its identifier could not be read")
		return
	}

	apiKey, err := h.manager.RegenerateAPIKey(record.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "tenant created but API key provisioning failed")
		return
	}
	h.dashboard.syncTenantAPIKeys(h.manager)

	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant":  sanitizeTenantResponse(tenant),
		"api_key": apiKey,
	})
}

func (h *TenantAdminHandler) getTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeError(w, http.StatusServiceUnavailable, "multi-tenant mode not enabled")
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	if tenant == nil {
		writeError(w, http.StatusNotFound, "tenant not found")
		return
	}

	writeJSON(w, http.StatusOK, sanitizeTenantResponse(tenant))
}

func (h *TenantAdminHandler) updateTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeError(w, http.StatusServiceUnavailable, "multi-tenant mode not enabled")
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
		"active": true, "status": true, "plan": true,
		"email": true, "auto_rotation": true, "rotation_interval": true,
	}
	for k := range update {
		if !allowedKeys[k] {
			writeError(w, http.StatusBadRequest, "unknown field: "+k)
			return
		}
	}
	update = normalizeTenantAdminUpdate(update)

	if err := h.manager.UpdateTenant(tenantID, update); err != nil {
		writeError(w, http.StatusNotFound, sanitizeErr(err))
		return
	}

	tenant := h.manager.GetTenant(tenantID)
	writeJSON(w, http.StatusOK, sanitizeTenantResponse(tenant))
}

func (h *TenantAdminHandler) deleteTenant(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeError(w, http.StatusServiceUnavailable, "multi-tenant mode not enabled")
		return
	}

	if err := h.manager.DeleteTenant(tenantID); err != nil {
		writeError(w, http.StatusNotFound, sanitizeErr(err))
		return
	}
	h.dashboard.SetTenantAPIKey(tenantID, "")

	writeJSON(w, http.StatusNoContent, nil)
}

// sanitizeTenantResponse strips sensitive fields from a tenant object before it
// is returned from admin APIs. Tenant API keys are returned only by explicit
// create/regenerate-key responses, never embedded in tenant objects.
func sanitizeTenantResponse(tenant any) any {
	if tenant == nil {
		return nil
	}
	data, err := json.Marshal(tenant)
	if err != nil {
		return tenant
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return tenant
	}
	return sanitizeTenantMap(m)
}

func normalizeTenantAdminUpdate(update map[string]any) map[string]any {
	normalized := make(map[string]any, len(update))
	for k, v := range update {
		switch k {
		case "email", "auto_rotation", "rotation_interval":
			// Accepted for dashboard form compatibility. These fields are not
			// persisted by the current tenant manager model.
			continue
		case "status":
			if status, ok := v.(string); ok {
				normalized["active"] = status == "active" || status == "trial"
			}
		case "plan":
			normalized["billing_plan"] = v
		default:
			normalized[k] = v
		}
	}
	return normalized
}

func sanitizeTenantMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	for key, value := range m {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch normalized {
		case "api_key_hash", "key_hash":
			delete(m, key)
			continue
		case "api_key", "admin_key", "apikey", "adminkey":
			if s, ok := value.(string); ok && s != "" {
				m[key] = "[REDACTED]"
			}
			continue
		}

		switch typed := value.(type) {
		case map[string]any:
			m[key] = sanitizeTenantMap(typed)
		case []any:
			for i, item := range typed {
				if itemMap, ok := item.(map[string]any); ok {
					typed[i] = sanitizeTenantMap(itemMap)
				}
			}
			m[key] = typed
		}
	}
	active, _ := m["active"].(bool)
	if _, ok := m["status"]; !ok {
		if active {
			m["status"] = "active"
		} else {
			m["status"] = "suspended"
		}
	}
	if _, ok := m["plan"]; !ok {
		if plan, ok := m["billing_plan"].(string); ok && plan != "" {
			m["plan"] = plan
		} else {
			m["plan"] = "basic"
		}
	}
	if _, ok := m["email"]; !ok {
		m["email"] = ""
	}
	if _, ok := m["usage"]; !ok {
		m["usage"] = map[string]any{
			"requests_this_month": tenantNumber(m, "RequestCount", "request_count", "total_requests"),
			"blocked_requests":    tenantNumber(m, "BlockedCount", "blocked_count", "blocked_requests"),
		}
	}
	return m
}

func tenantNumber(m map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch v := m[key].(type) {
		case float64:
			return int64(v)
		case int64:
			return v
		case int:
			return int64(v)
		}
	}
	return 0
}

func (h *TenantAdminHandler) regenerateAPIKey(w http.ResponseWriter, r *http.Request, tenantID string) {
	if h.manager == nil {
		writeError(w, http.StatusServiceUnavailable, "multi-tenant mode not enabled")
		return
	}

	apiKey, err := h.manager.RegenerateAPIKey(tenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, sanitizeErr(err))
		return
	}
	// Replace the complete snapshot so the old hash is removed and the new hash
	// becomes effective immediately. Production managers expose current records
	// through ListTenants; lightweight adapters without records remain compatible.
	h.dashboard.syncTenantAPIKeys(h.manager)

	writeJSON(w, http.StatusOK, map[string]any{"api_key": apiKey})
}

func (h *TenantAdminHandler) handleStats(w http.ResponseWriter, r *http.Request) {
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

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *TenantAdminHandler) handleBillingDetail(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/billing/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "tenant ID required")
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
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}

		// Extract tenant data from map
		tenantMap, ok := tenant.(map[string]any)
		if !ok {
			writeError(w, http.StatusInternalServerError, "invalid tenant data")
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
			writeError(w, http.StatusInternalServerError, sanitizeErr(err))
			return
		}

		writeJSON(w, http.StatusCreated, invoice)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *TenantAdminHandler) handleAllUsage(w http.ResponseWriter, r *http.Request) {
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

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *TenantAdminHandler) handleUsageDetail(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/usage/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "tenant ID required")
		return
	}

	tenantID := strings.Split(path, "/")[0]

	// GET - Get usage for specific tenant
	if r.Method == http.MethodGet {
		usage := h.manager.GetTenantUsage(tenantID)
		if usage == nil {
			writeError(w, http.StatusNotFound, "tenant not found")
			return
		}
		writeJSON(w, http.StatusOK, usage)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *TenantAdminHandler) handleAlerts(w http.ResponseWriter, r *http.Request) {
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

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *TenantAdminHandler) handleTenantRules(w http.ResponseWriter, r *http.Request) {
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
			writeError(w, http.StatusBadRequest, "tenant_id query parameter required")
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
			writeError(w, http.StatusBadRequest, "tenant_id is required")
			return
		}
		if err := h.manager.AddTenantRule(req.TenantID, req.Rule); err != nil {
			writeError(w, http.StatusBadRequest, sanitizeErr(err))
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *TenantAdminHandler) handleTenantRuleDetail(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "multi-tenant mode not enabled",
		})
		return
	}

	// Path format: /api/admin/tenants/rules/{tenantID}/{ruleID}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/tenants/rules/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "tenant ID and rule ID required")
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		writeError(w, http.StatusBadRequest, "rule ID required")
		return
	}
	tenantID := parts[0]
	ruleID := parts[1]

	switch r.Method {
	case http.MethodGet:
		rule := h.manager.GetTenantRule(tenantID, ruleID)
		if rule == nil {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodPut:
		var rule map[string]any
		if !limitedDecodeJSON(w, r, &rule) {
			return
		}
		if err := h.manager.UpdateTenantRule(tenantID, rule); err != nil {
			writeError(w, http.StatusNotFound, sanitizeErr(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	case http.MethodDelete:
		if err := h.manager.RemoveTenantRule(tenantID, ruleID); err != nil {
			writeError(w, http.StatusNotFound, sanitizeErr(err))
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
			writeError(w, http.StatusNotFound, sanitizeErr(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "enabled": req.Enabled})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
