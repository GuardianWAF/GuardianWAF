package dashboard

import "net/http"

func (d *Dashboard) handleTenantListCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeJSON(w, http.StatusOK, map[string]any{"tenants": []any{}, "count": 0, "enabled": false})
		return
	}
	tenants := d.tenantManager.ListTenants()
	items := make([]any, len(tenants))
	for i, tenant := range tenants {
		items[i] = sanitizeTenantResponse(tenant)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": items, "count": len(items), "enabled": true})
}

func (d *Dashboard) handleTenantCreateCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Domain      string   `json:"domain"`
		Domains     []string `json:"domains"`
		Plan        string   `json:"plan"`
		Quota       any      `json:"quota,omitempty"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Domains) == 0 && req.Domain != "" {
		req.Domains = []string{req.Domain}
	}
	if len(req.Domains) == 0 {
		writeError(w, http.StatusBadRequest, "at least one domain is required")
		return
	}
	tenant, err := d.tenantManager.CreateTenant(req.Name, req.Description, req.Domains, req.Quota)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tenant": sanitizeTenantResponse(tenant)})
}

func (d *Dashboard) handleTenantGetCompat(w http.ResponseWriter, r *http.Request) {
	tenant, ok := d.compatTenant(w, r.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sanitizeTenantResponse(tenant))
}

func (d *Dashboard) handleTenantUpdateCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	var update map[string]any
	if !limitedDecodeJSON(w, r, &update) {
		return
	}
	id := r.PathValue("id")
	if err := d.tenantManager.UpdateTenant(id, update); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, sanitizeTenantResponse(d.tenantManager.GetTenant(id)))
}

func (d *Dashboard) handleTenantDeleteCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	if err := d.tenantManager.DeleteTenant(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (d *Dashboard) handleTenantConfigCompat(w http.ResponseWriter, r *http.Request) {
	tenant, ok := d.compatTenant(w, r.PathValue("id"))
	if !ok {
		return
	}
	if m, ok := sanitizeTenantResponse(tenant).(map[string]any); ok {
		if cfg, ok := m["waf_config"]; ok {
			writeJSON(w, http.StatusOK, cfg)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (d *Dashboard) handleTenantConfigUpdateCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	var cfg map[string]any
	if !limitedDecodeJSON(w, r, &cfg) {
		return
	}
	id := r.PathValue("id")
	if err := d.tenantManager.UpdateTenant(id, map[string]any{"waf_config": cfg}); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleTenantStatsCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	usage := d.tenantManager.GetTenantUsage(r.PathValue("id"))
	if usage == nil {
		writeJSON(w, http.StatusOK, map[string]any{"requests": 0, "blocks": 0})
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

func (d *Dashboard) handleTenantUsageCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	usage := d.tenantManager.GetTenantUsage(r.PathValue("id"))
	if usage == nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

func (d *Dashboard) handleTenantAllUsageCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeJSON(w, http.StatusOK, map[string]any{"usage": []any{}, "enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": d.tenantManager.GetAllUsage(), "enabled": true})
}

func (d *Dashboard) handleTenantAPIKeyCompat(w http.ResponseWriter, r *http.Request) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return
	}
	apiKey, err := d.tenantManager.RegenerateAPIKey(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_key": apiKey})
}

func (d *Dashboard) compatTenant(w http.ResponseWriter, id string) (any, bool) {
	if d.tenantManager == nil {
		writeTenantDisabled(w)
		return nil, false
	}
	tenant := d.tenantManager.GetTenant(id)
	if tenant == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "tenant not found"})
		return nil, false
	}
	return tenant, true
}

func writeTenantDisabled(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":   "multi-tenant mode not enabled",
		"enabled": false,
	})
}
