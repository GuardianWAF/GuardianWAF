package dashboard

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// registerRules registers rules CRUD and geoip routes.
func (d *Dashboard) registerRules(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/rules", d.authWrap(d.handleGetRules))
	mux.HandleFunc("POST /api/v1/rules", d.authAuditWrap(d.handleAddRule))
	mux.HandleFunc("PUT /api/v1/rules/{id}", d.authAuditWrap(d.handleUpdateRule))
	mux.HandleFunc("PATCH /api/v1/rules/{id}", d.authAuditWrap(d.handlePatchRule))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", d.authAuditWrap(d.handleDeleteRule))
	mux.HandleFunc("GET /api/v1/geoip/lookup", d.authWrap(d.handleGeoIPLookup))
	mux.HandleFunc("POST /api/v1/geoip/lookup", d.authWrap(d.handleGeoIPLookupPost))
}

// --- Rules ---

// SetRulesFns injects rule management functions to avoid circular imports.
// Internally assembles a ruleStoreAdapter to satisfy the RuleStore and GeoLookup interfaces.
func (d *Dashboard) SetRulesFns(
	getRules func() any,
	addRule func(map[string]any) error,
	updateRule func(string, map[string]any) error,
	deleteRule func(string) bool,
	toggleRule func(string, bool) bool,
	geoLookup func(string) (string, string),
) {
	d.ruleStore = &ruleStoreAdapter{
		getRules:   getRules,
		addRule:    addRule,
		updateRule: updateRule,
		deleteRule: deleteRule,
		toggleRule: toggleRule,
	}
	if geoLookup != nil {
		d.geoLookup = &geoLookupAdapter{fn: geoLookup}
	}
}

// ruleStoreAdapter wraps closure-based rule accessors as a RuleStore interface.
type ruleStoreAdapter struct {
	getRules   func() any
	addRule    func(map[string]any) error
	updateRule func(string, map[string]any) error
	deleteRule func(string) bool
	toggleRule func(string, bool) bool
}

func (r *ruleStoreAdapter) GetRules() any                    { return r.getRules() }
func (r *ruleStoreAdapter) AddRule(raw map[string]any) error { return r.addRule(raw) }
func (r *ruleStoreAdapter) UpdateRule(id string, raw map[string]any) error {
	return r.updateRule(id, raw)
}
func (r *ruleStoreAdapter) RemoveRule(id string) bool               { return r.deleteRule(id) }
func (r *ruleStoreAdapter) ToggleRule(id string, enabled bool) bool { return r.toggleRule(id, enabled) }

// geoLookupAdapter wraps a func(string) (string, string) as a GeoLookup interface.
type geoLookupAdapter struct{ fn func(string) (string, string) }

func (g *geoLookupAdapter) Lookup(ip string) (string, string) { return g.fn(ip) }

func (d *Dashboard) handleGetRules(w http.ResponseWriter, r *http.Request) {
	if d.ruleStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": filterRuleList(d.ruleStore.GetRules(), r.URL.Query())})
}

func filterRuleList(raw any, query url.Values) any {
	action := strings.TrimSpace(query.Get("action"))
	enabledRaw := strings.TrimSpace(query.Get("enabled"))
	search := strings.TrimSpace(query.Get("q"))
	if search == "" {
		search = strings.TrimSpace(query.Get("type"))
	}
	if action == "" && enabledRaw == "" && search == "" {
		return raw
	}

	rules := ruleListAsMaps(raw)
	filtered := make([]map[string]any, 0, len(rules))

	var enabledFilter *bool
	if enabledRaw != "" {
		if enabled, err := strconv.ParseBool(enabledRaw); err == nil {
			enabledFilter = &enabled
		}
	}

	for _, rule := range rules {
		if action != "" && !strings.EqualFold(ruleStringField(rule, "action"), action) {
			continue
		}
		if enabledFilter != nil && ruleBoolField(rule, "enabled") != *enabledFilter {
			continue
		}
		if search != "" && !ruleMatchesSearch(rule, search) {
			continue
		}
		filtered = append(filtered, rule)
	}

	return filtered
}

func ruleListAsMaps(raw any) []map[string]any {
	data, err := json.Marshal(raw)
	if err != nil {
		return []map[string]any{}
	}
	var rules []map[string]any
	if err := json.Unmarshal(data, &rules); err != nil {
		return []map[string]any{}
	}
	if rules == nil {
		return []map[string]any{}
	}
	return rules
}

func ruleStringField(rule map[string]any, field string) string {
	value, ok := rule[field]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func ruleBoolField(rule map[string]any, field string) bool {
	value, ok := rule[field]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(typed)
		return err == nil && parsed
	default:
		return false
	}
}

func ruleMatchesSearch(rule map[string]any, search string) bool {
	data, err := json.Marshal(rule)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), strings.ToLower(search))
}

func (d *Dashboard) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if d.ruleStore == nil {
		writeError(w, http.StatusNotImplemented, "rules not configured")
		return
	}
	var rule map[string]any
	if !limitedDecodeJSON(w, r, &rule) {
		return
	}
	if err := d.ruleStore.AddRule(rule); err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.ruleStore == nil {
		writeError(w, http.StatusNotImplemented, "rules not configured")
		return
	}
	var rule map[string]any
	if !limitedDecodeJSON(w, r, &rule) {
		return
	}
	if err := d.ruleStore.UpdateRule(id, rule); err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handlePatchRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.ruleStore == nil {
		writeError(w, http.StatusNotImplemented, "rules not configured")
		return
	}
	var patch map[string]any
	if !limitedDecodeJSON(w, r, &patch) {
		return
	}
	enabled, ok := patch["enabled"].(bool)
	if !ok {
		writeError(w, http.StatusBadRequest, "enabled boolean is required")
		return
	}
	if !d.ruleStore.ToggleRule(id, enabled) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.ruleStore == nil || !d.ruleStore.RemoveRule(id) {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip parameter required")
		return
	}
	// Validate that the input looks like an IP address
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}
	if d.geoLookup == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": "", "name": "GeoIP not configured"})
		return
	}
	code, name := d.geoLookup.Lookup(ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": code, "name": name})
}

// handleGeoIPLookupPost performs the same lookup as GET but accepts IP in request
// body to keep client IPs out of server-side access logs.
func (d *Dashboard) handleGeoIPLookupPost(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type: application/json required")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}
	if req.IP == "" {
		writeError(w, http.StatusBadRequest, "ip field required")
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "invalid ip address")
		return
	}
	if d.geoLookup == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": req.IP, "country": "", "name": "GeoIP not configured"})
		return
	}
	code, name := d.geoLookup.Lookup(req.IP)
	writeJSON(w, http.StatusOK, map[string]any{"ip": req.IP, "country": code, "name": name})
}
