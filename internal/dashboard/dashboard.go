// Package dashboard provides the web dashboard and REST API for GuardianWAF.
// It serves a real-time monitoring UI with SSE event streaming,
// REST endpoints for stats/events/config, and embedded static assets.
package dashboard

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

//go:embed dist
var distFS embed.FS

// Legacy static files kept for backward compatibility
//
//go:embed static/index.html static/style.css static/app.js static/config.html static/config.js static/routing.html static/routing.js
var staticFiles embed.FS

// tenantManagerInterface is the interface for multi-tenant management.
type tenantManagerInterface interface {
	ListTenants() []any
	GetTenant(id string) any
	CreateTenant(name, description string, domains []string, quota any) (any, error)
	UpdateTenant(id string, update any) error
	DeleteTenant(id string) error
	RegenerateAPIKey(id string) (string, error)
	Stats() any
	BillingManager() BillingManagerInterface
	AlertManager() AlertManagerInterface
	GetAllUsage() []any
	GetTenantUsage(tenantID string) any
	GetTenantRules(tenantID string) []any
	AddTenantRule(tenantID string, rule map[string]any) error
	GetTenantRule(tenantID, ruleID string) any
	UpdateTenantRule(tenantID string, rule map[string]any) error
	RemoveTenantRule(tenantID, ruleID string) error
	ToggleTenantRule(tenantID, ruleID string, enabled bool) error
}

// BillingManagerInterface is the interface for tenant billing.
type BillingManagerInterface interface {
	GetAllInvoices() []any
	GetInvoices(tenantID string) []any
	GetCurrentUsage(tenantID string) any
	GenerateInvoice(tenantID, tenantName string, plan string, periodStart, periodEnd time.Time) (any, error)
}

// AlertManagerInterface is the interface for tenant alerts.
type AlertManagerInterface interface {
	GetRecentAlerts(since time.Duration) []any
}

// Dashboard is the web dashboard server.
type Dashboard struct {
	engine          *engine.Engine
	eventStore      events.EventStore
	sse             *SSEBroadcaster
	mux             *http.ServeMux
	apiKey          string
	upstreamsFn     func() any   // returns upstream status (injected to avoid circular imports)
	rebuildFn       func() error // rebuilds proxy after config change
	saveFn          func() error // persists current config to disk
	rulesFn         func() any   // returns rules list
	addRuleFn       func(map[string]any) error
	updateRuleFn    func(string, map[string]any) error
	deleteRuleFn    func(string) bool
	toggleRuleFn    func(string, bool) bool
	geoLookupFn     func(string) (string, string) // ip -> (country_code, country_name)
	alertingStatsFn func() any                    // returns alerting stats (optional)
	aiAnalyzer      aiAnalyzerInterface           // AI threat analyzer (optional)
	dockerWatcher   dockerWatcherInterface        // Docker auto-discovery (optional)
	tenantManager   tenantManagerInterface        // Multi-tenant manager (optional)
	certFn          func() any                    // returns SSL cert status (optional)
}

// New creates a new Dashboard wired to the given engine and event store.
func New(eng *engine.Engine, store events.EventStore, apiKey string) *Dashboard {
	d := &Dashboard{
		engine:     eng,
		eventStore: store,
		sse:        NewSSEBroadcaster(),
		mux:        http.NewServeMux(),
		apiKey:     apiKey,
	}

	// Login/logout (always accessible)
	d.mux.HandleFunc("GET /login", d.handleLoginPage)
	d.mux.HandleFunc("POST /login", d.handleLoginSubmit)
	d.mux.HandleFunc("GET /logout", d.handleLogout)

	// Health check (always accessible, no sensitive data)
	d.mux.HandleFunc("GET /api/v1/health", d.handleHealth)

	// Protected API routes
	d.mux.HandleFunc("GET /api/v1/stats", d.authWrap(d.handleGetStats))
	d.mux.HandleFunc("GET /api/v1/events", d.authWrap(d.handleGetEvents))
	d.mux.HandleFunc("GET /api/v1/events/export", d.authWrap(d.handleExportEvents))
	d.mux.HandleFunc("GET /api/v1/events/{id}", d.authWrap(d.handleGetEvent))
	d.mux.HandleFunc("GET /api/v1/ssl", d.authWrap(d.handleGetCerts))
	d.mux.HandleFunc("GET /api/v1/upstreams", d.authWrap(d.handleGetUpstreams))
	d.mux.HandleFunc("GET /api/v1/config", d.authWrap(d.handleGetConfig))
	d.mux.HandleFunc("PUT /api/v1/config", d.authWrap(d.handleUpdateConfig))
	d.mux.HandleFunc("OPTIONS /api/v1/config", handleCORS)
	d.mux.HandleFunc("GET /api/v1/routing", d.authWrap(d.handleGetRouting))
	d.mux.HandleFunc("PUT /api/v1/routing", d.authWrap(d.handleUpdateRouting))
	d.mux.HandleFunc("OPTIONS /api/v1/routing", handleCORS)
	d.mux.HandleFunc("GET /api/v1/ipacl", d.authWrap(d.handleGetIPACL))
	d.mux.HandleFunc("POST /api/v1/ipacl", d.authWrap(d.handleAddIPACL))
	d.mux.HandleFunc("DELETE /api/v1/ipacl", d.authWrap(d.handleRemoveIPACL))
	d.mux.HandleFunc("GET /api/v1/bans", d.authWrap(d.handleGetBans))
	d.mux.HandleFunc("POST /api/v1/bans", d.authWrap(d.handleAddBan))
	d.mux.HandleFunc("DELETE /api/v1/bans", d.authWrap(d.handleRemoveBan))
	d.mux.HandleFunc("OPTIONS /api/v1/ipacl", handleCORS)
	d.mux.HandleFunc("GET /api/v1/rules", d.authWrap(d.handleGetRules))
	d.mux.HandleFunc("POST /api/v1/rules", d.authWrap(d.handleAddRule))
	d.mux.HandleFunc("PUT /api/v1/rules/{id}", d.authWrap(d.handleUpdateRule))
	d.mux.HandleFunc("DELETE /api/v1/rules/{id}", d.authWrap(d.handleDeleteRule))
	d.mux.HandleFunc("GET /api/v1/geoip/lookup", d.authWrap(d.handleGeoIPLookup))
	d.mux.HandleFunc("GET /api/v1/logs", d.authWrap(d.handleGetLogs))
	d.mux.HandleFunc("GET /api/v1/sse", d.authWrap(d.handleSSE))

	// AI Analysis endpoints
	d.mux.HandleFunc("GET /api/v1/ai/providers", d.authWrap(d.handleAIProviders))
	d.mux.HandleFunc("GET /api/v1/ai/config", d.authWrap(d.handleAIGetConfig))
	d.mux.HandleFunc("PUT /api/v1/ai/config", d.authWrap(d.handleAISetConfig))
	d.mux.HandleFunc("GET /api/v1/ai/history", d.authWrap(d.handleAIHistory))
	d.mux.HandleFunc("GET /api/v1/ai/stats", d.authWrap(d.handleAIStats))
	d.mux.HandleFunc("POST /api/v1/ai/analyze", d.authWrap(d.handleAIAnalyze))
	d.mux.HandleFunc("POST /api/v1/ai/test", d.authWrap(d.handleAITest))

	// Alerting endpoints
	d.mux.HandleFunc("GET /api/v1/alerting/status", d.authWrap(d.handleAlertingStatus))
	d.mux.HandleFunc("GET /api/v1/alerting/webhooks", d.authWrap(d.handleGetWebhooks))
	d.mux.HandleFunc("POST /api/v1/alerting/webhooks", d.authWrap(d.handleAddWebhook))
	d.mux.HandleFunc("DELETE /api/v1/alerting/webhooks/{name}", d.authWrap(d.handleDeleteWebhook))
	d.mux.HandleFunc("GET /api/v1/alerting/emails", d.authWrap(d.handleGetEmails))
	d.mux.HandleFunc("POST /api/v1/alerting/emails", d.authWrap(d.handleAddEmail))
	d.mux.HandleFunc("DELETE /api/v1/alerting/emails/{name}", d.authWrap(d.handleDeleteEmail))
	d.mux.HandleFunc("POST /api/v1/alerting/test", d.authWrap(d.handleTestAlert))

	// Docker auto-discovery endpoints
	d.mux.HandleFunc("GET /api/v1/docker/services", d.authWrap(d.handleDockerServices))

	// SPA serving — React build output from dist/ with fallback to legacy static/
	d.mux.HandleFunc("GET /assets/", d.handleDistAssets)       // Vite hashed assets — public (content-hashed, no secrets)
	d.mux.HandleFunc("GET /ssl", d.authWrap(d.handleSPA)) // SPA routes
	d.mux.HandleFunc("GET /config", d.authWrap(d.handleSPA))   // SPA routes
	d.mux.HandleFunc("GET /routing", d.authWrap(d.handleSPA))  // SPA routes
	d.mux.HandleFunc("GET /alerting", d.authWrap(d.handleSPA)) // SPA routes
	d.mux.HandleFunc("GET /logs", d.authWrap(d.handleSPA))     // SPA routes
	d.mux.HandleFunc("GET /rules", d.authWrap(d.handleSPA))    // SPA routes
	d.mux.HandleFunc("GET /ai", d.authWrap(d.handleSPA))       // SPA routes
	d.mux.HandleFunc("/", d.authWrap(d.handleSPA))             // SPA catch-all

	return d
}

// Handler returns the root http.Handler.
func (d *Dashboard) Handler() http.Handler {
	return d.mux
}

// Mux returns the underlying ServeMux for registering additional routes.
func (d *Dashboard) Mux() *http.ServeMux {
	return d.mux
}

// SSE returns the SSE broadcaster for publishing events from outside.
func (d *Dashboard) SSE() *SSEBroadcaster {
	return d.sse
}

// --- Auth ---

func (d *Dashboard) authWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.isAuthenticated(r) {
			// API requests get 401 JSON, browser requests get redirected to login
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		handler(w, r)
	}
}

func (d *Dashboard) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if d.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginPage("")))
}

func (d *Dashboard) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	key := r.FormValue("key")
	if subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) != 1 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(loginPage("Invalid API key. Please try again.")))
		return
	}
	setSessionCookie(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (d *Dashboard) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// --- Stats ---

func (d *Dashboard) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := d.engine.Stats()
	result := map[string]any{
		"total_requests":      stats.TotalRequests,
		"blocked_requests":    stats.BlockedRequests,
		"challenged_requests": stats.ChallengedRequests,
		"logged_requests":     stats.LoggedRequests,
		"passed_requests":     stats.PassedRequests,
		"avg_latency_us":      stats.AvgLatencyUs,
	}
	if d.alertingStatsFn != nil {
		result["alerting"] = d.alertingStatsFn()
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Events ---

func (d *Dashboard) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, 1000)
		}
	}

	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	filter := events.EventFilter{
		Limit:     limit,
		Offset:    offset,
		Action:    q.Get("action"),
		ClientIP:  q.Get("client_ip"),
		Path:      q.Get("path"),
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.MinScore = n
		}
	}

	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	evts, total, err := d.eventStore.Query(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": evts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (d *Dashboard) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing event ID"})
		return
	}

	evt, err := d.eventStore.Get(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "event not found"})
		return
	}

	writeJSON(w, http.StatusOK, evt)
}

// handleExportEvents exports events to JSON or CSV format.
// Query params: format (json|csv), action, client_ip, path, min_score, since, until
func (d *Dashboard) handleExportEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid format, use 'json' or 'csv'"})
		return
	}

	// Build filter (same as handleGetEvents but with higher limit for exports)
	filter := events.EventFilter{
		Action:    q.Get("action"),
		ClientIP:  q.Get("client_ip"),
		Path:      q.Get("path"),
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	// Export limit: default 10000, max 50000
	filter.Limit = 10000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = min(n, 50000)
		}
	}

	if v := q.Get("min_score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.MinScore = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = t
		}
	}

	evts, _, err := d.eventStore.Query(filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	switch format {
	case "csv":
		d.writeEventsCSV(w, evts)
	default:
		d.writeEventsJSON(w, evts)
	}
}

func (d *Dashboard) writeEventsJSON(w http.ResponseWriter, evts []engine.Event) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"events.json\"")
	writeJSON(w, http.StatusOK, map[string]any{"events": evts, "count": len(evts)})
}

func (d *Dashboard) writeEventsCSV(w http.ResponseWriter, evts []engine.Event) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"events.csv\"")

	// CSV header
	header := "timestamp,event_id,client_ip,method,path,action,score,user_agent,findings\n"
	_, _ = w.Write([]byte(header))

	// CSV rows
	for _, e := range evts {
		findings := ""
		for i, f := range e.Findings {
			if i > 0 {
				findings += "; "
			}
			findings += f.DetectorName + ":" + f.Description
		}
		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s,%d,\"%s\",\"%s\"\n",
			e.Timestamp.Format(time.RFC3339),
			e.ID,
			e.ClientIP,
			e.Method,
			escapeCSV(e.Path),
			e.Action.String(),
			e.Score,
			escapeCSV(e.UserAgent),
			escapeCSV(findings),
		)
		_, _ = w.Write([]byte(line))
	}
}

// escapeCSV escapes a string for CSV output.
func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// --- Upstreams ---

// SetRebuildFn sets the function called after routing config changes to rebuild the proxy.
func (d *Dashboard) SetRebuildFn(fn func() error) {
	d.rebuildFn = fn
}

// SetSaveFn sets the function used to persist config changes to disk.
func (d *Dashboard) SetSaveFn(fn func() error) {
	d.saveFn = fn
}

// --- Routing (Upstreams + Virtual Hosts + Routes) ---

func (d *Dashboard) handleGetRouting(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()

	// Serialize upstreams
	upstreams := make([]map[string]any, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		targets := make([]map[string]any, len(u.Targets))
		for j, t := range u.Targets {
			targets[j] = map[string]any{"url": t.URL, "weight": t.Weight}
		}
		upstreams[i] = map[string]any{
			"name":          u.Name,
			"load_balancer": u.LoadBalancer,
			"targets":       targets,
			"health_check": map[string]any{
				"enabled":  u.HealthCheck.Enabled,
				"interval": u.HealthCheck.Interval.String(),
				"timeout":  u.HealthCheck.Timeout.String(),
				"path":     u.HealthCheck.Path,
			},
		}
	}

	// Serialize virtual hosts
	vhosts := make([]map[string]any, len(cfg.VirtualHosts))
	for i, vh := range cfg.VirtualHosts {
		routes := make([]map[string]any, len(vh.Routes))
		for j, r := range vh.Routes {
			routes[j] = map[string]any{
				"path":         r.Path,
				"upstream":     r.Upstream,
				"strip_prefix": r.StripPrefix,
			}
		}
		vhosts[i] = map[string]any{
			"domains": vh.Domains,
			"tls": map[string]any{
				"cert_file": vh.TLS.CertFile,
				"key_file":  vh.TLS.KeyFile,
			},
			"routes": routes,
		}
	}

	// Serialize default routes
	routes := make([]map[string]any, len(cfg.Routes))
	for i, r := range cfg.Routes {
		routes[i] = map[string]any{
			"path":         r.Path,
			"upstream":     r.Upstream,
			"strip_prefix": r.StripPrefix,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"upstreams":     upstreams,
		"virtual_hosts": vhosts,
		"routes":        routes,
	})
}

func (d *Dashboard) handleUpdateRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Upstreams    []map[string]any `json:"upstreams"`
		VirtualHosts []map[string]any `json:"virtual_hosts"`
		Routes       []map[string]any `json:"routes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}

	cfg := d.engine.Config()

	// Parse upstreams from raw JSON maps
	if body.Upstreams != nil {
		var upstreams []config.UpstreamConfig
		for _, raw := range body.Upstreams {
			u := config.UpstreamConfig{}
			if v, ok := raw["name"].(string); ok {
				u.Name = v
			}
			if v, ok := raw["load_balancer"].(string); ok {
				u.LoadBalancer = v
			}
			if targets, ok := raw["targets"].([]any); ok {
				for _, t := range targets {
					tm, ok := t.(map[string]any)
					if !ok {
						continue
					}
					tc := config.TargetConfig{Weight: 1}
					if v, ok := tm["url"].(string); ok {
						tc.URL = v
					}
					if v, ok := tm["weight"].(float64); ok {
						tc.Weight = int(v)
					}
					u.Targets = append(u.Targets, tc)
				}
			}
			// Preserve existing health check config if upstream name matches
			for _, existing := range cfg.Upstreams {
				if existing.Name == u.Name {
					u.HealthCheck = existing.HealthCheck
					break
				}
			}
			upstreams = append(upstreams, u)
		}
		cfg.Upstreams = upstreams
	}

	// Parse virtual hosts
	if body.VirtualHosts != nil {
		var vhosts []config.VirtualHostConfig
		for _, raw := range body.VirtualHosts {
			vh := config.VirtualHostConfig{}
			if domains, ok := raw["domains"].([]any); ok {
				for _, d := range domains {
					if s, ok := d.(string); ok {
						vh.Domains = append(vh.Domains, s)
					}
				}
			}
			if tls, ok := raw["tls"].(map[string]any); ok {
				if v, ok := tls["cert_file"].(string); ok {
					vh.TLS.CertFile = v
				}
				if v, ok := tls["key_file"].(string); ok {
					vh.TLS.KeyFile = v
				}
			}
			if routes, ok := raw["routes"].([]any); ok {
				for _, r := range routes {
					rm, ok := r.(map[string]any)
					if !ok {
						continue
					}
					rc := config.RouteConfig{}
					if v, ok := rm["path"].(string); ok {
						rc.Path = v
					}
					if v, ok := rm["upstream"].(string); ok {
						rc.Upstream = v
					}
					if v, ok := rm["strip_prefix"].(bool); ok {
						rc.StripPrefix = v
					}
					vh.Routes = append(vh.Routes, rc)
				}
			}
			vhosts = append(vhosts, vh)
		}
		cfg.VirtualHosts = vhosts
	}

	// Parse default routes
	if body.Routes != nil {
		var routes []config.RouteConfig
		for _, raw := range body.Routes {
			rc := config.RouteConfig{}
			if v, ok := raw["path"].(string); ok {
				rc.Path = v
			}
			if v, ok := raw["upstream"].(string); ok {
				rc.Upstream = v
			}
			if v, ok := raw["strip_prefix"].(bool); ok {
				rc.StripPrefix = v
			}
			routes = append(routes, rc)
		}
		cfg.Routes = routes
	}

	// Validate
	ve := &config.ValidationError{}
	config.ValidateUpstreamsExported(cfg.Upstreams, ve)
	config.ValidateRoutesExported(cfg.Routes, cfg.Upstreams, ve)
	config.ValidateVirtualHostsExported(cfg.VirtualHosts, cfg.Upstreams, ve)
	if ve.HasErrors() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ve.Error()})
		return
	}

	// Reload config
	if err := d.engine.Reload(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Rebuild proxy
	if d.rebuildFn != nil {
		if err := d.rebuildFn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "proxy rebuild: " + err.Error()})
			return
		}
	}

	// Persist to disk
	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Routing updated (save to disk failed: " + err.Error() + ")"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Routing updated and saved"})
}

// SetUpstreamsFn sets the function that returns upstream health status.
func (d *Dashboard) SetUpstreamsFn(fn func() any) {
	d.upstreamsFn = fn
}

// SetCertFn sets the function that returns SSL certificate status.
func (d *Dashboard) SetCertFn(fn func() any) {
	d.certFn = fn
}

func (d *Dashboard) handleGetUpstreams(w http.ResponseWriter, r *http.Request) {
	if d.upstreamsFn == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, d.upstreamsFn())
}

// --- SSL Certs ---

func (d *Dashboard) handleGetCerts(w http.ResponseWriter, r *http.Request) {
	if d.certFn == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": false,
			"certs":   []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, d.certFn())
}

// --- Config ---

func (d *Dashboard) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": cfg.Mode,
		"tls": map[string]any{
			"enabled":       cfg.TLS.Enabled,
			"listen":        cfg.TLS.Listen,
			"cert_file":     cfg.TLS.CertFile,
			"key_file":      cfg.TLS.KeyFile,
			"http_redirect": cfg.TLS.HTTPRedirect,
			"acme": map[string]any{
				"enabled":   cfg.TLS.ACME.Enabled,
				"email":     cfg.TLS.ACME.Email,
				"domains":   cfg.TLS.ACME.Domains,
				"cache_dir": cfg.TLS.ACME.CacheDir,
			},
		},
		"waf": map[string]any{
			"ip_acl": map[string]any{
				"enabled":   cfg.WAF.IPACL.Enabled,
				"whitelist": cfg.WAF.IPACL.Whitelist,
				"blacklist": cfg.WAF.IPACL.Blacklist,
				"auto_ban": map[string]any{
					"enabled":     cfg.WAF.IPACL.AutoBan.Enabled,
					"default_ttl": cfg.WAF.IPACL.AutoBan.DefaultTTL.String(),
					"max_ttl":     cfg.WAF.IPACL.AutoBan.MaxTTL.String(),
				},
			},
			"rate_limit": map[string]any{
				"enabled": cfg.WAF.RateLimit.Enabled,
				"rules":   cfg.WAF.RateLimit.Rules,
			},
			"sanitizer": map[string]any{
				"enabled":            cfg.WAF.Sanitizer.Enabled,
				"max_url_length":     cfg.WAF.Sanitizer.MaxURLLength,
				"max_header_size":    cfg.WAF.Sanitizer.MaxHeaderSize,
				"max_header_count":   cfg.WAF.Sanitizer.MaxHeaderCount,
				"max_body_size":      cfg.WAF.Sanitizer.MaxBodySize,
				"max_cookie_size":    cfg.WAF.Sanitizer.MaxCookieSize,
				"block_null_bytes":   cfg.WAF.Sanitizer.BlockNullBytes,
				"normalize_encoding": cfg.WAF.Sanitizer.NormalizeEncoding,
			},
			"detection": map[string]any{
				"enabled": cfg.WAF.Detection.Enabled,
				"threshold": map[string]any{
					"block": cfg.WAF.Detection.Threshold.Block,
					"log":   cfg.WAF.Detection.Threshold.Log,
				},
				"detectors": cfg.WAF.Detection.Detectors,
			},
			"bot_detection": map[string]any{
				"enabled": cfg.WAF.BotDetection.Enabled,
				"mode":    cfg.WAF.BotDetection.Mode,
				"tls_fingerprint": map[string]any{
					"enabled": cfg.WAF.BotDetection.TLSFingerprint.Enabled,
				},
				"user_agent": map[string]any{
					"enabled":              cfg.WAF.BotDetection.UserAgent.Enabled,
					"block_empty":          cfg.WAF.BotDetection.UserAgent.BlockEmpty,
					"block_known_scanners": cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
				},
				"behavior": map[string]any{
					"enabled":              cfg.WAF.BotDetection.Behavior.Enabled,
					"window":               cfg.WAF.BotDetection.Behavior.Window.String(),
					"rps_threshold":        cfg.WAF.BotDetection.Behavior.RPSThreshold,
					"error_rate_threshold": cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
				},
			},
			"challenge": map[string]any{
				"enabled":     cfg.WAF.Challenge.Enabled,
				"difficulty":  cfg.WAF.Challenge.Difficulty,
				"cookie_ttl":  cfg.WAF.Challenge.CookieTTL.String(),
				"cookie_name": cfg.WAF.Challenge.CookieName,
			},
			"response": map[string]any{
				"security_headers": map[string]any{
					"enabled":                cfg.WAF.Response.SecurityHeaders.Enabled,
					"x_frame_options":        cfg.WAF.Response.SecurityHeaders.XFrameOptions,
					"referrer_policy":        cfg.WAF.Response.SecurityHeaders.ReferrerPolicy,
					"x_content_type_options": cfg.WAF.Response.SecurityHeaders.XContentTypeOptions,
					"hsts": map[string]any{
						"enabled":            cfg.WAF.Response.SecurityHeaders.HSTS.Enabled,
						"max_age":            cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge,
						"include_subdomains": cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains,
					},
				},
				"data_masking": map[string]any{
					"enabled":            cfg.WAF.Response.DataMasking.Enabled,
					"mask_credit_cards":  cfg.WAF.Response.DataMasking.MaskCreditCards,
					"mask_ssn":           cfg.WAF.Response.DataMasking.MaskSSN,
					"mask_api_keys":      cfg.WAF.Response.DataMasking.MaskAPIKeys,
					"strip_stack_traces": cfg.WAF.Response.DataMasking.StripStackTraces,
				},
			},
			"cors": map[string]any{
				"enabled":           cfg.WAF.CORS.Enabled,
				"allow_origins":     cfg.WAF.CORS.AllowOrigins,
				"allow_methods":     cfg.WAF.CORS.AllowMethods,
				"allow_headers":     cfg.WAF.CORS.AllowHeaders,
				"allow_credentials": cfg.WAF.CORS.AllowCredentials,
				"strict_mode":       cfg.WAF.CORS.StrictMode,
			},
			"threat_intel": map[string]any{
				"enabled":    cfg.WAF.ThreatIntel.Enabled,
				"cache_size": cfg.WAF.ThreatIntel.CacheSize,
				"ip_reputation": map[string]any{
					"enabled":         cfg.WAF.ThreatIntel.IPReputation.Enabled,
					"block_malicious": cfg.WAF.ThreatIntel.IPReputation.BlockMalicious,
					"score_threshold": cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold,
				},
				"domain_reputation": map[string]any{
					"enabled":         cfg.WAF.ThreatIntel.DomainRep.Enabled,
					"block_malicious": cfg.WAF.ThreatIntel.DomainRep.BlockMalicious,
				},
			},
			"ato_protection": map[string]any{
				"enabled":     cfg.WAF.ATOProtection.Enabled,
				"login_paths": cfg.WAF.ATOProtection.LoginPaths,
				"brute_force": map[string]any{
					"enabled":                cfg.WAF.ATOProtection.BruteForce.Enabled,
					"max_attempts_per_ip":    cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP,
					"max_attempts_per_email": cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail,
				},
				"credential_stuffing": map[string]any{
					"enabled":               cfg.WAF.ATOProtection.CredStuffing.Enabled,
					"distributed_threshold": cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold,
				},
				"impossible_travel": map[string]any{
					"enabled":         cfg.WAF.ATOProtection.Travel.Enabled,
					"max_distance_km": cfg.WAF.ATOProtection.Travel.MaxDistanceKm,
				},
			},
			"api_security": map[string]any{
				"enabled": cfg.WAF.APISecurity.Enabled,
				"jwt": map[string]any{
					"enabled":    cfg.WAF.APISecurity.JWT.Enabled,
					"issuer":     cfg.WAF.APISecurity.JWT.Issuer,
					"audience":   cfg.WAF.APISecurity.JWT.Audience,
					"algorithms": cfg.WAF.APISecurity.JWT.Algorithms,
					"jwks_url":   cfg.WAF.APISecurity.JWT.JWKSURL,
				},
				"api_keys": map[string]any{
					"enabled":     cfg.WAF.APISecurity.APIKeys.Enabled,
					"header_name": cfg.WAF.APISecurity.APIKeys.HeaderName,
					"key_count":   len(cfg.WAF.APISecurity.APIKeys.Keys),
				},
			},
		},
		"docker": map[string]any{
			"enabled":       cfg.Docker.Enabled,
			"socket_path":   cfg.Docker.SocketPath,
			"label_prefix":  cfg.Docker.LabelPrefix,
			"poll_interval": cfg.Docker.PollInterval.String(),
			"network":       cfg.Docker.Network,
		},
		"ai_analysis": map[string]any{
			"enabled":    cfg.WAF.AIAnalysis.Enabled,
			"batch_size": cfg.WAF.AIAnalysis.BatchSize,
			"min_score":  cfg.WAF.AIAnalysis.MinScore,
			"auto_block": cfg.WAF.AIAnalysis.AutoBlock,
		},
		"alerting": map[string]any{
			"enabled":       cfg.Alerting.Enabled,
			"webhook_count": len(cfg.Alerting.Webhooks),
		},
	})
}

func (d *Dashboard) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}

	cfg := d.engine.Config()

	// Apply top-level mode
	if v, ok := patch["mode"].(string); ok {
		cfg.Mode = v
	}

	// Apply TLS section patches
	if tls, ok := patch["tls"].(map[string]any); ok {
		if v, ok := tls["enabled"].(bool); ok {
			cfg.TLS.Enabled = v
		}
		if v, ok := tls["listen"].(string); ok {
			cfg.TLS.Listen = v
		}
		if v, ok := tls["cert_file"].(string); ok {
			cfg.TLS.CertFile = v
		}
		if v, ok := tls["key_file"].(string); ok {
			cfg.TLS.KeyFile = v
		}
		if v, ok := tls["http_redirect"].(bool); ok {
			cfg.TLS.HTTPRedirect = v
		}
		if acme, ok := tls["acme"].(map[string]any); ok {
			if v, ok := acme["enabled"].(bool); ok {
				cfg.TLS.ACME.Enabled = v
			}
			if v, ok := acme["email"].(string); ok {
				cfg.TLS.ACME.Email = v
			}
			if v, ok := acme["cache_dir"].(string); ok {
				cfg.TLS.ACME.CacheDir = v
			}
		}
	}

	// Apply WAF section patches
	if waf, ok := patch["waf"].(map[string]any); ok {
		applyWAFPatch(cfg, waf)
	}

	// Apply Docker section patches
	if docker, ok := patch["docker"].(map[string]any); ok {
		if v, ok := docker["enabled"].(bool); ok {
			cfg.Docker.Enabled = v
		}
		if v, ok := docker["socket_path"].(string); ok {
			cfg.Docker.SocketPath = v
		}
		if v, ok := docker["label_prefix"].(string); ok {
			cfg.Docker.LabelPrefix = v
		}
		if v, ok := docker["network"].(string); ok {
			cfg.Docker.Network = v
		}
	}

	// Apply AI Analysis section patches
	if ai, ok := patch["ai_analysis"].(map[string]any); ok {
		if v, ok := ai["enabled"].(bool); ok {
			cfg.WAF.AIAnalysis.Enabled = v
		}
		if v, ok := ai["batch_size"].(float64); ok {
			cfg.WAF.AIAnalysis.BatchSize = int(v)
		}
		if v, ok := ai["min_score"].(float64); ok {
			cfg.WAF.AIAnalysis.MinScore = int(v)
		}
		if v, ok := ai["auto_block"].(bool); ok {
			cfg.WAF.AIAnalysis.AutoBlock = v
		}
	}

	// Apply Alerting section patches
	if alerting, ok := patch["alerting"].(map[string]any); ok {
		if v, ok := alerting["enabled"].(bool); ok {
			cfg.Alerting.Enabled = v
		}
	}

	if err := d.engine.Reload(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// Persist to disk
	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated (save to disk failed: " + err.Error() + ")"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated and saved"})
}

// --- IP ACL ---

// ipaclLayer is the interface we need from the ipacl layer (avoids circular import).
type ipaclLayer interface {
	AddWhitelist(cidr string) error
	RemoveWhitelist(cidr string) error
	AddBlacklist(cidr string) error
	RemoveBlacklist(cidr string) error
	WhitelistEntries() []string
	BlacklistEntries() []string
}

func (d *Dashboard) getIPACLLayer() (ipaclLayer, bool) {
	l := d.engine.FindLayer("ipacl")
	if l == nil {
		return nil, false
	}
	acl, ok := l.(ipaclLayer)
	return acl, ok
}

func (d *Dashboard) handleGetIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"whitelist": []string{},
			"blacklist": []string{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": acl.WhitelistEntries(),
		"blacklist": acl.BlacklistEntries(),
	})
}

func (d *Dashboard) handleAddIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
		return
	}

	var body struct {
		List string `json:"list"` // "whitelist" or "blacklist"
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.AddWhitelist(body.IP)
	case "blacklist":
		err = acl.AddBlacklist(body.IP)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "list must be 'whitelist' or 'blacklist'"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "list": body.List})
}

func (d *Dashboard) handleRemoveIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
		return
	}

	var body struct {
		List string `json:"list"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.RemoveWhitelist(body.IP)
	case "blacklist":
		err = acl.RemoveBlacklist(body.IP)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "list must be 'whitelist' or 'blacklist'"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "list": body.List})
}

// --- Temporary Bans ---

// banLayer is the interface for temp ban operations (avoids circular import).
type banLayer interface {
	AddAutoBan(ip string, reason string, ttl time.Duration)
	RemoveAutoBan(ip string)
}

func (d *Dashboard) handleGetBans(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeJSON(w, http.StatusOK, map[string]any{"bans": []any{}})
		return
	}
	type banLister interface{ ActiveBansAny() any }
	if lister, ok := bl.(banLister); ok {
		writeJSON(w, http.StatusOK, map[string]any{"bans": lister.ActiveBansAny()})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"bans": []any{}})
	}
}

func (d *Dashboard) handleAddBan(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
		return
	}
	var body struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"` // e.g. "30m", "1h", "24h"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}
	ttl, err := time.ParseDuration(body.Duration)
	if err != nil || ttl <= 0 {
		ttl = 1 * time.Hour // default 1 hour
	}
	if body.Reason == "" {
		body.Reason = "manual ban from dashboard"
	}
	bl.AddAutoBan(body.IP, body.Reason, ttl)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "duration": ttl.String()})
}

func (d *Dashboard) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}
	bl.RemoveAutoBan(body.IP)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP})
}

func (d *Dashboard) getBanLayer() banLayer {
	l := d.engine.FindLayer("ipacl")
	if l == nil {
		return nil
	}
	bl, ok := l.(banLayer)
	if !ok {
		return nil
	}
	return bl
}

// applyWAFPatch applies partial config updates from a JSON patch object.
func applyWAFPatch(cfg *config.Config, waf map[string]any) {
	if det, ok := waf["detection"].(map[string]any); ok {
		if v, ok := det["enabled"].(bool); ok {
			cfg.WAF.Detection.Enabled = v
		}
		if th, ok := det["threshold"].(map[string]any); ok {
			if v, ok := th["block"].(float64); ok {
				cfg.WAF.Detection.Threshold.Block = int(v)
			}
			if v, ok := th["log"].(float64); ok {
				cfg.WAF.Detection.Threshold.Log = int(v)
			}
		}
		if detectors, ok := det["detectors"].(map[string]any); ok {
			for name, raw := range detectors {
				d, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				dc := cfg.WAF.Detection.Detectors[name]
				if v, ok := d["enabled"].(bool); ok {
					dc.Enabled = v
				}
				if v, ok := d["multiplier"].(float64); ok {
					dc.Multiplier = v
				}
				cfg.WAF.Detection.Detectors[name] = dc
			}
		}
	}

	if rl, ok := waf["rate_limit"].(map[string]any); ok {
		if v, ok := rl["enabled"].(bool); ok {
			cfg.WAF.RateLimit.Enabled = v
		}
	}

	if san, ok := waf["sanitizer"].(map[string]any); ok {
		if v, ok := san["enabled"].(bool); ok {
			cfg.WAF.Sanitizer.Enabled = v
		}
		if v, ok := san["max_body_size"].(float64); ok {
			cfg.WAF.Sanitizer.MaxBodySize = int64(v)
		}
		if v, ok := san["max_url_length"].(float64); ok {
			cfg.WAF.Sanitizer.MaxURLLength = int(v)
		}
	}

	if bd, ok := waf["bot_detection"].(map[string]any); ok {
		if v, ok := bd["enabled"].(bool); ok {
			cfg.WAF.BotDetection.Enabled = v
		}
		if v, ok := bd["mode"].(string); ok {
			cfg.WAF.BotDetection.Mode = v
		}
		if ua, ok := bd["user_agent"].(map[string]any); ok {
			if v, ok := ua["block_empty"].(bool); ok {
				cfg.WAF.BotDetection.UserAgent.BlockEmpty = v
			}
			if v, ok := ua["block_known_scanners"].(bool); ok {
				cfg.WAF.BotDetection.UserAgent.BlockKnownScanners = v
			}
		}
		if beh, ok := bd["behavior"].(map[string]any); ok {
			if v, ok := beh["rps_threshold"].(float64); ok {
				cfg.WAF.BotDetection.Behavior.RPSThreshold = int(v)
			}
			if v, ok := beh["error_rate_threshold"].(float64); ok {
				cfg.WAF.BotDetection.Behavior.ErrorRateThreshold = int(v)
			}
		}
	}

	if ch, ok := waf["challenge"].(map[string]any); ok {
		if v, ok := ch["enabled"].(bool); ok {
			cfg.WAF.Challenge.Enabled = v
		}
		if v, ok := ch["difficulty"].(float64); ok {
			cfg.WAF.Challenge.Difficulty = int(v)
		}
	}

	if ipacl, ok := waf["ip_acl"].(map[string]any); ok {
		if v, ok := ipacl["enabled"].(bool); ok {
			cfg.WAF.IPACL.Enabled = v
		}
		if ab, ok := ipacl["auto_ban"].(map[string]any); ok {
			if v, ok := ab["enabled"].(bool); ok {
				cfg.WAF.IPACL.AutoBan.Enabled = v
			}
		}
	}

	if resp, ok := waf["response"].(map[string]any); ok {
		if sh, ok := resp["security_headers"].(map[string]any); ok {
			if v, ok := sh["enabled"].(bool); ok {
				cfg.WAF.Response.SecurityHeaders.Enabled = v
			}
		}
		if dm, ok := resp["data_masking"].(map[string]any); ok {
			if v, ok := dm["enabled"].(bool); ok {
				cfg.WAF.Response.DataMasking.Enabled = v
			}
			if v, ok := dm["mask_credit_cards"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskCreditCards = v
			}
			if v, ok := dm["mask_ssn"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskSSN = v
			}
			if v, ok := dm["mask_api_keys"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskAPIKeys = v
			}
			if v, ok := dm["strip_stack_traces"].(bool); ok {
				cfg.WAF.Response.DataMasking.StripStackTraces = v
			}
		}
	}

	// CORS Security
	if cors, ok := waf["cors"].(map[string]any); ok {
		if v, ok := cors["enabled"].(bool); ok {
			cfg.WAF.CORS.Enabled = v
		}
		if v, ok := cors["strict_mode"].(bool); ok {
			cfg.WAF.CORS.StrictMode = v
		}
		if v, ok := cors["allow_credentials"].(bool); ok {
			cfg.WAF.CORS.AllowCredentials = v
		}
	}

	// Threat Intelligence
	if ti, ok := waf["threat_intel"].(map[string]any); ok {
		if v, ok := ti["enabled"].(bool); ok {
			cfg.WAF.ThreatIntel.Enabled = v
		}
		if ipr, ok := ti["ip_reputation"].(map[string]any); ok {
			if v, ok := ipr["enabled"].(bool); ok {
				cfg.WAF.ThreatIntel.IPReputation.Enabled = v
			}
			if v, ok := ipr["block_malicious"].(bool); ok {
				cfg.WAF.ThreatIntel.IPReputation.BlockMalicious = v
			}
			if v, ok := ipr["score_threshold"].(float64); ok {
				cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold = int(v)
			}
		}
		if dr, ok := ti["domain_reputation"].(map[string]any); ok {
			if v, ok := dr["enabled"].(bool); ok {
				cfg.WAF.ThreatIntel.DomainRep.Enabled = v
			}
			if v, ok := dr["block_malicious"].(bool); ok {
				cfg.WAF.ThreatIntel.DomainRep.BlockMalicious = v
			}
		}
	}

	// ATO Protection
	if ato, ok := waf["ato_protection"].(map[string]any); ok {
		if v, ok := ato["enabled"].(bool); ok {
			cfg.WAF.ATOProtection.Enabled = v
		}
		if bf, ok := ato["brute_force"].(map[string]any); ok {
			if v, ok := bf["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.BruteForce.Enabled = v
			}
			if v, ok := bf["max_attempts_per_ip"].(float64); ok {
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP = int(v)
			}
			if v, ok := bf["max_attempts_per_email"].(float64); ok {
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail = int(v)
			}
		}
		if cs, ok := ato["credential_stuffing"].(map[string]any); ok {
			if v, ok := cs["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.CredStuffing.Enabled = v
			}
			if v, ok := cs["distributed_threshold"].(float64); ok {
				cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold = int(v)
			}
		}
		if tr, ok := ato["impossible_travel"].(map[string]any); ok {
			if v, ok := tr["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.Travel.Enabled = v
			}
			if v, ok := tr["max_distance_km"].(float64); ok {
				cfg.WAF.ATOProtection.Travel.MaxDistanceKm = v
			}
		}
	}

	// API Security
	if api, ok := waf["api_security"].(map[string]any); ok {
		if v, ok := api["enabled"].(bool); ok {
			cfg.WAF.APISecurity.Enabled = v
		}
		if jwt, ok := api["jwt"].(map[string]any); ok {
			if v, ok := jwt["enabled"].(bool); ok {
				cfg.WAF.APISecurity.JWT.Enabled = v
			}
			if v, ok := jwt["issuer"].(string); ok {
				cfg.WAF.APISecurity.JWT.Issuer = v
			}
			if v, ok := jwt["audience"].(string); ok {
				cfg.WAF.APISecurity.JWT.Audience = v
			}
		}
		if keys, ok := api["api_keys"].(map[string]any); ok {
			if v, ok := keys["enabled"].(bool); ok {
				cfg.WAF.APISecurity.APIKeys.Enabled = v
			}
			if v, ok := keys["header_name"].(string); ok {
				cfg.WAF.APISecurity.APIKeys.HeaderName = v
			}
		}
	}
}

// --- Rules ---

// SetRulesFns injects rule management functions to avoid circular imports.
func (d *Dashboard) SetRulesFns(
	getRules func() any,
	addRule func(map[string]any) error,
	updateRule func(string, map[string]any) error,
	deleteRule func(string) bool,
	toggleRule func(string, bool) bool,
	geoLookup func(string) (string, string),
) {
	d.rulesFn = getRules
	d.addRuleFn = addRule
	d.updateRuleFn = updateRule
	d.deleteRuleFn = deleteRule
	d.toggleRuleFn = toggleRule
	d.geoLookupFn = geoLookup
}

// SetAlertingStatsFn injects alerting stats function.
func (d *Dashboard) SetAlertingStatsFn(fn func() any) {
	d.alertingStatsFn = fn
}

// SetTenantManager injects the multi-tenant manager.
func (d *Dashboard) SetTenantManager(manager tenantManagerInterface) {
	d.tenantManager = manager
}

func (d *Dashboard) handleGetRules(w http.ResponseWriter, r *http.Request) {
	if d.rulesFn == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": d.rulesFn()})
}

func (d *Dashboard) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if d.addRuleFn == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "rules not configured"})
		return
	}
	var rule map[string]any
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if err := d.addRuleFn(rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.updateRuleFn == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "rules not configured"})
		return
	}
	var rule map[string]any
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if err := d.updateRuleFn(id, rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.deleteRuleFn == nil || !d.deleteRuleFn(id) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleGeoIPLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip parameter required"})
		return
	}
	if d.geoLookupFn == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": "", "name": "GeoIP not configured"})
		return
	}
	code, name := d.geoLookupFn(ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "country": code, "name": name})
}

// --- Logs ---

func (d *Dashboard) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = min(parsed, 2000)
		}
	}
	level := r.URL.Query().Get("level")

	logs := d.engine.Logs.Recent(n)

	if level != "" {
		var filtered []engine.LogEntry
		for _, l := range logs {
			if l.Level == level {
				filtered = append(filtered, l)
			}
		}
		logs = filtered
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"logs":  logs,
		"total": d.engine.Logs.Len(),
	})
}

// --- Health ---

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	components := map[string]string{
		"engine":     "healthy",
		"eventStore": "healthy",
	}

	if d.engine == nil {
		status = "degraded"
		components["engine"] = "unhealthy"
	}
	if d.eventStore == nil {
		status = "degraded"
		components["eventStore"] = "unhealthy"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"components": components,
	})
}

// --- SSE ---

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	d.sse.HandleSSE(w, r)
}

// --- SPA Serving (React dashboard) ---

// handleSPA serves the React SPA's index.html for all non-API, non-asset routes.
// This enables client-side routing (React Router).
func (d *Dashboard) handleSPA(w http.ResponseWriter, r *http.Request) {
	// Try dist/index.html (React build)
	data, err := distFS.ReadFile("dist/index.html")
	if err != nil {
		// Fallback to legacy static/index.html
		data, err = staticFiles.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Dashboard not found", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// handleDistAssets serves Vite-built assets (JS/CSS with content hashes).
// These are immutable and can be cached forever.
func (d *Dashboard) handleDistAssets(w http.ResponseWriter, r *http.Request) {
	// Serve from dist/ filesystem
	filePath := "dist" + r.URL.Path
	data, err := distFS.ReadFile(filePath)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Content-Type detection
	ct := "application/octet-stream"
	switch {
	case strings.HasSuffix(r.URL.Path, ".js"):
		ct = "application/javascript; charset=utf-8"
	case strings.HasSuffix(r.URL.Path, ".css"):
		ct = "text/css; charset=utf-8"
	case strings.HasSuffix(r.URL.Path, ".svg"):
		ct = "image/svg+xml"
	case strings.HasSuffix(r.URL.Path, ".png"):
		ct = "image/png"
	case strings.HasSuffix(r.URL.Path, ".woff2"):
		ct = "font/woff2"
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(data)
}

// --- SSE Broadcaster ---

// SSEBroadcaster manages Server-Sent Events client connections.
type SSEBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan string]struct{}
}

// NewSSEBroadcaster creates a new SSEBroadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients: make(map[chan string]struct{}),
	}
}

// HandleSSE is the HTTP handler for SSE connections.
func (b *SSEBroadcaster) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan string, 64)
	b.addClient(ch)
	defer b.removeClient(ch)

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// BroadcastEvent serializes and broadcasts a WAF event to all SSE clients.
// Uses json.Marshal on the Event struct directly (which has json tags).
func (b *SSEBroadcaster) BroadcastEvent(event engine.Event) {
	data, _ := json.Marshal(event)

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- string(data):
		default:
		}
	}
}

// ClientCount returns the number of connected SSE clients.
func (b *SSEBroadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

func (b *SSEBroadcaster) addClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clients[ch] = struct{}{}
}

func (b *SSEBroadcaster) removeClient(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.clients, ch)
	close(ch)
}

// --- Helpers ---

func handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func formatFindings(findings []engine.Finding) []map[string]any {
	result := make([]map[string]any, len(findings))
	for i, f := range findings {
		result[i] = map[string]any{
			"detector":    f.DetectorName,
			"category":    f.Category,
			"severity":    f.Severity.String(),
			"score":       f.Score,
			"description": f.Description,
			"location":    f.Location,
			"confidence":  f.Confidence,
		}
	}
	return result
}

// --- Alerting Handlers ---

func (d *Dashboard) handleAlertingStatus(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	webhooks := make([]any, 0, len(cfg.Alerting.Webhooks))
	for _, w := range cfg.Alerting.Webhooks {
		webhooks = append(webhooks, map[string]any{
			"name":      w.Name,
			"url":       w.URL,
			"type":      w.Type,
			"events":    w.Events,
			"min_score": w.MinScore,
			"cooldown":  w.Cooldown.String(),
		})
	}
	emails := make([]any, 0, len(cfg.Alerting.Emails))
	for _, e := range cfg.Alerting.Emails {
		emails = append(emails, map[string]any{
			"name":      e.Name,
			"smtp_host": e.SMTPHost,
			"smtp_port": e.SMTPPort,
			"from":      e.From,
			"to":        e.To,
			"use_tls":   e.UseTLS,
			"events":    e.Events,
			"min_score": e.MinScore,
			"cooldown":  e.Cooldown.String(),
		})
	}

	result := map[string]any{
		"enabled":       cfg.Alerting.Enabled,
		"webhook_count": len(cfg.Alerting.Webhooks),
		"email_count":   len(cfg.Alerting.Emails),
		"webhooks":      webhooks,
		"emails":        emails,
	}

	if d.alertingStatsFn != nil {
		stats := d.alertingStatsFn()
		if s, ok := stats.(map[string]any); ok {
			result["sent"] = s["sent"]
			result["failed"] = s["failed"]
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (d *Dashboard) handleGetWebhooks(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	webhooks := make([]any, 0, len(cfg.Alerting.Webhooks))
	for _, w := range cfg.Alerting.Webhooks {
		webhooks = append(webhooks, map[string]any{
			"name":      w.Name,
			"url":       w.URL,
			"type":      w.Type,
			"events":    w.Events,
			"min_score": w.MinScore,
			"cooldown":  w.Cooldown.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": webhooks})
}

func (d *Dashboard) handleAddWebhook(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string            `json:"name"`
		URL      string            `json:"url"`
		Type     string            `json:"type"`
		Events   []string          `json:"events"`
		MinScore int               `json:"min_score"`
		Cooldown string            `json:"cooldown"`
		Headers  map[string]string `json:"headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.Name == "" || body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name and url are required"})
		return
	}

	cooldown, _ := time.ParseDuration(body.Cooldown)
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}

	cfg := d.engine.Config()
	cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks, config.WebhookConfig{
		Name:     body.Name,
		URL:      body.URL,
		Type:     body.Type,
		Events:   body.Events,
		MinScore: body.MinScore,
		Cooldown: cooldown,
		Headers:  body.Headers,
	})

	// Persist config
	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}

	cfg := d.engine.Config()
	found := false
	for i, w := range cfg.Alerting.Webhooks {
		if w.Name == name {
			cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks[:i], cfg.Alerting.Webhooks[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "webhook not found"})
		return
	}

	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleGetEmails(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	emails := make([]any, 0, len(cfg.Alerting.Emails))
	for _, e := range cfg.Alerting.Emails {
		emails = append(emails, map[string]any{
			"name":      e.Name,
			"smtp_host": e.SMTPHost,
			"smtp_port": e.SMTPPort,
			"from":      e.From,
			"to":        e.To,
			"use_tls":   e.UseTLS,
			"events":    e.Events,
			"min_score": e.MinScore,
			"cooldown":  e.Cooldown.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"emails": emails})
}

func (d *Dashboard) handleAddEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string   `json:"name"`
		SMTPHost string   `json:"smtp_host"`
		SMTPPort int      `json:"smtp_port"`
		Username string   `json:"username"`
		Password string   `json:"password"`
		From     string   `json:"from"`
		To       []string `json:"to"`
		UseTLS   bool     `json:"use_tls"`
		Events   []string `json:"events"`
		MinScore int      `json:"min_score"`
		Cooldown string   `json:"cooldown"`
		Subject  string   `json:"subject"`
		Template string   `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.Name == "" || body.SMTPHost == "" || body.From == "" || len(body.To) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name, smtp_host, from, and to are required"})
		return
	}

	cooldown, _ := time.ParseDuration(body.Cooldown)
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	cfg := d.engine.Config()
	cfg.Alerting.Emails = append(cfg.Alerting.Emails, config.EmailConfig{
		Name:     body.Name,
		SMTPHost: body.SMTPHost,
		SMTPPort: body.SMTPPort,
		Username: body.Username,
		Password: body.Password,
		From:     body.From,
		To:       body.To,
		UseTLS:   body.UseTLS,
		Events:   body.Events,
		MinScore: body.MinScore,
		Cooldown: cooldown,
		Subject:  body.Subject,
		Template: body.Template,
	})

	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteEmail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}

	cfg := d.engine.Config()
	found := false
	for i, e := range cfg.Alerting.Emails {
		if e.Name == name {
			cfg.Alerting.Emails = append(cfg.Alerting.Emails[:i], cfg.Alerting.Emails[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "email target not found"})
		return
	}

	if d.saveFn != nil {
		if err := d.saveFn(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target is required"})
		return
	}

	// This would ideally call the alerting manager's TestAlert method
	// For now, we just return a success message
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Test alert functionality requires MCP or direct alerting manager access"})
}
