// Package dashboard provides the web dashboard and REST API for GuardianWAF.
// It serves a real-time monitoring UI with SSE event streaming,
// REST endpoints for stats/events/config, and embedded static assets.
package dashboard

import (
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
//go:embed static/index.html static/style.css static/app.js static/config.html static/config.js static/routing.html static/routing.js
var staticFiles embed.FS

// Dashboard is the web dashboard server.
type Dashboard struct {
	engine        *engine.Engine
	eventStore    events.EventStore
	sse           *SSEBroadcaster
	mux           *http.ServeMux
	apiKey        string
	upstreamsFn   func() any // returns upstream status (injected to avoid circular imports)
	rebuildFn     func() error // rebuilds proxy after config change
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
	d.mux.HandleFunc("GET /api/v1/events/{id}", d.authWrap(d.handleGetEvent))
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
	d.mux.HandleFunc("OPTIONS /api/v1/ipacl", handleCORS)
	d.mux.HandleFunc("GET /api/v1/sse", d.authWrap(d.handleSSE))

	// SPA serving — React build output from dist/ with fallback to legacy static/
	d.mux.HandleFunc("GET /assets/", d.authWrap(d.handleDistAssets)) // Vite hashed assets
	d.mux.HandleFunc("GET /config", d.authWrap(d.handleSPA))        // SPA routes
	d.mux.HandleFunc("GET /routing", d.authWrap(d.handleSPA))       // SPA routes
	d.mux.HandleFunc("/", d.authWrap(d.handleSPA))                  // SPA catch-all

	return d
}

// Handler returns the root http.Handler.
func (d *Dashboard) Handler() http.Handler {
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
	w.Write([]byte(loginPage("")))
}

func (d *Dashboard) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if d.apiKey == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	key := r.FormValue("key")
	if key != d.apiKey {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(loginPage("Invalid API key. Please try again.")))
		return
	}
	setSessionCookie(w)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"total_requests":      stats.TotalRequests,
		"blocked_requests":    stats.BlockedRequests,
		"challenged_requests": stats.ChallengedRequests,
		"logged_requests":     stats.LoggedRequests,
		"passed_requests":     stats.PassedRequests,
		"avg_latency_us":      stats.AvgLatencyUs,
	})
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

// --- Upstreams ---

// SetRebuildFn sets the function called after routing config changes to rebuild the proxy.
func (d *Dashboard) SetRebuildFn(fn func() error) {
	d.rebuildFn = fn
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

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Routing updated"})
}

// SetUpstreamsFn sets the function that returns upstream health status.
func (d *Dashboard) SetUpstreamsFn(fn func() any) {
	d.upstreamsFn = fn
}

func (d *Dashboard) handleGetUpstreams(w http.ResponseWriter, r *http.Request) {
	if d.upstreamsFn == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, d.upstreamsFn())
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

	if err := d.engine.Reload(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated"})
}

func (d *Dashboard) handleRoutingPage(w http.ResponseWriter, r *http.Request) {
	data, err := staticFiles.ReadFile("static/routing.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (d *Dashboard) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	data, err := staticFiles.ReadFile("static/config.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
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
}

// --- Health ---

func (d *Dashboard) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "healthy"})
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
	w.Write(data)
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
	if strings.HasSuffix(r.URL.Path, ".js") {
		ct = "application/javascript; charset=utf-8"
	} else if strings.HasSuffix(r.URL.Path, ".css") {
		ct = "text/css; charset=utf-8"
	} else if strings.HasSuffix(r.URL.Path, ".svg") {
		ct = "image/svg+xml"
	} else if strings.HasSuffix(r.URL.Path, ".png") {
		ct = "image/png"
	} else if strings.HasSuffix(r.URL.Path, ".woff2") {
		ct = "font/woff2"
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(data)
}

// Legacy static handler (kept for backward compatibility)
func (d *Dashboard) handleStatic(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFiles.ReadFile(path)
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	}
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
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

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
	json.NewEncoder(w).Encode(v)
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
