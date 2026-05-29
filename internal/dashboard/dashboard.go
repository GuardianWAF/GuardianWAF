// Package dashboard provides the web dashboard and REST API for GuardianWAF.
// It serves a real-time monitoring UI with SSE event streaming,
// REST endpoints for stats/events/config, and embedded static assets.
package dashboard

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/compliance"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
)

var dashboardLog = slog.Default().With(slog.String("component", "dashboard"))

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
	engine        *engine.Engine
	eventStore    events.EventStore
	sse           *SSEBroadcaster
	mux           *http.ServeMux
	apiKey        string
	adminKey      string            // Separate key for system admin operations (tenant management, billing, stats)
	pprofKey      string            // Separate key for pprof debug endpoints (more restrictive than apiKey)
	tenantAPIKeys map[string]string // map[tenantID] -> SHA256 hash of per-tenant API key
	// Dependency interfaces (injected to avoid circular imports)
	routingCtrl    RoutingController      // rebuild + save routing config
	upstreamStatus UpstreamStatusProvider // returns upstream health status
	certProvider   CertificateProvider    // returns SSL cert status
	ruleStore      RuleStore              // CRUD operations for rules
	geoLookup      GeoLookup              // IP → (country_code, country_name)
	alertingStats  AlertingStatsProvider  // returns alerting statistics (optional)

	// Existing interfaces (kept as-is)
	aiAnalyzer       aiAnalyzerInterface   // AI threat analyzer (optional)
	dockerWatcher    dockerWatcherInterface // Docker auto-discovery (optional)
	tenantManager    tenantManagerInterface // Multi-tenant manager (optional)
	complianceEngine *compliance.Engine     // Compliance reporting engine (optional)

	// Login rate limiting: per-IP token buckets
	loginBuckets sync.Map // map[string]*loginBucket
	loginStopCh  chan struct{}

	// Layer references for dashboard handlers
	crsLayer           *crs.Layer
	virtualPatchLayer  *virtualpatch.Layer
	clientSideLayer    *clientside.Layer
	apiValidationLayer *apivalidation.Layer
	dlpLayer           *dlp.Layer
}

const (
	loginMaxAttempts = 5                // max failed login attempts before lockout
	loginWindow      = 5 * time.Minute  // window for counting attempts
	loginLockout     = 15 * time.Minute // lockout duration after max attempts
)

// SetAdminKey sets the system administrator API key.
// This key grants exclusive access to /api/admin/* endpoints for cross-tenant
// management (tenant CRUD, billing, system-wide stats). It is separate from
// the per-tenant API key which only authenticates within a single tenant context.
// If not set, admin endpoints are inaccessible.
func (d *Dashboard) SetAdminKey(key string) {
	d.adminKey = key
}

// SetPprofKey sets the pprof debug key. When set, pprof endpoints require this
// key in addition to the localhost check. This provides defense-in-depth for
// sensitive profiling endpoints that can expose memory contents and goroutine stacks.
func (d *Dashboard) SetPprofKey(key string) {
	d.pprofKey = key
}

// checkPprofKey validates the pprof key from the Authorization Bearer header.
func (d *Dashboard) checkPprofKey(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		key := auth[len("Bearer "):]
		if subtle.ConstantTimeCompare([]byte(key), []byte(d.pprofKey)) == 1 {
			return key, true
		}
	}
	return "", false
}

// SetTenantAPIKey registers a per-tenant API key hash for tenant-scoped authentication.
// This enables AUTH-003: each tenant's API key only authenticates within that tenant's context.
// Keys are stored as SHA256 hashes (not plaintext). The same hash format as tenant Manager uses.
func (d *Dashboard) SetTenantAPIKey(tenantID, apiKeyHash string) {
	if d.tenantAPIKeys == nil {
		d.tenantAPIKeys = make(map[string]string)
	}
	d.tenantAPIKeys[tenantID] = apiKeyHash
}

// SetCRSLayer sets the CRS layer for dashboard handlers.
func (d *Dashboard) SetCRSLayer(layer *crs.Layer) {
	d.crsLayer = layer
}

// SetVirtualPatchLayer sets the virtual patch layer for dashboard handlers.
func (d *Dashboard) SetVirtualPatchLayer(layer *virtualpatch.Layer) {
	d.virtualPatchLayer = layer
}

// SetClientSideLayer sets the client-side protection layer for dashboard handlers.
func (d *Dashboard) SetClientSideLayer(layer *clientside.Layer) {
	d.clientSideLayer = layer
}

// SetAPIValidationLayer sets the API validation layer for dashboard handlers.
func (d *Dashboard) SetAPIValidationLayer(layer *apivalidation.Layer) {
	d.apiValidationLayer = layer
}

// SetDLPLayer sets the DLP layer for dashboard handlers.
func (d *Dashboard) SetDLPLayer(layer *dlp.Layer) {
	d.dlpLayer = layer
}

// isAdminAuthenticated checks if the request has the system admin API key.
func (d *Dashboard) isAdminAuthenticated(r *http.Request) bool {
	if d.adminKey == "" {
		// Admin key not configured — reject all admin requests
		return false
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return subtle.ConstantTimeCompare([]byte(key), []byte(d.adminKey)) == 1
	}
	return false
}


// New creates a new Dashboard wired to the given engine and event store.
func New(eng *engine.Engine, store events.EventStore, apiKey string) *Dashboard {
	d := &Dashboard{
		engine:      eng,
		eventStore:  store,
		sse:         NewSSEBroadcaster(),
		mux:         http.NewServeMux(),
		apiKey:      apiKey,
		loginStopCh: make(chan struct{}),
	}

	go d.cleanupLoginBuckets()
	go cleanupRevokedSessionsLoop(d.loginStopCh)

	// Login/logout (always accessible)
	d.mux.HandleFunc("GET /login", d.handleLoginPage)
	d.mux.HandleFunc("POST /login", d.handleLoginSubmit)
	d.mux.HandleFunc("GET /logout", d.handleLogout)

	// Health check (always accessible, no sensitive data)
	d.mux.HandleFunc("GET /api/v1/health", d.handleHealth)

	// Domain-based route registration
	d.registerStats(d.mux)
	d.registerConfig(d.mux)
	d.registerRouting(d.mux)
	d.registerACL(d.mux)
	d.registerRules(d.mux)
	d.registerAI(d.mux)
	d.registerAlerting(d.mux)
	d.registerDocker(d.mux)
	d.registerCompliance(d.mux)
	d.registerSPA(d.mux)

	// Debug pprof endpoints — localhost-only, sensitive runtime data
	d.mux.HandleFunc("GET /debug/pprof/", d.pprofWrap(pprof.Index))
	d.mux.HandleFunc("GET /debug/pprof/cmdline", d.pprofWrap(pprof.Cmdline))
	d.mux.HandleFunc("GET /debug/pprof/profile", d.pprofWrap(pprof.Profile))
	d.mux.HandleFunc("GET /debug/pprof/symbol", d.pprofWrap(pprof.Symbol))
	d.mux.HandleFunc("GET /debug/pprof/trace", d.pprofWrap(pprof.Trace))

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
		r, ok := d.isAuthenticated(r)
		if !ok {
			// API requests get 401 JSON, browser requests get redirected to login
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		// Enforce tenant API key scoping: tenant keys cannot access admin-only endpoints
		if getAuthType(r) == authTenant {
			for _, prefix := range adminOnlyPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					writeJSON(w, http.StatusForbidden, map[string]any{"error": "tenant-scoped API key cannot access this endpoint"})
					return
				}
			}
		}

		// Refresh session cookie on each request (sliding idle timeout)
		if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
			setSessionCookie(w, r)
		}

		// CSRF protection for state-changing requests authenticated via cookie
		// (API key header auth is inherently CSRF-safe since browsers can't set custom headers cross-origin)
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get("X-API-Key") == "" && !verifySameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF validation failed"})
				return
			}
		}

		handler(w, r)
	}
}

// pprofWrap restricts pprof endpoints to localhost connections and requires
// pprofKey (or adminKey when pprofKey is not set) for authentication.
func (d *Dashboard) pprofWrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use RemoteAddr directly - never trust X-Forwarded-For for pprof access.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "connection error", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "pprof endpoints are localhost-only", http.StatusForbidden)
			return
		}
		// Require pprofKey when set; when adminKey is set and pprofKey is not,
		// accept adminKey as a fallback (admin has debug access).
		if d.pprofKey != "" {
			_, authorized := d.checkPprofKey(r)
			if !authorized {
				http.Error(w, "pprof access denied", http.StatusForbidden)
				return
			}
		} else if d.adminKey != "" {
			if key := r.Header.Get("X-API-Key"); key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(d.adminKey)) != 1 {
				http.Error(w, "pprof access denied", http.StatusForbidden)
				return
			}
		}
		handler.ServeHTTP(w, r)
	}
}






// SetUpstreamsFn sets the function that returns upstream health status.

// --- Config ---

func (d *Dashboard) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": cfg.Mode,
		"tls": map[string]any{
			"enabled":         cfg.TLS.Enabled,
			"listen":          cfg.TLS.Listen,
			"cert_configured": cfg.TLS.CertFile != "",
			"key_configured":  cfg.TLS.KeyFile != "",
			"http_redirect":   cfg.TLS.HTTPRedirect,
			"acme": map[string]any{
				"enabled": cfg.TLS.ACME.Enabled,
				"domains": cfg.TLS.ACME.Domains,
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
	if !limitedDecodeJSON(w, r, &patch) {
		return
	}

	// Copy config to avoid mutating shared state without a lock.
	cfg := deepCopyConfig(d.engine.Config())

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

	// Audit log for security-critical config changes
	d.logSecurityConfigChanges(d.engine.Config(), cfg, r)

	if err := d.engine.Reload(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
		return
	}

	// Persist to disk
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated (disk sync pending)"})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated and saved"})
}


// applyWAFPatch applies partial config updates from a JSON patch object.
func applyWAFPatch(cfg *config.Config, waf map[string]any) {
	if det, ok := waf["detection"].(map[string]any); ok {
		if v, ok := det["enabled"].(bool); ok {
			cfg.WAF.Detection.Enabled = v
		}
		if th, ok := det["threshold"].(map[string]any); ok {
			if v, ok := th["block"].(float64); ok {
				cfg.WAF.Detection.Threshold.Block = clampInt(int(v), 1, 1000)
			}
			if v, ok := th["log"].(float64); ok {
				cfg.WAF.Detection.Threshold.Log = clampInt(int(v), 0, 1000)
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
					dc.Multiplier = clampFloat(v, 0.1, 10.0)
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
			cfg.WAF.Sanitizer.MaxBodySize = clampInt64(int64(v), 0, 100<<20)
		}
		if v, ok := san["max_url_length"].(float64); ok {
			cfg.WAF.Sanitizer.MaxURLLength = clampInt(int(v), 64, 65535)
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
				cfg.WAF.BotDetection.Behavior.RPSThreshold = clampInt(int(v), 1, 100000)
			}
			if v, ok := beh["error_rate_threshold"].(float64); ok {
				cfg.WAF.BotDetection.Behavior.ErrorRateThreshold = clampInt(int(v), 1, 100)
			}
		}
	}

	if ch, ok := waf["challenge"].(map[string]any); ok {
		if v, ok := ch["enabled"].(bool); ok {
			cfg.WAF.Challenge.Enabled = v
		}
		if v, ok := ch["difficulty"].(float64); ok {
			cfg.WAF.Challenge.Difficulty = clampInt(int(v), 1, 5)
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
				cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold = clampInt(int(v), 0, 100)
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
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP = clampInt(int(v), 1, 10000)
			}
			if v, ok := bf["max_attempts_per_email"].(float64); ok {
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail = clampInt(int(v), 1, 10000)
			}
		}
		if cs, ok := ato["credential_stuffing"].(map[string]any); ok {
			if v, ok := cs["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.CredStuffing.Enabled = v
			}
			if v, ok := cs["distributed_threshold"].(float64); ok {
				cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold = clampInt(int(v), 1, 10000)
			}
		}
		if tr, ok := ato["impossible_travel"].(map[string]any); ok {
			if v, ok := tr["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.Travel.Enabled = v
			}
			if v, ok := tr["max_distance_km"].(float64); ok {
				cfg.WAF.ATOProtection.Travel.MaxDistanceKm = clampFloat(v, 0, 20000)
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
		getRules:    getRules,
		addRule:     addRule,
		updateRule:  updateRule,
		deleteRule:  deleteRule,
		toggleRule:  toggleRule,
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

func (r *ruleStoreAdapter) GetRules() any   { return r.getRules() }
func (r *ruleStoreAdapter) AddRule(raw map[string]any) error { return r.addRule(raw) }
func (r *ruleStoreAdapter) UpdateRule(id string, raw map[string]any) error { return r.updateRule(id, raw) }
func (r *ruleStoreAdapter) RemoveRule(id string) bool { return r.deleteRule(id) }
func (r *ruleStoreAdapter) ToggleRule(id string, enabled bool) bool { return r.toggleRule(id, enabled) }

// geoLookupAdapter wraps a func(string) (string, string) as a GeoLookup interface.
type geoLookupAdapter struct{ fn func(string) (string, string) }

func (g *geoLookupAdapter) Lookup(ip string) (string, string) { return g.fn(ip) }

// SetAlertingStatsFn injects alerting stats via the AlertingStatsProvider interface.
func (d *Dashboard) SetAlertingStatsFn(fn func() any) {
	if fn == nil {
		return
	}
	d.alertingStats = &alertingStatsAdapter{fn: fn}
}

// alertingStatsAdapter wraps a func() any as an AlertingStatsProvider.
type alertingStatsAdapter struct{ fn func() any }

func (a *alertingStatsAdapter) GetAlertingStats() any { return a.fn() }

// SetTenantManager injects the multi-tenant manager.
// Also registers all existing tenant API keys for per-tenant authentication (AUTH-003).
// SetComplianceEngine sets the compliance reporting engine for the dashboard.
func (d *Dashboard) SetComplianceEngine(e *compliance.Engine) {
	d.complianceEngine = e
}

func (d *Dashboard) SetTenantManager(manager tenantManagerInterface) {
	d.tenantManager = manager
	adminHandler := NewTenantAdminHandler(d, manager)
	adminHandler.RegisterRoutes(d.mux)

	// Sync existing tenant API keys into dashboard for per-tenant auth
	d.syncTenantAPIKeys(manager)
}

// syncTenantAPIKeys registers all tenant API key hashes for per-tenant authentication.
// This enables the dashboard to validate per-tenant API keys without needing the full tenant manager.
func (d *Dashboard) syncTenantAPIKeys(manager tenantManagerInterface) {
	if manager == nil {
		return
	}
	tenants := manager.ListTenants()
	d.tenantAPIKeys = make(map[string]string, len(tenants))
	for _, t := range tenants {
		if m, ok := t.(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				if hash, ok := m["api_key_hash"].(string); ok && hash != "" {
					d.tenantAPIKeys[id] = hash
				}
			}
		}
	}
}

func (d *Dashboard) handleGetRules(w http.ResponseWriter, r *http.Request) {
	if d.ruleStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": d.ruleStore.GetRules()})
}

func (d *Dashboard) handleAddRule(w http.ResponseWriter, r *http.Request) {
	if d.ruleStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "rules not configured"})
		return
	}
	var rule map[string]any
	if !limitedDecodeJSON(w, r, &rule) {
		return
	}
	if err := d.ruleStore.AddRule(rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.ruleStore == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "rules not configured"})
		return
	}
	var rule map[string]any
	if !limitedDecodeJSON(w, r, &rule) {
		return
	}
	if err := d.ruleStore.UpdateRule(id, rule); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d.ruleStore == nil || !d.ruleStore.RemoveRule(id) {
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
	// Validate that the input looks like an IP address
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ip address"})
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
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "Content-Type: application/json required"})
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &req) {
		return
	}
	if req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip field required"})
		return
	}
	if net.ParseIP(req.IP) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ip address"})
		return
	}
	if d.geoLookup == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ip": req.IP, "country": "", "name": "GeoIP not configured"})
		return
	}
	code, name := d.geoLookup.Lookup(req.IP)
	writeJSON(w, http.StatusOK, map[string]any{"ip": req.IP, "country": code, "name": name})
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

// --- SSE Broadcaster ---

// SSEBroadcaster manages Server-Sent Events client connections.
type SSEBroadcaster struct {
	mu         sync.RWMutex
	clients    map[chan string]struct{}
	maxClients int
}

const defaultMaxSSEClients = 1000

// NewSSEBroadcaster creates a new SSEBroadcaster.
func NewSSEBroadcaster() *SSEBroadcaster {
	return &SSEBroadcaster{
		clients:    make(map[chan string]struct{}),
		maxClients: defaultMaxSSEClients,
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

	// Check client cap and register atomically
	ch := make(chan string, 64)
	b.mu.Lock()
	if len(b.clients) >= b.maxClients {
		b.mu.Unlock()
		http.Error(w, "too many SSE connections", http.StatusServiceUnavailable)
		return
	}
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	defer b.removeClient(ch)

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case msg := <-ch:
			// Split on newlines per SSE spec: each line gets its own "data:" prefix
			for _, line := range strings.Split(msg, "\n") {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprint(w, "\n")
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
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON marshals v before writing the status code so that an encoding
// failure can still produce a proper 500 instead of a 200 with a truncated,
// invalid body. Encoding failures are logged rather than silently dropped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		dashboardLog.Error("response encode failed", "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal encoding error"}`)) // nolint:errcheck // error response; error ignored
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf) // nolint:errcheck // download write; error ignored
}

// writeError writes a JSON error response with the standard {"error": ...}
// envelope used across the dashboard API.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

const maxRequestBody = 1 << 20 // 1MB max request body for API endpoints

// decodeJSON limits the request body size and decodes JSON.
func limitedDecodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
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

// clampInt clamps v to [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampInt64 clamps v to [lo, hi].
func clampInt64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// clampFloat clamps v to [lo, hi].
func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// sanitizeErr strips potentially sensitive details from error messages
// before returning them to clients.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip file paths
	if strings.Contains(msg, "/") || strings.Contains(msg, "\\") {
		return "internal error"
	}
	// Strip stack trace indicators
	if strings.Contains(msg, "goroutine") || strings.Contains(msg, "runtime/") {
		return "internal error"
	}
	// Truncate very long errors
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// --- Alerting Handlers ---

func (d *Dashboard) handleAlertingStatus(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	webhooks := make([]any, 0, len(cfg.Alerting.Webhooks))
	for _, w := range cfg.Alerting.Webhooks {
		webhooks = append(webhooks, map[string]any{
			"name":      w.Name,
			"url":       maskURL(w.URL),
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

	if d.alertingStats != nil {
		stats := d.alertingStats.GetAlertingStats()
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
			"url":       maskURL(w.URL),
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
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.Name == "" || body.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name and url are required"})
		return
	}

	// Validate webhook URL to prevent SSRF (reject private/loopback IPs)
	if err := alerting.ValidateWebhookURL(body.URL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
		return
	}

	cooldown, _ := time.ParseDuration(body.Cooldown)
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}

	cfg := deepCopyConfig(d.engine.Config())
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
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
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

	cfg := deepCopyConfig(d.engine.Config())
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

	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
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
	if !limitedDecodeJSON(w, r, &body) {
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

	cfg := deepCopyConfig(d.engine.Config())
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

	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
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

	cfg := deepCopyConfig(d.engine.Config())
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

	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if !limitedDecodeJSON(w, r, &body) || body.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target is required"})
		return
	}

	// This would ideally call the alerting manager's TestAlert method
	// For now, we just return a success message
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Test alert functionality requires MCP or direct alerting manager access"})
}

// deepCopyConfig creates a deep copy of the config using JSON round-trip.
// This prevents shared mutable state between the dashboard and engine.
func deepCopyConfig(cfg *config.Config) *config.Config {
	data, err := json.Marshal(cfg)
	if err != nil {
		panic("deepCopyConfig: failed to marshal config: " + err.Error())
	}
	cp := &config.Config{}
	if err := json.Unmarshal(data, cp); err != nil {
		cp2 := *cfg
		return &cp2
	}
	return cp
}

// maskURL masks sensitive parts of a URL, showing only scheme and host.
// e.g. "https://user:pass@hooks.example.com/v1/secret?token=abc" → "https://hooks.example.com"
func maskURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	return u.Scheme + "://" + u.Host
}

// logSecurityConfigChanges logs when security features are disabled via the config API.
func (d *Dashboard) logSecurityConfigChanges(oldCfg, newCfg *config.Config, r *http.Request) {
	securityFields := []struct {
		name string
		old  bool
		new  bool
	}{
		{"detection", oldCfg.WAF.Detection.Enabled, newCfg.WAF.Detection.Enabled},
		{"rate_limit", oldCfg.WAF.RateLimit.Enabled, newCfg.WAF.RateLimit.Enabled},
		{"sanitizer", oldCfg.WAF.Sanitizer.Enabled, newCfg.WAF.Sanitizer.Enabled},
		{"bot_detection", oldCfg.WAF.BotDetection.Enabled, newCfg.WAF.BotDetection.Enabled},
		{"challenge", oldCfg.WAF.Challenge.Enabled, newCfg.WAF.Challenge.Enabled},
		{"ip_acl", oldCfg.WAF.IPACL.Enabled, newCfg.WAF.IPACL.Enabled},
		{"cors", oldCfg.WAF.CORS.Enabled, newCfg.WAF.CORS.Enabled},
		{"ato_protection", oldCfg.WAF.ATOProtection.Enabled, newCfg.WAF.ATOProtection.Enabled},
		{"api_security", oldCfg.WAF.APISecurity.Enabled, newCfg.WAF.APISecurity.Enabled},
		{"dlp", oldCfg.WAF.DLP.Enabled, newCfg.WAF.DLP.Enabled},
		{"ml_anomaly", oldCfg.WAF.MLAnomaly.Enabled, newCfg.WAF.MLAnomaly.Enabled},
		{"crs", oldCfg.WAF.CRS.Enabled, newCfg.WAF.CRS.Enabled},
	}
	clientIP := clientIPFromRequest(r)
	for _, f := range securityFields {
		if f.old && !f.new {
			dashboardLog.Warn("security feature disabled via config API",
				"feature", f.name,
				"client_ip", clientIP)
		}
	}
}
