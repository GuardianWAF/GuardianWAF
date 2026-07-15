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
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	engine           *engine.Engine
	eventStore       events.EventStore
	sse              *SSEBroadcaster
	mux              *http.ServeMux
	apiKey           atomic.Value // stores *apiKeyHolder
	buildInfo        map[string]string
	adminKey         string            // Separate key for system admin operations (tenant management, billing, stats)
	pprofKey         string            // Separate key for pprof debug endpoints (more restrictive than apiKey)
	tenantAPIKeys    map[string]string // map[tenantID] -> SHA256 hash of per-tenant API key
	trustedProxyNets []*net.IPNet      // Direct proxy CIDRs trusted for forwarded TLS metadata
	// Dependency interfaces (injected to avoid circular imports)
	routingCtrl    RoutingController      // rebuild + save routing config
	upstreamStatus UpstreamStatusProvider // returns upstream health status
	certProvider   CertificateProvider    // returns SSL cert status
	ruleStore      RuleStore              // CRUD operations for rules
	geoLookup      GeoLookup              // IP → (country_code, country_name)
	alertingStats  AlertingStatsProvider  // returns alerting statistics (optional)

	// Existing interfaces (kept as-is)
	aiAnalyzer       aiAnalyzerInterface    // AI threat analyzer (optional)
	dockerWatcher    dockerWatcherInterface // Docker auto-discovery (optional)
	tenantManager    tenantManagerInterface // Multi-tenant manager (optional)
	complianceEngine *compliance.Engine     // Compliance reporting engine (optional)

	// Login rate limiting: per-IP token buckets
	loginBuckets sync.Map // map[string]*loginBucket
	loginStopCh  chan struct{}
	cleanupWG    sync.WaitGroup

	// API rate limiting: per-IP token buckets for authenticated endpoints
	apiBuckets sync.Map // map[string]*apiBucket
	apiStopCh  chan struct{}

	// Layer references for dashboard handlers
	crsLayer              *crs.Layer
	virtualPatchLayer     *virtualpatch.Layer
	clientSideLayer       *clientside.Layer
	apiValidationLayer    *apivalidation.Layer
	dlpLayer              *dlp.Layer
	crsLayerOverride      CRSLayerInterface
	virtualPatchOverride  VirtualPatchLayerInterface
	clientSideOverride    ClientSideLayerInterface
	apiValidationOverride APIValidationLayerInterface
	dlpLayerOverride      DLPLayerInterface
	tenantAdminHandler *TenantAdminHandler
}

const (
	loginMaxAttempts = 5                // max failed login attempts before lockout
	loginWindow      = 5 * time.Minute  // window for counting attempts
	loginLockout     = 15 * time.Minute // lockout duration after max attempts

	// API rate limit constants — per-IP token bucket for authenticated endpoints.
	apiRateLimit       = 120             // max requests per window
	apiRateWindow      = time.Minute     // sliding window
	apiRateBurst       = 20              // max burst
	apiRateCleanupTick = 5 * time.Minute // cleanup interval for stale buckets

	// keyRotationGracePeriod is the duration the previous API key remains valid
	// after a rotation, allowing in-flight requests and cached clients to transition.
	keyRotationGracePeriod = 60 * time.Second
)

// apiKeyHolder holds the current dashboard API key and optionally the previous
// key during the rotation grace period. Stored in an atomic.Value so the hot
// authentication path never blocks on a mutex.
type apiKeyHolder struct {
	Current   string    // active API key
	Previous  string    // previous API key (valid until ExpiresAt)
	ExpiresAt time.Time // when Previous ceases to be valid
}

// loadActiveAPIKeys returns (current, previous) where previous is only populated
// if it exists and the grace period has not expired.
func (d *Dashboard) loadActiveAPIKeys() (current string, previous string) {
	v := d.apiKey.Load()
	if v == nil {
		return "", ""
	}
	kh := v.(*apiKeyHolder)
	current = kh.Current
	if time.Now().Before(kh.ExpiresAt) {
		previous = kh.Previous
	}
	return current, previous
}

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
		loginStopCh: make(chan struct{}),
		apiStopCh:   make(chan struct{}),
	}
	d.apiKey.Store(&apiKeyHolder{Current: apiKey})

	d.cleanupWG.Add(3)
	go d.cleanupLoginBuckets()
	go d.cleanupAPIBuckets()
	go cleanupRevokedSessionsLoop(d.loginStopCh, &d.cleanupWG)

	d.registerRoutes()

	return d
}

// Handler returns the root http.Handler.
func (d *Dashboard) Handler() http.Handler {
	return CORSMiddleware(d.mux)
}

// Mux returns the underlying ServeMux for registering additional routes.
func (d *Dashboard) Mux() *http.ServeMux {
	return d.mux
}

// SSE returns the SSE broadcaster for publishing events from outside.
func (d *Dashboard) SSE() *SSEBroadcaster {
	return d.sse
}

func (d *Dashboard) SetBuildInfo(version, commit, date string) {
	d.buildInfo = map[string]string{
		"version": version,
		"commit":  commit,
		"date":    date,
	}
}

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

	// Copy config to avoid mutating shared state without a lock and retain a
	// rollback snapshot if durable persistence fails.
	oldCfg := d.engine.Config()
	cfg := deepCopyConfig(oldCfg)

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
	d.logSecurityConfigChanges(oldCfg, cfg, r)

	if err := validateRuntimeReloadableConfig(oldCfg, cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}

	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}

	// Persist to disk
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			if rollbackErr := d.engine.Reload(oldCfg); rollbackErr != nil {
				dashboardLog.Error("configuration persistence and rollback failed", "save_error", err, "rollback_error", rollbackErr)
			} else {
				dashboardLog.Error("configuration persistence failed; runtime rolled back", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "configuration persistence failed; previous runtime configuration restored")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated and saved"})
}

func (d *Dashboard) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	cfg := deepCopyConfig(d.engine.Config())
	if err := validateRuntimeReloadableConfig(d.engine.Config(), cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}
	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Rebuild(); err != nil {
			writeError(w, http.StatusInternalServerError, "proxy rebuild failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration reloaded"})
}

func validateRuntimeReloadableConfig(oldCfg, newCfg *config.Config) error {
	if oldCfg == nil || newCfg == nil {
		return nil
	}

	changed := make([]string, 0)
	addBoolChange := func(path string, oldValue, newValue bool) {
		if oldValue != newValue {
			changed = append(changed, path)
		}
	}

	addBoolChange("waf.ip_acl.enabled", oldCfg.WAF.IPACL.Enabled, newCfg.WAF.IPACL.Enabled)
	addBoolChange("waf.threat_intel.enabled", oldCfg.WAF.ThreatIntel.Enabled, newCfg.WAF.ThreatIntel.Enabled)
	addBoolChange("waf.cors.enabled", oldCfg.WAF.CORS.Enabled, newCfg.WAF.CORS.Enabled)
	addBoolChange("waf.custom_rules.enabled", oldCfg.WAF.CustomRules.Enabled, newCfg.WAF.CustomRules.Enabled)
	addBoolChange("waf.rate_limit.enabled", oldCfg.WAF.RateLimit.Enabled, newCfg.WAF.RateLimit.Enabled)
	addBoolChange("waf.ato_protection.enabled", oldCfg.WAF.ATOProtection.Enabled, newCfg.WAF.ATOProtection.Enabled)
	addBoolChange("waf.api_security.enabled", oldCfg.WAF.APISecurity.Enabled, newCfg.WAF.APISecurity.Enabled)
	addBoolChange("waf.api_validation.enabled", oldCfg.WAF.APIValidation.Enabled, newCfg.WAF.APIValidation.Enabled)
	addBoolChange("waf.sanitizer.enabled", oldCfg.WAF.Sanitizer.Enabled, newCfg.WAF.Sanitizer.Enabled)
	addBoolChange("waf.crs.enabled", oldCfg.WAF.CRS.Enabled, newCfg.WAF.CRS.Enabled)
	addBoolChange("waf.detection.enabled", oldCfg.WAF.Detection.Enabled, newCfg.WAF.Detection.Enabled)
	addBoolChange("waf.virtual_patch.enabled", oldCfg.WAF.VirtualPatch.Enabled, newCfg.WAF.VirtualPatch.Enabled)
	addBoolChange("waf.dlp.enabled", oldCfg.WAF.DLP.Enabled, newCfg.WAF.DLP.Enabled)
	addBoolChange("waf.bot_detection.enabled", oldCfg.WAF.BotDetection.Enabled, newCfg.WAF.BotDetection.Enabled)
	addBoolChange("waf.client_side.enabled", oldCfg.WAF.ClientSide.Enabled, newCfg.WAF.ClientSide.Enabled)

	if len(changed) == 0 {
		return validateRuntimeReloadableWAFConfig(oldCfg, newCfg)
	}
	return fmt.Errorf("runtime reload cannot change WAF layer topology (%s); update the config file and restart GuardianWAF", strings.Join(changed, ", "))
}

func validateRuntimeReloadableWAFConfig(oldCfg, newCfg *config.Config) error {
	oldWAF := reloadGuardWAFShape(oldCfg)
	newWAF := reloadGuardWAFShape(newCfg)

	if reflect.DeepEqual(oldWAF, newWAF) {
		return nil
	}
	return fmt.Errorf("runtime reload cannot change WAF layer configuration without rebuilding the pipeline; update the config file and restart GuardianWAF")
}

func reloadGuardWAFShape(cfg *config.Config) any {
	waf := cfg.DeepCopy().WAF

	// These fields are consumed through Engine atomics and do not require
	// rebuilding layer instances.
	waf.Detection.Threshold = config.ThresholdConfig{}
	waf.Sanitizer.MaxBodySize = 0

	return struct {
		IPACL         config.IPACLConfig
		ThreatIntel   config.ThreatIntelConfig
		CORS          config.CORSConfig
		CustomRules   config.CustomRulesConfig
		RateLimit     config.RateLimitConfig
		ATOProtection config.ATOProtectionConfig
		APISecurity   config.APISecurityConfig
		APIValidation config.APIValidationConfig
		Sanitizer     config.SanitizerConfig
		CRS           config.CRSConfig
		Detection     config.DetectionConfig
		VirtualPatch  config.VirtualPatchConfig
		DLP           config.DLPConfig
		BotDetection  config.BotDetectionConfig
		ClientSide    config.ClientSideConfig
		Response      config.ResponseConfig
	}{
		IPACL:         waf.IPACL,
		ThreatIntel:   waf.ThreatIntel,
		CORS:          waf.CORS,
		CustomRules:   waf.CustomRules,
		RateLimit:     waf.RateLimit,
		ATOProtection: waf.ATOProtection,
		APISecurity:   waf.APISecurity,
		APIValidation: waf.APIValidation,
		Sanitizer:     waf.Sanitizer,
		CRS:           waf.CRS,
		Detection:     waf.Detection,
		VirtualPatch:  waf.VirtualPatch,
		DLP:           waf.DLP,
		BotDetection:  waf.BotDetection,
		ClientSide:    waf.ClientSide,
		Response:      waf.Response,
	}
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
	if d.tenantAdminHandler != nil {
		d.tenantAdminHandler.manager = manager
	}

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

func (d *Dashboard) handleVersion(w http.ResponseWriter, r *http.Request) {
	info := d.buildInfo
	if info == nil {
		info = map[string]string{
			"version": "dev",
			"commit":  "none",
			"date":    "unknown",
		}
	}
	writeJSON(w, http.StatusOK, info)
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
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}

	// Validate webhook URL to prevent SSRF (reject private/loopback IPs)
	if err := alerting.ValidateWebhookURL(body.URL); err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}

	cooldown, err := time.ParseDuration(body.Cooldown)
	if err != nil && body.Cooldown != "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid cooldown duration: %q", body.Cooldown))
		return
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks, config.WebhookConfig{
			Name:     body.Name,
			URL:      body.URL,
			Type:     body.Type,
			Events:   body.Events,
			MinScore: body.MinScore,
			Cooldown: cooldown,
			Headers:  body.Headers,
		})
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check existence first for proper 404
	current := d.engine.Config()
	exists := false
	for _, wh := range current.Alerting.Webhooks {
		if wh.Name == name {
			exists = true
			break
		}
	}
	if !exists {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		for i, wh := range cfg.Alerting.Webhooks {
			if wh.Name == name {
				cfg.Alerting.Webhooks = append(cfg.Alerting.Webhooks[:i], cfg.Alerting.Webhooks[i+1:]...)
				return
			}
		}
	}) {
		return
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
		writeError(w, http.StatusBadRequest, "name, smtp_host, from, and to are required")
		return
	}

	cooldown, err := time.ParseDuration(body.Cooldown)
	if err != nil && body.Cooldown != "" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid cooldown duration: %q", body.Cooldown))
		return
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
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
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "name": body.Name})
}

func (d *Dashboard) handleDeleteEmail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Check existence first for proper 404
	current := d.engine.Config()
	exists := false
	for _, em := range current.Alerting.Emails {
		if em.Name == name {
			exists = true
			break
		}
	}
	if !exists {
		writeError(w, http.StatusNotFound, "email target not found")
		return
	}

	if !d.reloadAndPersist(w, func(cfg *config.Config) {
		for i, em := range cfg.Alerting.Emails {
			if em.Name == name {
				cfg.Alerting.Emails = append(cfg.Alerting.Emails[:i], cfg.Alerting.Emails[i+1:]...)
				return
			}
		}
	}) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (d *Dashboard) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if !limitedDecodeJSON(w, r, &body) || body.Target == "" {
		writeError(w, http.StatusBadRequest, "target is required")
		return
	}

	// This would ideally call the alerting manager's TestAlert method
	// For now, we just return a success message
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Test alert functionality requires MCP or direct alerting manager access"})
}

// deepCopyConfig creates a deep copy of the config using the generated
// DeepCopy method. This prevents shared mutable state between the dashboard
// and engine without the allocation overhead of JSON round-trip.
func deepCopyConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	return cfg.DeepCopy()
}

// reloadAndPersist applies a config mutation, reloads the engine, and persists
// to disk. Returns true on success, false on failure (error already written to w).
// The caller must provide a function that mutates the deep-copied config.
func (d *Dashboard) reloadAndPersist(w http.ResponseWriter, mutate func(cfg *config.Config)) bool {
	oldCfg := d.engine.Config()
	cfg := deepCopyConfig(oldCfg)
	mutate(cfg)

	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return false
	}

	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			if rollbackErr := d.engine.Reload(oldCfg); rollbackErr != nil {
				dashboardLog.Error("configuration mutation persistence and rollback failed", "save_error", err, "rollback_error", rollbackErr)
			} else {
				dashboardLog.Error("configuration mutation persistence failed; runtime rolled back", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "configuration persistence failed; previous runtime configuration restored")
			return false
		}
	}
	return true
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
