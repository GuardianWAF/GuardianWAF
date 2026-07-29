// Package dashboard provides the web dashboard and REST API for GuardianWAF.
// It serves a real-time monitoring UI with SSE event streaming,
// REST endpoints for stats/events/config, and embedded static assets.
package dashboard

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/compliance"
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
	adminKey         string       // Separate key for system admin operations (tenant management, billing, stats)
	pprofKey         string       // Separate key for pprof debug endpoints (more restrictive than apiKey)
	tenantAPIKeysMu  sync.RWMutex // protects tenantAPIKeys during authentication and admin mutations
	tenantAPIKeys    map[string]string
	trustedProxyNets []*net.IPNet // Direct proxy CIDRs trusted for forwarded TLS metadata
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
	tenantAdminHandler    *TenantAdminHandler

	// Audit log for REST API mutations
	auditLog *AuditLog
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

// CurrentAPIKey returns only the active dashboard key. Grace-period keys are
// intentionally excluded so dependent security surfaces revoke them immediately.
func (d *Dashboard) CurrentAPIKey() string {
	current, _ := d.loadActiveAPIKeys()
	return current
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
// Keys are stored as hashes (not plaintext) in the same format as tenant.Manager.
func (d *Dashboard) SetTenantAPIKey(tenantID, apiKeyHash string) {
	if d == nil || tenantID == "" {
		return
	}
	d.tenantAPIKeysMu.Lock()
	defer d.tenantAPIKeysMu.Unlock()
	if d.tenantAPIKeys == nil {
		d.tenantAPIKeys = make(map[string]string)
	}
	if apiKeyHash == "" {
		delete(d.tenantAPIKeys, tenantID)
		return
	}
	d.tenantAPIKeys[tenantID] = apiKeyHash
}

func (d *Dashboard) tenantAPIKeyHash(tenantID string) (string, bool) {
	d.tenantAPIKeysMu.RLock()
	defer d.tenantAPIKeysMu.RUnlock()
	hash, ok := d.tenantAPIKeys[tenantID]
	return hash, ok
}

type tenantAuthRecord struct {
	ID         string `json:"id"`
	APIKeyHash string `json:"api_key_hash"`
}

func decodeTenantAuthRecord(tenant any) (tenantAuthRecord, bool) {
	data, err := json.Marshal(tenant)
	if err != nil {
		return tenantAuthRecord{}, false
	}
	var record tenantAuthRecord
	if err := json.Unmarshal(data, &record); err != nil || record.ID == "" {
		return tenantAuthRecord{}, false
	}
	return record, true
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
		auditLog:    NewAuditLog(0),
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

type tenantAPIKeySnapshotProvider interface {
	TenantAPIKeyHashes() map[string]string
}

// syncTenantAPIKeys replaces the tenant-key snapshot used by dashboard authentication.
// Production adapters provide an immutable snapshot copied under their manager lock;
// JSON-tagged records remain a compatibility fallback for lightweight adapters.
func (d *Dashboard) syncTenantAPIKeys(manager tenantManagerInterface) {
	if manager == nil {
		return
	}
	var keys map[string]string
	if provider, ok := manager.(tenantAPIKeySnapshotProvider); ok {
		snapshot := provider.TenantAPIKeyHashes()
		keys = make(map[string]string, len(snapshot))
		for id, hash := range snapshot {
			if id != "" && hash != "" {
				keys[id] = hash
			}
		}
	} else {
		tenants := manager.ListTenants()
		keys = make(map[string]string, len(tenants))
		for _, tenant := range tenants {
			record, ok := decodeTenantAuthRecord(tenant)
			if !ok || record.APIKeyHash == "" {
				continue
			}
			keys[record.ID] = record.APIKeyHash
		}
	}
	if keys == nil {
		keys = make(map[string]string)
	}

	d.tenantAPIKeysMu.Lock()
	d.tenantAPIKeys = keys
	d.tenantAPIKeysMu.Unlock()
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
