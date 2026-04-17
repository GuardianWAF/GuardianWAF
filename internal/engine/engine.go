package engine

import (
	"context"
	"fmt"
	"strconv"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// EventStorer is the interface for event persistence.
// This is defined in the engine package to avoid circular imports with the events package.
// The events.MemoryStore and events.FileStore types satisfy this interface.
type EventStorer interface {
	Store(event Event) error
	Close() error
}

// EventPublisher is the interface for event publish/subscribe.
// The events.EventBus type satisfies this interface.
type EventPublisher interface {
	Subscribe(ch chan<- Event)
	Publish(event Event)
	Close()
}

// Stats holds runtime statistics for the engine.
type Stats struct {
	TotalRequests      int64
	BlockedRequests    int64
	ChallengedRequests int64
	LoggedRequests     int64
	PassedRequests     int64
	AvgLatencyUs       int64 // average latency in microseconds
	GeoIPReady         bool
	GeoIPRanges        int64
}

// ChallengeChecker is the interface for the JS challenge service.
// Implemented by challenge.Service to avoid circular imports.
type ChallengeChecker interface {
	HasValidCookie(r *http.Request, clientIP net.IP) bool
	ServeChallengePage(w http.ResponseWriter, r *http.Request)
}

// AccessLogFunc is called for every request with structured access log data.
type AccessLogFunc func(entry AccessLogEntry)

// AccessLogEntry holds structured access log data for a single request.
type AccessLogEntry struct {
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Action     string `json:"action"`
	Score      int    `json:"score"`
	Duration   string `json:"duration_us"`
	UserAgent  string `json:"user_agent"`
	Findings   int    `json:"findings"`
	RequestID  string `json:"request_id"`
	TenantID   string `json:"tenant_id,omitempty"`
}

// TenantContext holds tenant information for request isolation.
// This type exists to avoid importing the tenant package in engine (which would
// create a circular dependency). The tenant middleware sets this in context.
type TenantContext struct {
	ID            string                  // Tenant ID
	WAFConfig    *config.WAFConfig       // Tenant's global WAF config
	VirtualHosts []config.VirtualHostConfig // Tenant's virtual hosts (for domain override lookup)
}

// tenantContextKey is the context key for tenant context.
type tenantContextKeyType struct{}

var tenantContextKey = tenantContextKeyType{}

// WithTenantContext adds tenant context to a context.Context.
func WithTenantContext(ctx context.Context, tc *TenantContext) context.Context {
	return context.WithValue(ctx, tenantContextKey, tc)
}

// GetTenantContext retrieves tenant context from a context.Context.
func GetTenantContext(ctx context.Context) *TenantContext {
	if tc, ok := ctx.Value(tenantContextKey).(*TenantContext); ok {
		return tc
	}
	return nil
}

// Engine is the core WAF engine that processes requests through the detection pipeline.
type Engine struct {
	cfg        *config.Config
	pipeline   atomic.Value // stores *Pipeline
	eventStore EventStorer
	eventBus   EventPublisher

	// Challenge service (optional, injected via SetChallengeService)
	challengeSvc ChallengeChecker

	// Application log buffer
	Logs *LogBuffer

	// Access log callback (optional)
	accessLogFn AccessLogFunc

	// Statistics (atomic for lock-free updates)
	totalRequests      atomic.Int64
	blockedRequests    atomic.Int64
	challengedRequests atomic.Int64
	loggedRequests     atomic.Int64
	passedRequests     atomic.Int64
	totalLatencyUs     atomic.Int64

	// Configuration (atomic for lock-free reads in Middleware hot path)
	paranoiaLevel  atomic.Int32
	maxBodySize    atomic.Int64
	blockThreshold atomic.Int32
	logThreshold   atomic.Int32

	// GeoIP status (set via SetGeoIPReady)
	geoipReady atomic.Bool
	geoipCount atomic.Int64

	mu sync.RWMutex // protects cfg
}

// NewEngine creates a new WAF engine from the given configuration.
// It initializes the pipeline (empty - layers are added via AddLayer).
// eventStore and eventBus are injected to avoid circular imports between engine and events packages.
// Both must be non-nil.
func NewEngine(cfg *config.Config, eventStore EventStorer, eventBus EventPublisher) (*Engine, error) {
	if eventStore == nil {
		return nil, fmt.Errorf("eventStore must not be nil")
	}
	if eventBus == nil {
		return nil, fmt.Errorf("eventBus must not be nil")
	}

	e := &Engine{
		cfg:            cfg,
		eventStore:     eventStore,
		eventBus:       eventBus,
		Logs:           NewLogBuffer(2000),
	}
	// Initialize atomic config fields
	e.paranoiaLevel.Store(2) // default
	e.maxBodySize.Store(cfg.WAF.Sanitizer.MaxBodySize)
	e.blockThreshold.Store(int32(cfg.WAF.Detection.Threshold.Block))
	e.logThreshold.Store(int32(cfg.WAF.Detection.Threshold.Log))

	// Configure trusted proxies for X-Forwarded-For handling
	SetTrustedProxies(cfg.TrustedProxies)

	// Initialize empty pipeline
	e.pipeline.Store(NewPipeline())

	// Set up exclusions from config
	if len(cfg.WAF.Detection.Exclusions) > 0 {
		exclusions := make([]Exclusion, len(cfg.WAF.Detection.Exclusions))
		for i, exc := range cfg.WAF.Detection.Exclusions {
			exclusions[i] = Exclusion{
				PathPrefix: exc.Path,
				Detectors:  exc.Detectors,
			}
		}
		e.currentPipeline().SetExclusions(exclusions)
	}

	return e, nil
}

// SetChallengeService injects the JS challenge service into the engine.
func (e *Engine) SetChallengeService(svc ChallengeChecker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.challengeSvc = svc
}

// SetAccessLog sets a callback for structured access logging.
func (e *Engine) SetAccessLog(fn AccessLogFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accessLogFn = fn
}

// currentPipeline returns the current pipeline (from atomic.Value).
func (e *Engine) currentPipeline() *Pipeline {
	return e.pipeline.Load().(*Pipeline)
}

// FindLayer returns the first layer with the given name, or nil.
func (e *Engine) FindLayer(name string) Layer {
	for _, ol := range e.currentPipeline().Layers() {
		if ol.Layer.Name() == name {
			return ol.Layer
		}
	}
	return nil
}

// AddLayer adds a processing layer to the engine's pipeline.
func (e *Engine) AddLayer(layer OrderedLayer) {
	e.currentPipeline().AddLayer(layer)
}

// Check processes an HTTP request through the WAF pipeline.
// Returns an Event describing the outcome.
func (e *Engine) Check(r *http.Request) *Event {
	// Acquire context from pool
	ctx := AcquireContext(r, int(e.paranoiaLevel.Load()), e.maxBodySize.Load())
	defer ReleaseContext(ctx)

	// Execute pipeline
	result := e.currentPipeline().Execute(ctx)

	finalAction := determineAction(result, int(e.blockThreshold.Load()), int(e.logThreshold.Load()))

	// Create event
	statusCode := 200
	switch finalAction {
	case ActionBlock:
		statusCode = 403
	case ActionChallenge:
		statusCode = 403
	}

	event := NewEvent(ctx, statusCode)
	event.Action = finalAction
	event.Score = result.TotalScore
	event.Findings = result.Findings
	event.Duration = result.Duration

	// Update stats
	e.totalRequests.Add(1)
	e.totalLatencyUs.Add(result.Duration.Microseconds())
	switch finalAction {
	case ActionBlock:
		e.blockedRequests.Add(1)
	case ActionChallenge:
		e.challengedRequests.Add(1)
	case ActionLog:
		e.loggedRequests.Add(1)
	default:
		e.passedRequests.Add(1)
	}

	// Store and publish event
	if err := e.eventStore.Store(event); err != nil {
			e.Logs.Add("error", fmt.Sprintf("event store write failed: %v", err))
		}
	e.eventBus.Publish(event)

	return &event
}

// Middleware returns standard Go HTTP middleware.
// It processes requests through the WAF pipeline and either passes to the
// next handler or returns a 403 block response. Security headers from the
// response layer are applied to all responses (both blocked and passed).
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Panic recovery — prevent a single request from crashing the server
		defer func() {
			if rv := recover(); rv != nil {
				e.Logs.Errorf("PANIC recovered in WAF middleware: %v", rv)
				// Best-effort error response — may fail if headers already sent
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			}
		}()

		// Snapshot challenge service and access log under read lock
		e.mu.RLock()
		challengeSvc := e.challengeSvc
		accessLogFn := e.accessLogFn
		e.mu.RUnlock()

		// Acquire context and run pipeline (inline, not via Check,
		// so we can access metadata before the context is released)
		ctx := AcquireContext(r, int(e.paranoiaLevel.Load()), e.maxBodySize.Load())

		// Set tenant info from context if available (set by caller via SetTenantContext)
		// This avoids importing tenant package to break circular dependency
		if tenantCtx := GetTenantContext(r.Context()); tenantCtx != nil {
			ctx.TenantID = tenantCtx.ID
			if tenantCtx.WAFConfig != nil {
				if vh := config.FindVirtualHost(tenantCtx.VirtualHosts, r.Host); vh != nil && vh.WAF != nil {
					ctx.TenantWAFConfig = vh.WAF
				} else {
					ctx.TenantWAFConfig = tenantCtx.WAFConfig
				}
			}
		}

		result := e.currentPipeline().Execute(ctx)

		finalAction := determineAction(result, int(e.blockThreshold.Load()), int(e.logThreshold.Load()))

		// If challenge, check for valid cookie first — if present, downgrade to pass
		if finalAction == ActionChallenge && challengeSvc != nil {
			if challengeSvc.HasValidCookie(r, ctx.ClientIP) {
				finalAction = ActionPass
			}
		}

		// Create event
		statusCode := 200
		switch finalAction {
		case ActionBlock:
			statusCode = 403
		case ActionChallenge:
			statusCode = 403
		}
		event := NewEvent(ctx, statusCode)
		event.Action = finalAction
		event.Score = result.TotalScore
		event.Findings = result.Findings
		event.Duration = result.Duration

		// Apply security headers from response layer hook
		applyResponseHook(w, ctx.Metadata)

		// Extract masking function before releasing context
		var maskFn func(string) string
		if fn, ok := ctx.Metadata["response_mask_fn"]; ok {
			if f, ok := fn.(func(string) string); ok {
				maskFn = f
			}
		}

		// Capture tenant ID before releasing context (pool resets all fields)
		tenantID := ctx.TenantID

		// Release context back to pool
		ReleaseContext(ctx)

		// Update stats
		e.totalRequests.Add(1)
		e.totalLatencyUs.Add(result.Duration.Microseconds())
		switch finalAction {
		case ActionBlock:
			e.blockedRequests.Add(1)
		case ActionChallenge:
			e.challengedRequests.Add(1)
		case ActionLog:
			e.loggedRequests.Add(1)
		default:
			e.passedRequests.Add(1)
		}

		// Store and publish event
		if err := e.eventStore.Store(event); err != nil {
			e.Logs.Add("error", fmt.Sprintf("event store write failed: %v", err))
		}
		e.eventBus.Publish(event)

		// Structured access log
		if accessLogFn != nil {
			accessLogFn(AccessLogEntry{
				Timestamp:  event.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
				ClientIP:   event.ClientIP,
				Method:     event.Method,
				Path:       event.Path,
				StatusCode: statusCode,
				Action:     finalAction.String(),
				Score:      result.TotalScore,
				Duration:   strconv.FormatInt(result.Duration.Microseconds(), 10),
				UserAgent:  event.UserAgent,
				Findings:   len(result.Findings),
				RequestID:  event.RequestID,
				TenantID:   tenantID,
			})
		}

		// Write response
		w.Header().Set("X-GuardianWAF-RequestID", event.RequestID)

		switch finalAction {
		case ActionBlock:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockPage(event.RequestID, event.Score)))
			return
		case ActionChallenge:
			if challengeSvc != nil {
				challengeSvc.ServeChallengePage(w, r)
				return
			}
			// Fallback if no challenge service: block
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockPage(event.RequestID, event.Score)))
			return
		}

		if maskFn != nil {
			mwr := newMaskingResponseWriter(w, maskFn)
			next.ServeHTTP(mwr, r)
			mwr.FlushMasked()
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// applyResponseHook calls the response hook function stored in context metadata.
// The response layer registers this hook during Process() so that security
// headers are applied without circular imports between engine and response packages.
// It also applies CORS headers stored by the CORS layer (Order 150) since the
// CORS layer runs before the response layer (Order 600) and stores headers in
// metadata rather than registering its own hook to avoid overwriting the response hook.
func applyResponseHook(w http.ResponseWriter, metadata map[string]any) {
	// Apply CORS headers from the CORS layer (runs before response layer).
	// The CORS layer stores headers in cors_headers/cors_preflight_headers metadata.
	applyCORSHook(w, metadata)

	// Apply the main response hook (security headers from response layer).
	if hook, ok := metadata["response_hook"]; ok {
		if fn, ok := hook.(func(http.ResponseWriter)); ok {
			fn(w)
		}
	}
}

// applyCORSHook applies CORS headers stored in context metadata by the CORS layer.
func applyCORSHook(w http.ResponseWriter, metadata map[string]any) {
	// Preflight headers take precedence if set (handled by CORS layer directly)
	if headers, ok := metadata["cors_preflight_headers"].(map[string]string); ok {
		w.Header().Set("Vary", "Origin")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		return
	}
	// Regular CORS headers from the CORS layer's Process()
	if headers, ok := metadata["cors_headers"].(map[string]string); ok {
		w.Header().Set("Vary", "Origin")
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		if expose, ok := metadata["cors_expose_headers"].(string); ok && expose != "" {
			w.Header().Set("Access-Control-Expose-Headers", expose)
		}
	}
}

// Reload hot-reloads the configuration.
// Updates thresholds and config atomically.
// The config is deep-copied to prevent caller mutations from affecting the engine.
func (e *Engine) Reload(cfg *config.Config) error {
	// Deep copy via Config.DeepCopy() to avoid GC pressure from JSON marshal/unmarshal
	cfgCopy := cfg.DeepCopy()
	if cfgCopy == nil {
		return fmt.Errorf("config deep copy returned nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.cfg = cfgCopy
	e.blockThreshold.Store(int32(e.cfg.WAF.Detection.Threshold.Block))
	e.logThreshold.Store(int32(e.cfg.WAF.Detection.Threshold.Log))
	e.maxBodySize.Store(e.cfg.WAF.Sanitizer.MaxBodySize)

	// Note: layers are re-added by the caller after reload
	// This just updates thresholds and config

	return nil
}

// Stats returns current runtime statistics.
func (e *Engine) Stats() Stats {
	total := e.totalRequests.Load()
	var avgLatency int64
	if total > 0 {
		avgLatency = e.totalLatencyUs.Load() / total
	}
	return Stats{
		TotalRequests:      total,
		BlockedRequests:    e.blockedRequests.Load(),
		ChallengedRequests: e.challengedRequests.Load(),
		LoggedRequests:     e.loggedRequests.Load(),
		PassedRequests:     e.passedRequests.Load(),
		AvgLatencyUs:       avgLatency,
		GeoIPReady:         e.geoipReady.Load(),
		GeoIPRanges:        e.geoipCount.Load(),
	}
}

// SetGeoIPStatus updates the GeoIP readiness state exposed via Stats and health checks.
func (e *Engine) SetGeoIPStatus(ready bool, count int) {
	e.geoipReady.Store(ready)
	e.geoipCount.Store(int64(count))
}

// EventStore returns the engine's event store.
func (e *Engine) EventStore() EventStorer {
	return e.eventStore
}

// EventBus returns the engine's event bus.
func (e *Engine) EventBus() EventPublisher {
	return e.eventBus
}

// Config returns the current configuration (read-only).
func (e *Engine) Config() *config.Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Close shuts down the engine, closing the event store first (to drain pending writes),
// then the event bus.
func (e *Engine) Close() error {
	err := e.eventStore.Close()
	e.eventBus.Close()
	return err
}
// determineAction computes the final action from a pipeline result and score thresholds.
func determineAction(result PipelineResult, blockThresh, logThresh int) Action {
	action := ActionPass
	if result.TotalScore >= blockThresh {
		action = ActionBlock
	} else if result.TotalScore >= logThresh {
		action = ActionLog
	}
	if result.Action == ActionBlock {
		action = ActionBlock
	}
	if result.Action == ActionChallenge && action != ActionBlock {
		action = ActionChallenge
	}
	return action
}
