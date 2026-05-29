package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/tracing"
)

// TenantContext holds tenant information for request isolation.
// This type exists to avoid importing the tenant package in engine (which would
// create a circular dependency). The tenant middleware sets this in context.
type TenantContext struct {
	ID           string                     // Tenant ID
	WAFConfig    *config.WAFConfig          // Tenant's global WAF config
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
	paranoiaLevel     atomic.Int32
	maxBodySize       atomic.Int64
	blockThreshold    atomic.Int32
	logThreshold      atomic.Int32
	trustedProxyCIDRs atomic.Value // stores []*net.IPNet

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
		cfg:        cfg,
		eventStore: eventStore,
		eventBus:   eventBus,
		Logs:       NewLogBuffer(2000),
	}
	// Initialize atomic config fields
	e.paranoiaLevel.Store(2) // default
	e.maxBodySize.Store(cfg.WAF.Sanitizer.MaxBodySize)
	e.blockThreshold.Store(int32(cfg.WAF.Detection.Threshold.Block))
	e.logThreshold.Store(int32(cfg.WAF.Detection.Threshold.Log))

	// Configure trusted proxies for X-Forwarded-For handling. The engine keeps
	// an instance-local copy so multiple Engine instances cannot overwrite each
	// other's client IP trust model through package-global state.
	proxyCIDRs := parseTrustedProxyCIDRs(cfg.TrustedProxies)
	e.trustedProxyCIDRs.Store(proxyCIDRs)
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

// PipelineLayers returns a read-only snapshot of active pipeline layer names and orders.
func (e *Engine) PipelineLayers() []PipelineLayerInfo {
	layers := e.currentPipeline().Layers()
	out := make([]PipelineLayerInfo, 0, len(layers))
	for _, layer := range layers {
		if layer.Layer == nil {
			continue
		}
		out = append(out, PipelineLayerInfo{Name: layer.Layer.Name(), Order: layer.Order})
	}
	return out
}

// statusForAction maps a final WAF action to the HTTP status recorded in the event.
func statusForAction(a Action) int {
	switch a {
	case ActionBlock, ActionChallenge:
		return 403
	default:
		return 200
	}
}

// startRootSpan starts the per-request root trace span when tracing is enabled
// and the request is sampled, assigning it to ctx.TraceSpan. It returns the span
// (or nil) so the caller controls when to End it.
func (e *Engine) startRootSpan(ctx *RequestContext, r *http.Request) *tracing.Span {
	if !tracing.Enabled() || !tracing.ShouldSample() {
		return nil
	}
	span := tracing.StartSpan("waf.request", tracing.SpanKindServer)
	span.SetAttribute(tracing.AttrHTTPMethod, r.Method)
	span.SetAttribute(tracing.AttrHTTPURL, redactSensitiveURL(r.URL.String()))
	span.SetAttribute(tracing.AttrHTTPHost, r.Host)
	if ua := r.UserAgent(); ua != "" {
		span.SetAttribute(tracing.AttrHTTPUserAgent, redactSensitiveEvidence(ua))
	}
	ctx.TraceSpan = span
	return span
}

// buildEvent constructs the Event describing a processed request.
func (e *Engine) buildEvent(ctx *RequestContext, result PipelineResult, finalAction Action) Event {
	event := NewEvent(ctx, statusForAction(finalAction))
	event.Action = finalAction
	event.Score = result.TotalScore
	event.Findings = redactFindings(result.Findings)
	event.Duration = result.Duration
	return event
}

// recordStats updates the atomic request counters for a final action.
func (e *Engine) recordStats(finalAction Action, d time.Duration) {
	e.totalRequests.Add(1)
	e.totalLatencyUs.Add(d.Microseconds())
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
}

// storeAndPublish persists and broadcasts an event, logging store failures.
func (e *Engine) storeAndPublish(event Event) {
	if err := e.eventStore.Store(event); err != nil {
		e.Logs.Add("error", fmt.Sprintf("event store write failed: %v", err))
	}
	e.eventBus.Publish(event)
}

// Check processes an HTTP request through the WAF pipeline.
// Returns an Event describing the outcome. Check is a dry-run scorer: unlike
// Middleware it does not apply per-tenant config overrides or write a response.
func (e *Engine) Check(r *http.Request) *Event {
	// Acquire context from pool
	ctx := AcquireContext(r, int(e.paranoiaLevel.Load()), e.maxBodySize.Load())
	ctx.ClientIP = e.extractClientIP(r)
	defer ReleaseContext(ctx)

	if span := e.startRootSpan(ctx, r); span != nil {
		defer span.End()
	}

	// Execute pipeline
	result := e.currentPipeline().Execute(ctx)
	finalAction := determineAction(result, int(e.blockThreshold.Load()), int(e.logThreshold.Load()))

	event := e.buildEvent(ctx, result, finalAction)
	e.recordStats(finalAction, result.Duration)
	e.storeAndPublish(event)

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
				e.Logs.ErrorWithStack(fmt.Sprintf("PANIC recovered in WAF middleware: %v", rv))
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
		ctx.ClientIP = e.extractClientIP(r)

		// Start root trace span if tracing is enabled and sampled. Unlike Check,
		// Middleware ends the span manually before releasing the context.
		e.startRootSpan(ctx, r)

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
		event := e.buildEvent(ctx, result, finalAction)
		statusCode := event.StatusCode

		// Apply security headers from response layer hook
		applyResponseHook(w, ctx.Metadata)

		// Extract masking function before releasing context
		var maskFn func(string) string
		if fn, ok := ctx.Metadata["response_mask_fn"]; ok {
			if f, ok := fn.(func(string) string); ok {
				maskFn = f
			}
		}

		// Extract client-side response body transform (Magecart/agent-injection)
		// before releasing context. The closure captures only value copies.
		var bodyXform func([]byte, string) ([]byte, bool)
		if fn, ok := ctx.Metadata["clientside_response_hook"]; ok {
			if f, ok := fn.(func([]byte, string) ([]byte, bool)); ok {
				bodyXform = f
			}
		}

		// Capture tenant ID before releasing context (pool resets all fields)
		tenantID := ctx.TenantID

		// End trace span before releasing context
		if ctx.TraceSpan != nil {
			ctx.TraceSpan.SetAttribute(tracing.AttrWAFAction, finalAction.String())
			ctx.TraceSpan.SetAttribute(tracing.AttrWAFScore, strconv.Itoa(result.TotalScore))
			ctx.TraceSpan.End()
		}

		// Release context back to pool
		ReleaseContext(ctx)

		e.recordStats(finalAction, result.Duration)
		e.storeAndPublish(event)

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

		// Set correlation headers: on request (for upstream proxy) and response (for client)
		r.Header.Set("X-Correlation-ID", event.RequestID)
		w.Header().Set("X-GuardianWAF-RequestID", event.RequestID)

		switch finalAction {
		case ActionBlock:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockPage(event.RequestID, event.Score))) // nolint:errcheck // block page write; error ignored
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
			_, _ = w.Write([]byte(blockPage(event.RequestID, event.Score))) // nolint:errcheck // block page write; error ignored
			return
		}

		if maskFn != nil || bodyXform != nil {
			mwr := newMaskingResponseWriter(w, maskFn, bodyXform)
			next.ServeHTTP(mwr, r)
			mwr.FlushMasked()
		} else {
			next.ServeHTTP(w, r)
		}
	})
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
	proxyCIDRs := parseTrustedProxyCIDRs(e.cfg.TrustedProxies)
	e.trustedProxyCIDRs.Store(proxyCIDRs)
	SetTrustedProxies(e.cfg.TrustedProxies)

	// Note: layers are re-added by the caller after reload
	// This just updates thresholds and config

	return nil
}

func (e *Engine) extractClientIP(r *http.Request) net.IP {
	cidrs, _ := e.trustedProxyCIDRs.Load().([]*net.IPNet)
	return extractClientIPWithTrustedProxies(r, cidrs)
}

// ExtractClientIP determines the real client IP using this engine's trusted
// proxy configuration. Prefer this method over the package-level ExtractClientIP
// when wiring runtime services that must share the engine's trust model.
func (e *Engine) ExtractClientIP(r *http.Request) net.IP {
	return e.extractClientIP(r)
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

// Config returns a defensive copy of the current configuration.
func (e *Engine) Config() *config.Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.DeepCopy()
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
