package engine

import (
	"fmt"
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

	// Configuration
	paranoiaLevel  int
	maxBodySize    int64
	blockThreshold int
	logThreshold   int

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
		paranoiaLevel:  2, // default
		maxBodySize:    cfg.WAF.Sanitizer.MaxBodySize,
		blockThreshold: cfg.WAF.Detection.Threshold.Block,
		logThreshold:   cfg.WAF.Detection.Threshold.Log,
	}

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
	e.challengeSvc = svc
}

// SetAccessLog sets a callback for structured access logging.
func (e *Engine) SetAccessLog(fn AccessLogFunc) {
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
	ctx := AcquireContext(r, e.paranoiaLevel, e.maxBodySize)
	defer ReleaseContext(ctx)

	// Execute pipeline
	result := e.currentPipeline().Execute(ctx)

	// Determine final action based on score thresholds
	finalAction := ActionPass
	if result.TotalScore >= e.blockThreshold {
		finalAction = ActionBlock
	} else if result.TotalScore >= e.logThreshold {
		finalAction = ActionLog
	}
	// Pipeline may have already set block (e.g., IP ACL, rate limit)
	if result.Action == ActionBlock {
		finalAction = ActionBlock
	}
	// Promote challenge from pipeline if not already blocked
	if result.Action == ActionChallenge && finalAction != ActionBlock {
		finalAction = ActionChallenge
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
	_ = e.eventStore.Store(event)
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

		// Acquire context and run pipeline (inline, not via Check,
		// so we can access metadata before the context is released)
		ctx := AcquireContext(r, e.paranoiaLevel, e.maxBodySize)

		result := e.currentPipeline().Execute(ctx)

		// Determine final action
		finalAction := ActionPass
		if result.TotalScore >= e.blockThreshold {
			finalAction = ActionBlock
		} else if result.TotalScore >= e.logThreshold {
			finalAction = ActionLog
		}
		if result.Action == ActionBlock {
			finalAction = ActionBlock
		}
		if result.Action == ActionChallenge && finalAction != ActionBlock {
			finalAction = ActionChallenge
		}

		// If challenge, check for valid cookie first — if present, downgrade to pass
		if finalAction == ActionChallenge && e.challengeSvc != nil {
			if e.challengeSvc.HasValidCookie(r, ctx.ClientIP) {
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
		_ = e.eventStore.Store(event)
		e.eventBus.Publish(event)

		// Structured access log
		if e.accessLogFn != nil {
			e.accessLogFn(AccessLogEntry{
				Timestamp:  event.Timestamp.Format("2006-01-02T15:04:05.000Z07:00"),
				ClientIP:   event.ClientIP,
				Method:     event.Method,
				Path:       event.Path,
				StatusCode: statusCode,
				Action:     finalAction.String(),
				Score:      result.TotalScore,
				Duration:   fmt.Sprintf("%d", result.Duration.Microseconds()),
				UserAgent:  event.UserAgent,
				Findings:   len(result.Findings),
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
			if e.challengeSvc != nil {
				e.challengeSvc.ServeChallengePage(w, r)
				return
			}
			// Fallback if no challenge service: block
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(blockPage(event.RequestID, event.Score)))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// applyResponseHook calls the response hook function stored in context metadata.
// The response layer registers this hook during Process() so that security
// headers are applied without circular imports between engine and response packages.
func applyResponseHook(w http.ResponseWriter, metadata map[string]any) {
	if hook, ok := metadata["response_hook"]; ok {
		if fn, ok := hook.(func(http.ResponseWriter)); ok {
			fn(w)
		}
	}
}

// Reload hot-reloads the configuration.
// Updates thresholds and config atomically.
func (e *Engine) Reload(cfg *config.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cfg = cfg
	e.blockThreshold = cfg.WAF.Detection.Threshold.Block
	e.logThreshold = cfg.WAF.Detection.Threshold.Log
	e.maxBodySize = cfg.WAF.Sanitizer.MaxBodySize

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
	}
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

// Close shuts down the engine, closing the event store and bus.
func (e *Engine) Close() error {
	e.eventBus.Close()
	return e.eventStore.Close()
}
