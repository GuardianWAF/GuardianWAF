package engine

import (
	"fmt"
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
	TotalRequests   int64
	BlockedRequests int64
	LoggedRequests  int64
	PassedRequests  int64
	AvgLatencyUs    int64 // average latency in microseconds
}

// Engine is the core WAF engine that processes requests through the detection pipeline.
type Engine struct {
	cfg        *config.Config
	pipeline   atomic.Value // stores *Pipeline
	eventStore EventStorer
	eventBus   EventPublisher

	// Statistics (atomic for lock-free updates)
	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	loggedRequests  atomic.Int64
	passedRequests  atomic.Int64
	totalLatencyUs  atomic.Int64

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

// currentPipeline returns the current pipeline (from atomic.Value).
func (e *Engine) currentPipeline() *Pipeline {
	return e.pipeline.Load().(*Pipeline)
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

	// Create event
	statusCode := 200
	if finalAction == ActionBlock {
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

		// Create event
		statusCode := 200
		if finalAction == ActionBlock {
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
		case ActionLog:
			e.loggedRequests.Add(1)
		default:
			e.passedRequests.Add(1)
		}

		// Store and publish event
		_ = e.eventStore.Store(event)
		e.eventBus.Publish(event)

		// Write response
		w.Header().Set("X-GuardianWAF-RequestID", event.RequestID)

		if finalAction == ActionBlock {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden - Request blocked by GuardianWAF"))
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
		TotalRequests:   total,
		BlockedRequests: e.blockedRequests.Load(),
		LoggedRequests:  e.loggedRequests.Load(),
		PassedRequests:  e.passedRequests.Load(),
		AvgLatencyUs:    avgLatency,
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
