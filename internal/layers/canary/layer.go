package canary

import (
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer provides canary release functionality as a WAF layer.
type Layer struct {
	canary *Canary
	config *LayerConfig
}

// LayerConfig for canary layer.
type LayerConfig struct {
	Enabled bool    `yaml:"enabled"`
	Config  *Config `yaml:"canary_config"`
}

// NewLayer creates a new canary layer.
func NewLayer(cfg *LayerConfig) (*Layer, error) {
	if cfg == nil {
		cfg = &LayerConfig{
			Enabled: false,
			Config:  DefaultConfig(),
		}
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	canary, err := New(cfg.Config)
	if err != nil {
		return nil, err
	}

	return &Layer{
		canary: canary,
		config: cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "canary"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 95 // Early, before IP ACL (100)
}

// Process implements the layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	if !l.config.Enabled || l.canary == nil {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.Canary.Enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Mark request for canary routing
	if l.canary.ShouldRouteToCanary(ctx.Request) {
		ctx.Metadata["canary"] = true
		ctx.Metadata["canary_upstream"] = l.canary.config.CanaryUpstream
	}

	return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
}

// GetCanary returns the canary manager.
func (l *Layer) GetCanary() *Canary {
	return l.canary
}

// GetStats returns canary statistics.
func (l *Layer) GetStats() map[string]any {
	if l.canary == nil {
		return map[string]any{
			"enabled": false,
		}
	}
	return l.canary.GetStats()
}

// Close closes the layer.
func (l *Layer) Close() error {
	if l.canary != nil {
		return l.canary.Close()
	}
	return nil
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)

// Middleware provides HTTP middleware for canary routing.
type Middleware struct {
	canary *Canary
}

// NewMiddleware creates new canary middleware.
func NewMiddleware(canary *Canary) *Middleware {
	return &Middleware{canary: canary}
}

// Handler wraps an HTTP handler with canary routing.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.canary != nil && m.canary.ShouldRouteToCanary(r) {
			// Add canary header for downstream identification
			r.Header.Set("X-Canary-Version", m.canary.config.CanaryVersion)
		}
		next.ServeHTTP(w, r)
	})
}

// Router handles upstream selection for canary releases.
type Router struct {
	canary *Canary
}

// NewRouter creates a new canary router.
func NewRouter(canary *Canary) *Router {
	return &Router{canary: canary}
}

// SelectUpstream returns the appropriate upstream for the request.
func (r *Router) SelectUpstream(req *http.Request) string {
	if r.canary == nil {
		return ""
	}
	return r.canary.GetUpstream(req)
}

// IsCanaryRequest checks if request should be routed to canary.
func (r *Router) IsCanaryRequest(req *http.Request) bool {
	if r.canary == nil {
		return false
	}
	return r.canary.ShouldRouteToCanary(req)
}

// RecordingResponseWriter wraps http.ResponseWriter to capture status code.
type RecordingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	isCanary   bool
	canary     *Canary
	startTime  time.Time
}

// NewRecordingResponseWriter creates a wrapped response writer.
func NewRecordingResponseWriter(w http.ResponseWriter, canary *Canary, isCanary bool) *RecordingResponseWriter {
	return &RecordingResponseWriter{
		ResponseWriter: w,
		statusCode:     200,
		isCanary:       isCanary,
		canary:         canary,
		startTime:      time.Now(),
	}
}

// WriteHeader captures status code.
func (rw *RecordingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Close records metrics when response is complete.
func (rw *RecordingResponseWriter) Close() {
	if rw.canary != nil {
		latency := time.Since(rw.startTime)
		rw.canary.RecordResult(rw.isCanary, rw.statusCode, latency)
	}
}
