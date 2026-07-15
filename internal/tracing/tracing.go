// Package tracing provides a lightweight, zero-dependency distributed tracing
// infrastructure for GuardianWAF. It uses the OpenTelemetry vocabulary (spans,
// attributes, exporters) but is implemented entirely with the Go stdlib.
//
// This design allows external OpenTelemetry SDKs to be plugged in later via
// build tags without changing the tracing API surface.
package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SpanKind classifies the span.
type SpanKind int

const (
	SpanKindInternal SpanKind = iota
	SpanKindServer
	SpanKindClient
	SpanKindProducer
	SpanKindConsumer
)

// SpanStatus represents the span outcome.
type SpanStatus int

const (
	SpanStatusUnset SpanStatus = iota
	SpanStatusOK
	SpanStatusError
)

// Span represents a unit of work in a trace.
type Span struct {
	Name       string
	Kind       SpanKind
	Status     SpanStatus
	StartTime  time.Time
	EndTime    time.Time
	Attributes map[string]string
	Events     []SpanEvent
	ParentID   string
	SpanID     string
	TraceID    string
	mu         sync.Mutex
	tracer     *Tracer
}

// SpanEvent is a timed log entry within a span.
type SpanEvent struct {
	Name       string
	Timestamp  time.Time
	Attributes map[string]string
}

// SetAttribute sets a single attribute on the span.
func (s *Span) SetAttribute(key, value string) {
	s.mu.Lock()
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = value
	s.mu.Unlock()
}

// AddEvent records a timed event on the span.
func (s *Span) AddEvent(name string, attrs map[string]string) {
	s.mu.Lock()
	s.Events = append(s.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
	s.mu.Unlock()
}

// End completes the span and exports it.
func (s *Span) End() {
	s.mu.Lock()
	if !s.EndTime.IsZero() {
		s.mu.Unlock()
		return
	}
	s.EndTime = time.Now()
	tracer := s.tracer
	s.mu.Unlock()
	if tracer != nil {
		tracer.export(s)
	}
}

// Duration returns the span duration.
func (s *Span) Duration() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// IsRecording returns true if the span is active.
func (s *Span) IsRecording() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.EndTime.IsZero()
}

// StartChild creates a child span tied to the same engine-local tracer.
func (s *Span) StartChild(name string, kind SpanKind) *Span {
	if s == nil || s.tracer == nil {
		return nil
	}
	child := s.tracer.StartSpanWithParent(name, kind, s.TraceID)
	child.ParentID = s.SpanID
	return child
}

// Exporter receives completed spans.
type Exporter interface {
	Export(span *Span)
	Shutdown()
}

// Config holds tracing configuration.
type Config struct {
	Enabled      bool
	ServiceName  string
	SamplingRate float64 // 0.0-1.0, fraction of requests to trace
	ExporterType string  // "stdout", "noop", or custom name
}

// Tracer creates and manages spans.
type Tracer struct {
	mu       sync.RWMutex
	config   Config
	exporter Exporter
	enabled  atomic.Bool
	samples  atomic.Int64
	spans    atomic.Int64
	exported atomic.Int64
}

var globalTracer = func() *Tracer {
	tracer, _ := NewTracer(Config{})
	return tracer
}()

// ValidateConfig rejects values that would silently disable or corrupt tracing.
func ValidateConfig(cfg Config) error {
	if math.IsNaN(cfg.SamplingRate) || math.IsInf(cfg.SamplingRate, 0) || cfg.SamplingRate < 0 || cfg.SamplingRate > 1 {
		return fmt.Errorf("sampling rate must be a finite number between 0 and 1")
	}
	switch cfg.ExporterType {
	case "", "noop", "stdout":
		return nil
	default:
		return fmt.Errorf("exporter type must be one of: noop, stdout")
	}
}

// NewTracer creates an isolated tracer for one GuardianWAF engine.
func NewTracer(cfg Config) (*Tracer, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	t := &Tracer{}
	if err := t.Reconfigure(cfg); err != nil {
		return nil, err
	}
	return t, nil
}

func exporterFor(name string) Exporter {
	if name == "stdout" {
		return NewStdoutExporter()
	}
	return NewNoopExporter()
}

// Init initializes the global tracer with the given config.
func Init(cfg Config) error {
	return globalTracer.Reconfigure(cfg)
}

// Reconfigure atomically replaces a tracer's runtime configuration.
func (t *Tracer) Reconfigure(cfg Config) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if cfg.Enabled && cfg.ServiceName == "" {
		cfg.ServiceName = "guardianwaf"
	}
	nextExporter := exporterFor(cfg.ExporterType)
	t.mu.Lock()
	oldExporter := t.exporter
	t.config = cfg
	t.exporter = nextExporter
	t.enabled.Store(cfg.Enabled)
	t.mu.Unlock()
	if oldExporter != nil {
		oldExporter.Shutdown()
	}
	return nil
}

// SetExporter sets a custom exporter on the global tracer.
func SetExporter(e Exporter) {
	globalTracer.SetExporter(e)
}

// SetExporter sets a custom exporter on this tracer.
func (t *Tracer) SetExporter(e Exporter) {
	if e == nil {
		e = NewNoopExporter()
	}
	t.mu.Lock()
	oldExporter := t.exporter
	t.exporter = e
	t.mu.Unlock()
	if oldExporter != nil {
		oldExporter.Shutdown()
	}
}

// Enabled reports whether tracing is active.
func Enabled() bool {
	return globalTracer.Enabled()
}

// Enabled reports whether this tracer is active.
func (t *Tracer) Enabled() bool {
	return t != nil && t.enabled.Load()
}

// ShouldSample returns true if the current request should be traced,
// based on the configured sampling rate.
func ShouldSample() bool {
	return globalTracer.ShouldSample()
}

// ShouldSample reports whether the next request should be traced.
func (t *Tracer) ShouldSample() bool {
	if t == nil || !t.enabled.Load() {
		return false
	}
	t.mu.RLock()
	rate := t.config.SamplingRate
	t.mu.RUnlock()
	if rate >= 1.0 {
		return true
	}
	if rate <= 0.0 {
		return false
	}
	// Deterministic sampling using span counter
	n := t.samples.Add(1)
	return float64(n%100)/100.0 < rate
}

// StartSpan creates a new span with the given name and kind.
func StartSpan(name string, kind SpanKind) *Span {
	return globalTracer.StartSpan(name, kind)
}

// StartSpanWithParent creates a new span linked to a parent.
func StartSpanWithParent(name string, kind SpanKind, parentTraceID string) *Span {
	return globalTracer.StartSpanWithParent(name, kind, parentTraceID)
}

// StartSpan creates a span owned by this tracer.
func (t *Tracer) StartSpan(name string, kind SpanKind) *Span {
	return t.StartSpanWithParent(name, kind, "")
}

// StartSpanWithParent creates a span owned by this tracer.
func (t *Tracer) StartSpanWithParent(name string, kind SpanKind, parentTraceID string) *Span {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	serviceName := t.config.ServiceName
	t.mu.RUnlock()
	spanNumber := t.spans.Add(1)
	span := &Span{
		Name:      name,
		Kind:      kind,
		StartTime: time.Now(),
		SpanID:    randomHexID(8, spanNumber),
		TraceID:   parentTraceID,
		tracer:    t,
	}
	if serviceName != "" {
		span.Attributes = map[string]string{"service.name": serviceName}
	}
	if span.TraceID == "" {
		span.TraceID = randomHexID(16, spanNumber)
	}
	return span
}

func randomHexID(byteLength int, fallback int64) string {
	id := make([]byte, byteLength)
	if _, err := rand.Read(id); err == nil {
		return hex.EncodeToString(id)
	}
	return fmt.Sprintf("%0*x", byteLength*2, fallback)
}

// Shutdown flushes pending spans and stops the tracer.
func Shutdown() {
	globalTracer.Shutdown()
}

// Shutdown disables this tracer and closes its exporter.
func (t *Tracer) Shutdown() {
	if t == nil {
		return
	}
	t.enabled.Store(false)
	t.mu.Lock()
	exporter := t.exporter
	t.exporter = nil
	t.mu.Unlock()
	if exporter != nil {
		exporter.Shutdown()
	}
}

// Stats returns tracing statistics.
func Stats() (enabled bool, spansCreated, spansExported int64) {
	return globalTracer.Stats()
}

// Stats returns statistics for this tracer.
func (t *Tracer) Stats() (enabled bool, spansCreated, spansExported int64) {
	if t == nil {
		return false, 0, 0
	}
	return t.enabled.Load(), t.spans.Load(), t.exported.Load()
}

func (t *Tracer) export(span *Span) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.exporter == nil {
		return
	}
	t.exporter.Export(span)
	t.exported.Add(1)
}

// NoopExporter discards all spans.
type NoopExporter struct{}

// NewNoopExporter creates an exporter that discards spans.
func NewNoopExporter() *NoopExporter { return &NoopExporter{} }

func (n *NoopExporter) Export(_ *Span) {}
func (n *NoopExporter) Shutdown()      {}

// StdoutExporter prints spans as JSON lines to stdout (for debugging).
type StdoutExporter struct {
	mu     sync.Mutex
	count  atomic.Int64
	closed atomic.Bool
}

// NewStdoutExporter creates an exporter that writes JSON to stdout.
func NewStdoutExporter() *StdoutExporter { return &StdoutExporter{} }

func (s *StdoutExporter) Export(span *Span) {
	if s.closed.Load() {
		return
	}
	s.count.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()

	span.mu.Lock()
	duration := time.Since(span.StartTime)
	if !span.EndTime.IsZero() {
		duration = span.EndTime.Sub(span.StartTime)
	}
	status := "OK"
	if span.Status == SpanStatusError {
		status = "ERROR"
	}

	// Build a JSON-safe map to avoid fmt.Printf with raw strings
	logEntry := map[string]any{
		"trace_id": span.TraceID,
		"span_id":  span.SpanID,
		"name":     span.Name,
		"duration": duration.String(),
		"status":   status,
	}
	for k, v := range span.Attributes {
		logEntry[k] = v
	}
	span.mu.Unlock()

	out, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tracing: failed to marshal span: %v\n", err)
		return
	}
	fmt.Println(string(out))
}

func (s *StdoutExporter) Shutdown() {
	s.closed.Store(true)
}

// SpanAttribute constants following OpenTelemetry semantic conventions.
const (
	AttrHTTPMethod    = "http.method"
	AttrHTTPURL       = "http.url"
	AttrHTTPHost      = "http.host"
	AttrHTTPCode      = "http.status_code"
	AttrHTTPUserAgent = "http.user_agent"

	AttrClientIP     = "client.ip"
	AttrWAFLayer     = "waf.layer"
	AttrWAFAction    = "waf.action"
	AttrWAFScore     = "waf.score"
	AttrWAFTenantID  = "waf.tenant_id"
	AttrWAFBlocked   = "waf.blocked"
	AttrWAFLatencyMs = "waf.latency_ms"
	AttrWAFRuleID    = "waf.rule_id"
	AttrWAFDetector  = "waf.detector"
	AttrWAFFinding   = "waf.finding"
)
