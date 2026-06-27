// Package tracing provides a lightweight, zero-dependency distributed tracing
// infrastructure for GuardianWAF. It uses the OpenTelemetry vocabulary (spans,
// attributes, exporters) but is implemented entirely with the Go stdlib.
//
// This design allows external OpenTelemetry SDKs to be plugged in later via
// build tags without changing the tracing API surface.
package tracing

import (
	"encoding/json"
	"fmt"
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
	if s.EndTime.IsZero() {
		s.EndTime = time.Now()
	}
	if globalTracer.exporter != nil {
		globalTracer.exporter.Export(s)
	}
}

// Duration returns the span duration.
func (s *Span) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// IsRecording returns true if the span is active.
func (s *Span) IsRecording() bool {
	return s != nil && s.EndTime.IsZero()
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
	config   Config
	exporter Exporter
	enabled  atomic.Bool
	spans    atomic.Int64
	exported atomic.Int64
}

var globalTracer = &Tracer{}

// Init initializes the global tracer with the given config.
func Init(cfg Config) {
	globalTracer.config = cfg
	globalTracer.enabled.Store(cfg.Enabled)

	switch cfg.ExporterType {
	case "stdout":
		globalTracer.exporter = NewStdoutExporter()
	default:
		globalTracer.exporter = NewNoopExporter()
	}
}

// SetExporter sets a custom exporter on the global tracer.
func SetExporter(e Exporter) {
	globalTracer.exporter = e
}

// Enabled reports whether tracing is active.
func Enabled() bool {
	return globalTracer.enabled.Load()
}

// ShouldSample returns true if the current request should be traced,
// based on the configured sampling rate.
func ShouldSample() bool {
	if !globalTracer.enabled.Load() {
		return false
	}
	if globalTracer.config.SamplingRate >= 1.0 {
		return true
	}
	if globalTracer.config.SamplingRate <= 0.0 {
		return false
	}
	// Deterministic sampling using span counter
	n := globalTracer.spans.Add(1)
	return float64(n%100)/100.0 < globalTracer.config.SamplingRate
}

// StartSpan creates a new span with the given name and kind.
func StartSpan(name string, kind SpanKind) *Span {
	return StartSpanWithParent(name, kind, "")
}

// StartSpanWithParent creates a new span linked to a parent.
func StartSpanWithParent(name string, kind SpanKind, parentTraceID string) *Span {
	span := &Span{
		Name:      name,
		Kind:      kind,
		StartTime: time.Now(),
		SpanID:    fmt.Sprintf("%016x", globalTracer.spans.Add(1)),
		TraceID:   parentTraceID,
	}
	if span.TraceID == "" {
		span.TraceID = span.SpanID // root span: trace ID = span ID
	}
	return span
}

// Shutdown flushes pending spans and stops the tracer.
func Shutdown() {
	globalTracer.enabled.Store(false)
	if globalTracer.exporter != nil {
		globalTracer.exporter.Shutdown()
	}
}

// Stats returns tracing statistics.
func Stats() (enabled bool, spansCreated, spansExported int64) {
	return globalTracer.enabled.Load(), globalTracer.spans.Load(), globalTracer.exported.Load()
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

	duration := span.Duration().String()
	status := "OK"
	if span.Status == SpanStatusError {
		status = "ERROR"
	}

	// Build a JSON-safe map to avoid fmt.Printf with raw strings
	logEntry := map[string]any{
		"trace_id": span.TraceID,
		"span_id":  span.SpanID,
		"name":     span.Name,
		"duration": duration,
		"status":   status,
	}
	for k, v := range span.Attributes {
		logEntry[k] = v
	}

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
