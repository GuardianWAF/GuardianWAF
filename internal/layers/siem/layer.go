package siem

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer wraps the SIEM exporter as an engine.Layer.
// It runs at Order 1 (first) — purely passive event forwarding.
// Process() does nothing per-request; events are forwarded via the event bus.
type Layer struct {
	exporter *Exporter
	config   *Config
}

// NewLayer creates a new SIEM layer.
func NewLayer(cfg *Config) (*Layer, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	exporter := NewExporter(cfg)
	if exporter == nil {
		return nil, nil
	}

	return &Layer{
		exporter: exporter,
		config:   cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "siem"
}

// Order returns the layer execution order (runs first).
func (l *Layer) Order() int {
	return 1
}

// Process is a no-op for SIEM layer.
// Events are forwarded via Start() subscribing to the event bus.
// This satisfies the engine.Layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	return engine.LayerResult{Action: engine.ActionPass}
}

// Exporter returns the underlying SIEM exporter.
func (l *Layer) Exporter() *Exporter {
	return l.exporter
}

// Stop stops the SIEM exporter.
func (l *Layer) Stop() {
	if l.exporter != nil {
		l.exporter.Stop()
	}
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)
