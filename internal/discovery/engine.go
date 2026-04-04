package discovery

import (
	"net/http"
	"time"
)

// Engine is a wrapper around Manager that provides the interface expected by v040 integrator.
type Engine struct {
	manager *Manager
	config  EngineConfig
}

// EngineConfig for the discovery engine.
type EngineConfig struct {
	CaptureMode      string
	RingBufferSize   int
	MinSamples       int
	ClusterThreshold float64
	ExportPath       string
	ExportFormat     string
	AutoExport       bool
	ExportInterval   time.Duration
}

// NewEngine creates a new discovery engine.
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	managerCfg := Config{
		Enabled: true,
		Collection: CollectionConfig{
			BufferSize:  cfg.RingBufferSize,
			SampleRate:  1.0,
			FlushPeriod: cfg.ExportInterval,
		},
		Analysis: AnalysisConfig{
			MinClusterSize:      cfg.MinSamples,
			SimilarityThreshold: cfg.ClusterThreshold,
			AutoLearning:        true,
		},
		Storage: StorageConfig{
			Path:      cfg.ExportPath,
			Retention: 30 * 24 * time.Hour,
		},
	}

	manager, err := NewManager(managerCfg)
	if err != nil {
		return nil, err
	}

	return &Engine{
		manager: manager,
		config:  *cfg,
	}, nil
}

// RecordRequest records a request for API discovery.
func (e *Engine) RecordRequest(r *http.Request, statusCode int) {
	if e.manager == nil {
		return
	}

	// Create a minimal response for recording
	resp := &http.Response{
		StatusCode: statusCode,
	}

	e.manager.Record(r, resp, 0)
}

// Stop stops the discovery engine.
func (e *Engine) Stop() {
	if e.manager != nil {
		e.manager.SetEnabled(false)
	}
}

// ExportToOpenAPI exports the discovered API as OpenAPI spec.
func (e *Engine) ExportToOpenAPI() *OpenAPISpec {
	if e.manager == nil {
		return nil
	}
	return e.manager.ExportOpenAPI()
}

// GetStats returns discovery statistics.
type DiscoveryStats struct {
	EndpointsDiscovered int
	RequestsAnalyzed    int64
	LastExport          time.Time
	IsLearning          bool
}

// GetStats returns the current discovery statistics.
func (e *Engine) GetStats() DiscoveryStats {
	if e.manager == nil {
		return DiscoveryStats{}
	}

	stats := e.manager.Stats()
	return DiscoveryStats{
		EndpointsDiscovered: stats.EndpointsDiscovered,
		RequestsAnalyzed:    stats.RequestsCollected,
		LastExport:          stats.LastAnalysis,
		IsLearning:          stats.Enabled,
	}
}
