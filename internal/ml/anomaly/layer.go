// Package anomaly provides the anomaly detection WAF layer.
package anomaly

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/ml/features"
	"github.com/guardianwaf/guardianwaf/internal/ml/onnx"
)

// Layer is the WAF anomaly detection layer.
// Layer order: 475 (between API Security and Sanitizer)
type Layer struct {
	mu sync.RWMutex

	enabled   bool
	threshold float64

	extractor *features.Extractor
	model     *onnx.Model

	// Metrics
	requestsAnalyzed int64
	anomaliesDetected int64
	avgLatency       time.Duration
}

// Config for anomaly detection layer.
type Config struct {
	Enabled   bool    `json:"enabled" yaml:"enabled"`
	Threshold float64 `json:"threshold" yaml:"threshold"` // 0.0 to 1.0
	ModelPath string  `json:"model_path" yaml:"model_path"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:   true,
		Threshold: 0.7,
		ModelPath: "models/anomaly.onnx",
	}
}

// New creates a new anomaly detection layer.
func New(cfg Config) (*Layer, error) {
	l := &Layer{
		enabled:   cfg.Enabled,
		threshold: cfg.Threshold,
		extractor: features.NewExtractor(),
	}

	// Initialize model
	l.model = onnx.NewModel("anomaly_detector", "v1.0.0")
	l.model.SetThreshold(cfg.Threshold)

	// In production: load actual ONNX model
	// err := l.model.Load(cfg.ModelPath, onnx.Config{})

	return l, nil
}

// Analyze analyzes an HTTP request for anomalies.
func (l *Layer) Analyze(req *http.Request) (*Result, error) {
	if !l.Enabled() {
		return &Result{AnomalyScore: 0, IsAnomaly: false}, nil
	}

	start := time.Now()

	// Extract features
	featureVec := l.extractor.Extract(req)
	features := featureVec.ToSlice()

	// Run inference
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	inferenceResult, err := l.model.Predict(ctx, features)
	if err != nil {
		// Fail open - don't block on ML errors
		return &Result{
			AnomalyScore: 0,
			IsAnomaly:    false,
			Error:        err,
		}, nil
	}

	// Update metrics
	l.updateMetrics(inferenceResult, time.Since(start))

	return &Result{
		AnomalyScore: inferenceResult.AnomalyScore,
		IsAnomaly:    inferenceResult.IsAnomaly,
		Confidence:   inferenceResult.Confidence,
		Latency:      inferenceResult.Latency,
	}, nil
}

// AnalyzeWithBody analyzes request with body content.
func (l *Layer) AnalyzeWithBody(req *http.Request, body []byte) (*Result, error) {
	if !l.Enabled() {
		return &Result{AnomalyScore: 0, IsAnomaly: false}, nil
	}

	start := time.Now()

	// Extract features with body
	featureVec := l.extractor.ExtractWithBody(req, body)
	features := featureVec.ToSlice()

	// Run inference
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	inferenceResult, err := l.model.Predict(ctx, features)
	if err != nil {
		return &Result{
			AnomalyScore: 0,
			IsAnomaly:    false,
			Error:        err,
		}, nil
	}

	l.updateMetrics(inferenceResult, time.Since(start))

	return &Result{
		AnomalyScore: inferenceResult.AnomalyScore,
		IsAnomaly:    inferenceResult.IsAnomaly,
		Confidence:   inferenceResult.Confidence,
		Latency:      inferenceResult.Latency,
	}, nil
}

// Result contains the anomaly analysis result.
type Result struct {
	AnomalyScore float64       // 0.0 to 1.0
	IsAnomaly    bool          // true if anomaly detected
	Confidence   float64       // model confidence
	Latency      time.Duration // inference latency
	Error        error         // any error during analysis
}

// Score returns the score for WAF pipeline integration.
func (r *Result) Score() int {
	// Convert 0.0-1.0 to 0-100
	return int(r.AnomalyScore * 100)
}

// Enabled returns whether the layer is enabled.
func (l *Layer) Enabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.enabled
}

// SetEnabled enables or disables the layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// SetThreshold updates the anomaly threshold.
func (l *Layer) SetThreshold(threshold float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.threshold = threshold
	l.model.SetThreshold(threshold)
}

// GetThreshold returns the current threshold.
func (l *Layer) GetThreshold() float64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.threshold
}

// Stats returns layer statistics.
func (l *Layer) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return Stats{
		RequestsAnalyzed:  l.requestsAnalyzed,
		AnomaliesDetected: l.anomaliesDetected,
		AvgLatency:        l.avgLatency,
		Threshold:         l.threshold,
		Enabled:           l.enabled,
	}
}

// Stats contains layer statistics.
type Stats struct {
	RequestsAnalyzed  int64
	AnomaliesDetected int64
	AvgLatency        time.Duration
	Threshold         float64
	Enabled           bool
}

// updateMetrics updates internal metrics.
func (l *Layer) updateMetrics(result *onnx.InferenceResult, latency time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.requestsAnalyzed++
	if result.IsAnomaly {
		l.anomaliesDetected++
	}

	// Running average
	if l.avgLatency == 0 {
		l.avgLatency = latency
	} else {
		l.avgLatency = (l.avgLatency + latency) / 2
	}
}

// Close cleans up resources.
func (l *Layer) Close() error {
	return nil
}

// Stop stops the layer and cleans up resources.
func (l *Layer) Stop() {
	l.Close()
}

// Name returns the layer name for the WAF pipeline.
func (l *Layer) Name() string {
	return "ml-anomaly"
}

// Process implements the engine.Layer interface.
// It analyzes the request for anomalies and returns a LayerResult.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.Enabled() {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Convert engine context to http.Request for analysis
	req := ctx.Request
	if req == nil {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	result, err := l.Analyze(req)
	if err != nil || result.Error != nil {
		// Fail open - log but don't block on errors
		return engine.LayerResult{
			Action: engine.ActionPass,
			Score:  0,
		}
	}

	// Determine action based on anomaly score
	action := engine.ActionPass
	if result.IsAnomaly {
		// Score >= 90 is block, 50-89 is log/challenge
		if result.AnomalyScore >= 0.9 {
			action = engine.ActionBlock
		} else if result.AnomalyScore >= 0.5 {
			action = engine.ActionLog
		}
	}

	// Create finding if anomaly detected
	var findings []engine.Finding
	if result.IsAnomaly {
		findings = append(findings, engine.Finding{
			DetectorName: "ml-anomaly",
			Category:     "anomaly",
			Severity:     engine.SeverityHigh,
			Score:        result.Score(),
			Description:  "ML anomaly detected",
			Location:     "request",
			Confidence:   result.Confidence,
		})
		ctx.Accumulator.Add(&findings[0])
	}

	return engine.LayerResult{
		Action:   action,
		Score:    result.Score(),
		Findings: findings,
		Duration: result.Latency,
	}
}
