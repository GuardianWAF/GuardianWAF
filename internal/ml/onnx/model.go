// Package onnx provides lightweight ONNX model inference for real-time anomaly detection.
// This is a POC implementation - actual ONNX runtime integration will be added.
package onnx

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// Model represents a loaded ONNX model for inference.
type Model struct {
	mu sync.RWMutex

	name        string
	version     string
	inputShape  []int64
	outputShape []int64

	// For POC: simulated model weights
	// In production: onnxruntime session
	threshold float64
}

// Config for model loading and inference.
type Config struct {
	ModelPath string
	// Optimization level: 0=none, 1=basic, 2=extended, 3=all
	OptimizationLevel int
	// Number of threads for inference (0=auto)
	IntraOpNumThreads int
	// Enable CUDA (GPU acceleration)
	UseCUDA bool
}

// InferenceResult contains the model output.
type InferenceResult struct {
	AnomalyScore float64   // 0.0 to 1.0, higher = more anomalous
	IsAnomaly    bool      // true if score > threshold
	Confidence   float64   // model confidence
	Latency      time.Duration
}

// NewModel creates a new model instance (POC version).
func NewModel(name, version string) *Model {
	return &Model{
		name:      name,
		version:   version,
		threshold: 0.7, // Default threshold
		inputShape: []int64{1, 10}, // POC: 10 features
		outputShape: []int64{1, 1}, // POC: single score
	}
}

// Load loads the model from disk.
// POC: Simulated loading, actual implementation will use onnxruntime.
func (m *Model) Load(path string, cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// POC: Simulate loading delay
	time.Sleep(10 * time.Millisecond)

	// In production:
	// session, err := ort.NewAdvancedSession(path,
	//     []string{"input"}, []string{"output"},
	//     nil, cfg.OptimizationLevel, cfg.IntraOpNumThreads)

	return nil
}

// Predict runs inference on input features.
// POC: Uses simulated anomaly detection logic.
func (m *Model) Predict(ctx context.Context, features []float64) (*InferenceResult, error) {
	start := time.Now()

	m.mu.RLock()
	threshold := m.threshold
	m.mu.RUnlock()

	// POC: Simple anomaly detection using feature statistics
	// In production: actual ONNX model inference
	score := calculateAnomalyScore(features)

	result := &InferenceResult{
		AnomalyScore: score,
		IsAnomaly:    score > threshold,
		Confidence:   calculateConfidence(score, threshold),
		Latency:      time.Since(start),
	}

	return result, nil
}

// SetThreshold updates the anomaly threshold.
func (m *Model) SetThreshold(threshold float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threshold = threshold
}

// GetThreshold returns the current threshold.
func (m *Model) GetThreshold() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.threshold
}

// Info returns model information.
func (m *Model) Info() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]any{
		"name":         m.name,
		"version":      m.version,
		"input_shape":  m.inputShape,
		"output_shape": m.outputShape,
		"threshold":    m.threshold,
	}
}

// calculateAnomalyScore is a POC implementation.
// Uses statistical measures to detect anomalies.
func calculateAnomalyScore(features []float64) float64 {
	if len(features) == 0 {
		return 0.0
	}

	// Calculate mean and std dev
	mean := 0.0
	for _, f := range features {
		mean += f
	}
	mean /= float64(len(features))

	variance := 0.0
	for _, f := range features {
		diff := f - mean
		variance += diff * diff
	}
	stdDev := math.Sqrt(variance / float64(len(features)))

	// Calculate z-scores and find max deviation
	maxZScore := 0.0
	for _, f := range features {
		if stdDev > 0 {
			zScore := math.Abs(f-mean) / stdDev
			if zScore > maxZScore {
				maxZScore = zScore
			}
		}
	}

	// Normalize to 0-1 range (sigmoid-like)
	score := 1.0 / (1.0 + math.Exp(-maxZScore+2.0))
	return math.Min(1.0, math.Max(0.0, score))
}

// calculateConfidence returns confidence based on distance from threshold.
func calculateConfidence(score, threshold float64) float64 {
	distance := math.Abs(score - threshold)
	// Higher distance from threshold = higher confidence
	return math.Min(1.0, distance*2.0)
}

// Manager handles multiple models.
type Manager struct {
	mu     sync.RWMutex
	models map[string]*Model
}

// NewManager creates a new model manager.
func NewManager() *Manager {
	return &Manager{
		models: make(map[string]*Model),
	}
}

// Register adds a model to the manager.
func (m *Manager) Register(name string, model *Model) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.models[name] = model
}

// Get retrieves a model by name.
func (m *Manager) Get(name string) (*Model, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	model, ok := m.models[name]
	if !ok {
		return nil, fmt.Errorf("model %q not found", name)
	}
	return model, nil
}

// List returns all registered model names.
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.models))
	for name := range m.models {
		names = append(names, name)
	}
	return names
}

// Close cleans up all models.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// In production: release ONNX sessions
	m.models = make(map[string]*Model)
	return nil
}
