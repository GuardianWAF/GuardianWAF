package replay

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer provides request recording as a WAF layer.
type Layer struct {
	recorder *Recorder
	config   *LayerConfig
}

// LayerConfig for replay layer.
type LayerConfig struct {
	Enabled  bool `yaml:"enabled"`
	Recorder *Config
}

// NewLayer creates a new replay layer.
func NewLayer(cfg *LayerConfig) (*Layer, error) {
	if cfg == nil {
		cfg = &LayerConfig{
			Enabled:  false,
			Recorder: DefaultConfig(),
		}
	}

	if !cfg.Enabled {
		return &Layer{config: cfg}, nil
	}

	recorder, err := NewRecorder(cfg.Recorder)
	if err != nil {
		return nil, err
	}

	return &Layer{
		recorder: recorder,
		config:   cfg,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "replay-recorder"
}

// Order returns the layer order.
func (l *Layer) Order() int {
	return 145 // After cache (140), before detection (150)
}

// Process implements the layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled || l.recorder == nil {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Store request for async recording
	// Actual recording happens in response phase via RecordResponse
	return engine.LayerResult{Action: engine.ActionPass}
}

// RecordResponse captures the complete request/response cycle.
func (l *Layer) RecordResponse(req *http.Request, resp *http.Response, duration time.Duration) error {
	if !l.config.Enabled || l.recorder == nil {
		return nil
	}

	return l.recorder.Record(req, resp, duration)
}

// GetRecorder returns the internal recorder.
func (l *Layer) GetRecorder() *Recorder {
	return l.recorder
}

// GetStats returns recording statistics.
func (l *Layer) GetStats() map[string]any {
	if l.recorder == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	return l.recorder.GetStats()
}

// Close closes the layer.
func (l *Layer) Close() error {
	if l.recorder != nil {
		return l.recorder.Close()
	}
	return nil
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)

// Manager coordinates recording and replay.
type Manager struct {
	recorder *Recorder
	replayer *Replayer
	config   *ManagerConfig
}

// ManagerConfig combines recorder and replayer configs.
type ManagerConfig struct {
	Recording *Config         `yaml:"recording"`
	Replay    *ReplayerConfig `yaml:"replay"`
}

// NewManager creates a new replay manager.
func NewManager(cfg *ManagerConfig) (*Manager, error) {
	if cfg == nil {
		cfg = &ManagerConfig{
			Recording: DefaultConfig(),
			Replay:    DefaultReplayerConfig(),
		}
	}

	m := &Manager{
		config: cfg,
	}

	// Initialize recorder if enabled
	if cfg.Recording != nil && cfg.Recording.Enabled {
		recorder, err := NewRecorder(cfg.Recording)
		if err != nil {
			return nil, err
		}
		m.recorder = recorder
	}

	// Initialize replayer
	if cfg.Replay != nil {
		m.replayer = NewReplayer(cfg.Replay)
	}

	return m, nil
}

// Record captures a request/response.
func (m *Manager) Record(req *http.Request, resp *http.Response, duration time.Duration) error {
	if m.recorder == nil {
		return nil
	}

	return m.recorder.Record(req, resp, duration)
}

// Replay starts a replay session.
func (m *Manager) Replay(ctx context.Context, file string, filter ReplayFilter) (*ReplayStats, error) {
	if m.replayer == nil {
		return nil, fmt.Errorf("replayer not initialized")
	}

	storagePath := ""
	if m.config.Recording != nil {
		storagePath = m.config.Recording.StoragePath
	}

	return m.replayer.ReplayRecording(ctx, storagePath, file, filter)
}

// ListRecordings returns available recordings.
func (m *Manager) ListRecordings() ([]string, error) {
	if m.recorder == nil {
		return nil, fmt.Errorf("recorder not initialized")
	}

	return m.recorder.ListRecordings()
}

// IsRecordingEnabled returns if recording is active.
func (m *Manager) IsRecordingEnabled() bool {
	return m.recorder != nil && m.config.Recording.Enabled
}

// IsReplayEnabled returns if replay is enabled.
func (m *Manager) IsReplayEnabled() bool {
	return m.replayer != nil && m.config.Replay.Enabled
}

// GetRecorderStats returns recording stats.
func (m *Manager) GetRecorderStats() map[string]any {
	if m.recorder == nil {
		return map[string]any{"enabled": false}
	}
	return m.recorder.GetStats()
}

// GetReplayStats returns replay stats.
func (m *Manager) GetReplayStats() ReplayStats {
	if m.replayer == nil {
		return ReplayStats{}
	}
	return m.replayer.GetStats()
}

// Close closes the manager.
func (m *Manager) Close() error {
	if m.recorder != nil {
		return m.recorder.Close()
	}
	return nil
}
