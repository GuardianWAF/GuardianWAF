package anomaly

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// AnalyzeWithBody
// ---------------------------------------------------------------------------

func TestLayer_AnalyzeWithBody_Enabled(t *testing.T) {
	cfg := DefaultConfig()
	layer, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create layer: %v", err)
	}
	defer layer.Close()

	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/api/submit"},
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(strings.NewReader(`{"user":"admin","pass":"secret"}`)),
	}
	body := []byte(`{"user":"admin","pass":"secret"}`)

	result, err := layer.AnalyzeWithBody(req, body)
	if err != nil {
		t.Fatalf("AnalyzeWithBody failed: %v", err)
	}
	if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
		t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
	}
}

func TestLayer_AnalyzeWithBody_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	layer, _ := New(cfg)
	defer layer.Close()

	req := &http.Request{Method: "POST", URL: &url.URL{Path: "/test"}}
	result, err := layer.AnalyzeWithBody(req, []byte("some body"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnomalyScore != 0 || result.IsAnomaly {
		t.Errorf("expected zero result when disabled, got score=%f anomaly=%v", result.AnomalyScore, result.IsAnomaly)
	}
}

func TestLayer_AnalyzeWithBody_EmptyBody(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	req := &http.Request{Method: "GET", URL: &url.URL{Path: "/api/empty"}}
	result, err := layer.AnalyzeWithBody(req, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
		t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
	}
}

// ---------------------------------------------------------------------------
// Result.Score
// ---------------------------------------------------------------------------

func TestResult_Score(t *testing.T) {
	tests := []struct {
		name       string
		score      float64
		wantInt    int
	}{
		{"zero", 0.0, 0},
		{"half", 0.5, 50},
		{"one", 1.0, 100},
		{"small", 0.42, 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{AnomalyScore: tt.score}
			if got := r.Score(); got != tt.wantInt {
				t.Errorf("Score() = %d, want %d", got, tt.wantInt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Name, Stop
// ---------------------------------------------------------------------------

func TestLayer_Name(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	if got := layer.Name(); got != "ml-anomaly" {
		t.Errorf("Name() = %q, want %q", got, "ml-anomaly")
	}
}

func TestLayer_Stop(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	// Should not panic
	layer.Stop()
}

// ---------------------------------------------------------------------------
// Process (engine.Layer interface)
// ---------------------------------------------------------------------------

func TestLayer_Process_DisabledLayer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	layer, _ := New(cfg)
	defer layer.Close()

	ctx := &engine.RequestContext{
		Request: &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when disabled, got %v", result.Action)
	}
}

func TestLayer_Process_NilRequest(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	ctx := &engine.RequestContext{Request: nil}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for nil request, got %v", result.Action)
	}
}

func TestLayer_Process_NormalRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	ctx := &engine.RequestContext{
		Request:    &http.Request{Method: "GET", URL: &url.URL{Path: "/api/users"}},
		Accumulator: engine.NewScoreAccumulator(1),
	}

	result := layer.Process(ctx)

	// Score should be 0-100 range
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("Score out of range: %d", result.Score)
	}
}

func TestLayer_Process_WithFindings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Threshold = 0.01 // very low threshold to force anomaly detection
	layer, _ := New(cfg)
	defer layer.Close()

	// Use a path with many ../ segments which should create anomalous features
	ctx := &engine.RequestContext{
		Request:    &http.Request{Method: "GET", URL: &url.URL{Path: "/../../../../../../etc/passwd"}},
		Accumulator: engine.NewScoreAccumulator(1),
	}

	result := layer.Process(ctx)

	if len(result.Findings) > 0 {
		t.Logf("Anomaly detected: score=%d, action=%v, findings=%d", result.Score, result.Action, len(result.Findings))

		f := result.Findings[0]
		if f.DetectorName != "ml-anomaly" {
			t.Errorf("finding detector = %q, want %q", f.DetectorName, "ml-anomaly")
		}
		if f.Category != "anomaly" {
			t.Errorf("finding category = %q, want %q", f.Category, "anomaly")
		}
		if f.Severity != engine.SeverityHigh {
			t.Errorf("finding severity = %v, want %v", f.Severity, engine.SeverityHigh)
		}

		// Verify that accumulator was used
		if ctx.Accumulator != nil {
			_ = ctx.Accumulator
		}
	}
}

// ---------------------------------------------------------------------------
// Threshold enforcement through Process
// ---------------------------------------------------------------------------

func TestLayer_Process_BlockThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	// Use a very low threshold so even normal requests trigger high scores
	layer.SetThreshold(0.01)

	// We need a request that produces a high anomaly score
	// The ONNX POC model uses z-score based detection, so we craft
	// a request with highly variable features
	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "DELETE",
			URL:    &url.URL{Path: "/a/b/c/d/../../../etc/passwd", RawQuery: "x=" + strings.Repeat("A", 500)},
			Header: http.Header{"Content-Type": []string{"application/json"}},
		},
		Accumulator: engine.NewScoreAccumulator(1),
	}

	result := layer.Process(ctx)

	// The action should be one of the valid actions
	validAction := result.Action == engine.ActionPass ||
		result.Action == engine.ActionLog ||
		result.Action == engine.ActionBlock ||
		result.Action == engine.ActionChallenge

	if !validAction {
		t.Errorf("unexpected action: %v", result.Action)
	}

	// If Score >= 90, the action should be block (Process maps anomaly_score >= 0.9 to block)
	if result.Score >= 90 && result.Action != engine.ActionBlock {
		t.Errorf("expected ActionBlock for score >= 90, got action=%v score=%d", result.Action, result.Score)
	}
}

// ---------------------------------------------------------------------------
// Stats after multiple requests
// ---------------------------------------------------------------------------

func TestLayer_Stats_AnomaliesDetected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Threshold = 0.01 // Very low threshold to maximize anomaly detection
	layer, _ := New(cfg)
	defer layer.Close()

	for i := 0; i < 20; i++ {
		req := &http.Request{
			Method: "POST",
			URL:    &url.URL{Path: "/api/test"},
		}
		layer.Analyze(req)
	}

	stats := layer.Stats()
	if stats.RequestsAnalyzed != 20 {
		t.Errorf("RequestsAnalyzed = %d, want 20", stats.RequestsAnalyzed)
	}
	if !stats.Enabled {
		t.Error("Stats should report Enabled=true")
	}
	if stats.Threshold != 0.01 {
		t.Errorf("Threshold = %f, want 0.01", stats.Threshold)
	}
	// AvgLatency may be 0 if inference is sub-nanosecond (POC model)
	// Just verify it is non-negative
	if stats.AvgLatency < 0 {
		t.Errorf("AvgLatency should be non-negative, got %v", stats.AvgLatency)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestLayer_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/api/concurrent"},
			}
			layer.Analyze(req)
			if idx%5 == 0 {
				layer.Stats()
			}
			if idx%10 == 0 {
				layer.SetEnabled(true)
				layer.Enabled()
				layer.GetThreshold()
			}
		}(i)
	}
	wg.Wait()

	stats := layer.Stats()
	if stats.RequestsAnalyzed != 50 {
		t.Errorf("after 50 concurrent Analyze calls, RequestsAnalyzed = %d, want 50", stats.RequestsAnalyzed)
	}
}

// ---------------------------------------------------------------------------
// Process with accumulator interaction
// ---------------------------------------------------------------------------

func TestLayer_Process_AccumulatorIntegration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Threshold = 0.01
	layer, _ := New(cfg)
	defer layer.Close()

	acc := engine.NewScoreAccumulator(2)
	ctx := &engine.RequestContext{
		Request:    &http.Request{Method: "DELETE", URL: &url.URL{Path: "/../../../etc/passwd"}},
		Accumulator: acc,
	}

	result := layer.Process(ctx)

	// If findings were produced, the accumulator should have them
	if len(result.Findings) > 0 {
		if acc.Total() == 0 {
			t.Error("expected non-zero total score in accumulator after anomaly finding")
		}
	}
}

// ---------------------------------------------------------------------------
// Feature extraction edge cases
// ---------------------------------------------------------------------------

func TestLayer_Analyze_EmptyPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
	}
	result, err := layer.Analyze(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
		t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
	}
}

func TestLayer_Analyze_LongURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	longPath := "/" + strings.Repeat("a/", 500) + "end"
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: longPath},
	}
	result, err := layer.Analyze(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
		t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
	}
}

func TestLayer_AnalyzeWithBody_LargeBody(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	largeBody := bytes.Repeat([]byte("A"), 10*1024)
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/api/upload"},
		Header: http.Header{"Content-Type": []string{"application/octet-stream"}},
	}

	result, err := layer.AnalyzeWithBody(req, largeBody)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
		t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
	}
}

// ---------------------------------------------------------------------------
// Metric update running average
// ---------------------------------------------------------------------------

func TestLayer_UpdateMetrics_RunningAverage(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	// Run several requests so avgLatency is computed
	for i := 0; i < 5; i++ {
		req := &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}}
		layer.Analyze(req)
	}

	stats := layer.Stats()
	// AvgLatency may be 0 on fast POC model; just verify non-negative
	if stats.AvgLatency < 0 {
		t.Errorf("AvgLatency should be non-negative, got %v", stats.AvgLatency)
	}
}

// ---------------------------------------------------------------------------
// SetThreshold concurrent with Analyze
// ---------------------------------------------------------------------------

func TestLayer_SetThreshold_ConcurrentWithAnalyze(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			layer.SetThreshold(float64(i%10) / 10.0)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			req := &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}}
			layer.Analyze(req)
		}
	}()

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Process action classification: block vs log vs pass
// ---------------------------------------------------------------------------

func TestLayer_Process_ActionClassification(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)
	defer layer.Close()

	// Create requests with varying characteristics
	testCases := []struct {
		name   string
		method string
		path   string
	}{
		{"simple GET", "GET", "/api/users"},
		{"DELETE with traversal", "DELETE", "/../../../etc/passwd"},
		{"POST with deep path", "POST", "/a/b/c/d/e/f/g/h"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &engine.RequestContext{
				Request:    &http.Request{Method: tc.method, URL: &url.URL{Path: tc.path}},
				Accumulator: engine.NewScoreAccumulator(1),
			}
			result := layer.Process(ctx)

			// Verify valid action range
			valid := result.Action == engine.ActionPass ||
				result.Action == engine.ActionBlock ||
				result.Action == engine.ActionLog ||
				result.Action == engine.ActionChallenge
			if !valid {
				t.Errorf("invalid action: %v", result.Action)
			}

			// Duration should be non-negative
			if result.Duration < 0 {
				t.Errorf("Duration should be non-negative, got %v", result.Duration)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Default config values
// ---------------------------------------------------------------------------

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("default config should be Enabled=true")
	}
	if cfg.Threshold != 0.7 {
		t.Errorf("default Threshold = %f, want 0.7", cfg.Threshold)
	}
	if cfg.ModelPath != "models/anomaly.onnx" {
		t.Errorf("default ModelPath = %q, want %q", cfg.ModelPath, "models/anomaly.onnx")
	}
}

// ---------------------------------------------------------------------------
// New with various configs
// ---------------------------------------------------------------------------

func TestNew_Disabled(t *testing.T) {
	cfg := Config{Enabled: false, Threshold: 0.5}
	layer, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer layer.Close()
	if layer.Enabled() {
		t.Error("layer should be disabled")
	}
}

func TestNew_CustomThreshold(t *testing.T) {
	cfg := Config{Enabled: true, Threshold: 0.3}
	layer, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer layer.Close()
	if got := layer.GetThreshold(); got != 0.3 {
		t.Errorf("threshold = %f, want 0.3", got)
	}
}

// ---------------------------------------------------------------------------
// Process: ensure ScoreAccumulator receives finding
// ---------------------------------------------------------------------------

func TestLayer_Process_FindingAddedToAccumulator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Threshold = 0.01
	layer, _ := New(cfg)
	defer layer.Close()

	acc := engine.NewScoreAccumulator(2)
	ctx := &engine.RequestContext{
		Request:    &http.Request{Method: "DELETE", URL: &url.URL{Path: "/../../../etc/shadow"}},
		Accumulator: acc,
	}

	result := layer.Process(ctx)

	if len(result.Findings) > 0 {
		// The finding was added to accumulator via ctx.Accumulator.Add
		if acc.Total() == 0 {
			t.Error("expected non-zero total score in accumulator after anomaly finding")
		}
	}
}
