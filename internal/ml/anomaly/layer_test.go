package anomaly

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ml/features"
)

func TestLayer_Analyze(t *testing.T) {
	cfg := DefaultConfig()
	layer, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create layer: %v", err)
	}
	defer layer.Close()

	tests := []struct {
		name     string
		path     string
		method   string
		wantScore bool // whether we expect a score > 0
	}{
		{
			name:     "normal request",
			path:     "/api/users",
			method:   "GET",
			wantScore: true,
		},
		{
			name:     "suspicious path",
			path:     "/api/users/../../../etc/passwd",
			method:   "GET",
			wantScore: true,
		},
		{
			name:     "normal POST",
			path:     "/api/users",
			method:   "POST",
			wantScore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: tt.method,
				URL:    &url.URL{Path: tt.path},
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := layer.Analyze(req)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			if result.Error != nil {
				t.Logf("Analysis had error: %v", result.Error)
			}

			// Score should be between 0 and 1
			if result.AnomalyScore < 0 || result.AnomalyScore > 1 {
				t.Errorf("AnomalyScore out of range: %f", result.AnomalyScore)
			}

			// Latency should be reasonable (< 10ms for POC)
			if result.Latency > 10*time.Millisecond {
				t.Errorf("Latency too high: %v", result.Latency)
			}

			t.Logf("Score: %.4f, IsAnomaly: %v, Latency: %v",
				result.AnomalyScore, result.IsAnomaly, result.Latency)
		})
	}
}

func TestLayer_Enabled(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	// Should be enabled by default
	if !layer.Enabled() {
		t.Error("Layer should be enabled by default")
	}

	// Disable
	layer.SetEnabled(false)
	if layer.Enabled() {
		t.Error("Layer should be disabled")
	}

	// Test that Analyze returns empty result when disabled
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/test"},
	}

	result, _ := layer.Analyze(req)
	if result.AnomalyScore != 0 {
		t.Error("Should return 0 score when disabled")
	}
}

func TestLayer_Threshold(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	// Test default threshold
	if layer.GetThreshold() != 0.7 {
		t.Errorf("Default threshold should be 0.7, got %f", layer.GetThreshold())
	}

	// Update threshold
	layer.SetThreshold(0.5)
	if layer.GetThreshold() != 0.5 {
		t.Errorf("Threshold should be 0.5, got %f", layer.GetThreshold())
	}
}

func TestLayer_Stats(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)
	defer layer.Close()

	// Make some requests
	for i := 0; i < 10; i++ {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/test"},
		}
		layer.Analyze(req)
	}

	// Check stats
	stats := layer.Stats()
	if stats.RequestsAnalyzed != 10 {
		t.Errorf("Expected 10 requests analyzed, got %d", stats.RequestsAnalyzed)
	}
}

func TestFeatureExtractor(t *testing.T) {
	extractor := features.NewExtractor()

	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:     "/api/users/123",
			RawQuery: "name=test&age=25",
		},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"User-Agent":   []string{"Mozilla/5.0"},
		},
		ContentLength: 100,
	}

	fv := extractor.Extract(req)

	// Verify feature extraction
	if fv.PathSegmentCount == 0 {
		t.Error("Path segment count should be > 0")
	}

	if fv.QueryParamCount != 2 {
		t.Errorf("Expected 2 query params, got %f", fv.QueryParamCount)
	}

	if fv.HeaderCount != 2 {
		t.Errorf("Expected 2 headers, got %f", fv.HeaderCount)
	}

	if fv.MethodScore == 0 {
		t.Error("POST method should have risk score > 0")
	}

	// Check feature vector length
	features := fv.ToSlice()
	if len(features) == 0 {
		t.Error("Feature vector should not be empty")
	}

	t.Logf("Features: %v", features)
}
