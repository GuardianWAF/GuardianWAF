package detection

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- AddExclusion ---

func TestLayer_AddExclusion(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	exc := Exclusion{PathPrefix: "/api/health", Detectors: []string{"sqli"}, Reason: "false positive"}
	layer.AddExclusion(exc)

	if len(layer.config.Exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(layer.config.Exclusions))
	}
	if layer.config.Exclusions[0].PathPrefix != "/api/health" {
		t.Errorf("expected /api/health, got %q", layer.config.Exclusions[0].PathPrefix)
	}
}

func TestLayer_AddExclusion_ReplaceExisting(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	// Add same path prefix — should replace
	layer.AddExclusion(Exclusion{PathPrefix: "/api/health", Detectors: []string{"xss"}, Reason: "updated"})

	if len(layer.config.Exclusions) != 1 {
		t.Fatalf("expected 1 exclusion (replaced), got %d", len(layer.config.Exclusions))
	}
	if layer.config.Exclusions[0].Reason != "updated" {
		t.Errorf("expected updated reason, got %q", layer.config.Exclusions[0].Reason)
	}
	if layer.config.Exclusions[0].Detectors[0] != "xss" {
		t.Errorf("expected xss detector, got %v", layer.config.Exclusions[0].Detectors)
	}
}

func TestLayer_AddExclusion_MultipleDistinct(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})

	layer.AddExclusion(Exclusion{PathPrefix: "/a"})
	layer.AddExclusion(Exclusion{PathPrefix: "/b"})

	if len(layer.config.Exclusions) != 2 {
		t.Errorf("expected 2 exclusions, got %d", len(layer.config.Exclusions))
	}
}

// --- RemoveExclusion ---

func TestLayer_RemoveExclusion(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health"},
			{PathPrefix: "/api/metrics"},
		},
	})

	removed := layer.RemoveExclusion("/api/health")
	if !removed {
		t.Error("expected removal to succeed")
	}
	if len(layer.config.Exclusions) != 1 {
		t.Errorf("expected 1 exclusion, got %d", len(layer.config.Exclusions))
	}
	if layer.config.Exclusions[0].PathPrefix != "/api/metrics" {
		t.Errorf("expected /api/metrics to remain, got %q", layer.config.Exclusions[0].PathPrefix)
	}
}

func TestLayer_RemoveExclusion_NotFound(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:    true,
		Exclusions: []Exclusion{{PathPrefix: "/api/health"}},
	})

	removed := layer.RemoveExclusion("/nonexistent")
	if removed {
		t.Error("expected removal to fail for nonexistent prefix")
	}
	if len(layer.config.Exclusions) != 1 {
		t.Error("exclusion should not be removed")
	}
}

// --- Process with exclusions ---

func TestLayer_Process_Excluded(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"sqli": {Enabled: true},
		},
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	ctx := &engine.RequestContext{
		Path:           "/api/health",
		NormalizedBody: "' OR 1=1 --",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for excluded path, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 for excluded path, got %d", result.Score)
	}
}

func TestLayer_Process_NotExcludedPath(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"sqli": {Enabled: true},
		},
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	ctx := &engine.RequestContext{
		Path:           "/api/login",
		NormalizedBody: "1' UNION SELECT username, password FROM users--",
	}

	result := layer.Process(ctx)
	// The detection layer accumulates findings and score from individual detectors.
	// Even if score is 0 (individual finding scores may vary), having findings means detection worked.
	if len(result.Findings) == 0 {
		t.Error("expected findings for non-excluded path with SQLi payload")
	}
}
