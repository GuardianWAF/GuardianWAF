package detection

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// =============================================================================
// detection.go: Process with tenant config, getExclusions
// =============================================================================

func TestCoverage_Process_TenantDetectionDisabled(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/search", "q='+OR+1=1--", "", "")
	ctx.TenantWAFConfig = &config.WAFConfig{
		Detection: config.DetectionConfig{
			Enabled: false,
		},
	}
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when tenant disabled detection, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings when tenant disabled, got %d", len(result.Findings))
	}
}

func TestCoverage_Process_TenantExclusions(t *testing.T) {
	cfg := defaultConfig()
	layer := NewLayer(cfg)

	ctx := makeContext("/api/tenant-path", "q='+UNION+SELECT+1,2,3--", "", "")
	ctx.TenantWAFConfig = &config.WAFConfig{
		Detection: config.DetectionConfig{
			Enabled: true,
			Exclusions: []config.ExclusionConfig{
				{Path: "/api/tenant-path", Detectors: []string{"sqli"}},
			},
		},
	}
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	for _, f := range result.Findings {
		if f.DetectorName == "sqli" {
			t.Error("expected sqli to be excluded by tenant exclusion")
		}
	}
}

func TestCoverage_Process_TenantEnabledDetection(t *testing.T) {
	cfg := defaultConfig()
	layer := NewLayer(cfg)

	ctx := makeContext("/search", "q='+UNION+SELECT+1,2,3--", "", "")
	ctx.TenantWAFConfig = &config.WAFConfig{
		Detection: config.DetectionConfig{
			Enabled: true,
		},
	}
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog with tenant enabled, got %v", result.Action)
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score with tenant enabled, got %d", result.Score)
	}
}

func TestCoverage_GetExclusions_NilTenant(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	result := layer.getExclusions(nil)
	if len(result) != 1 {
		t.Errorf("expected 1 exclusion, got %d", len(result))
	}
}

func TestCoverage_GetExclusions_TenantNoExclusions(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	tenantDet := &config.DetectionConfig{
		Enabled:    true,
		Exclusions: nil,
	}

	result := layer.getExclusions(tenantDet)
	if len(result) != 1 {
		t.Errorf("expected 1 exclusion (global only), got %d", len(result))
	}
}

func TestCoverage_GetExclusions_Merged(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Exclusions: []Exclusion{
			{PathPrefix: "/api/health", Detectors: []string{"sqli"}},
		},
	})

	tenantDet := &config.DetectionConfig{
		Enabled: true,
		Exclusions: []config.ExclusionConfig{
			{Path: "/api/tenant", Detectors: []string{"xss"}},
		},
	}

	result := layer.getExclusions(tenantDet)
	if len(result) != 2 {
		t.Errorf("expected 2 exclusions (global + tenant), got %d", len(result))
	}

	hasGlobal := false
	hasTenant := false
	for _, exc := range result {
		if exc.PathPrefix == "/api/health" {
			hasGlobal = true
		}
		if exc.PathPrefix == "/api/tenant" {
			hasTenant = true
		}
	}
	if !hasGlobal {
		t.Error("expected global exclusion to be present")
	}
	if !hasTenant {
		t.Error("expected tenant exclusion to be present")
	}
}

func TestCoverage_LFI_WindowsDriveAfterLetter(t *testing.T) {
	// "axc:" should NOT trigger drive detection because 'x' is preceded by 'a' (a letter)
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"lfi": {Enabled: true, Multiplier: 1.0},
		},
	})

	ctx := makeContext("/files/axc:\\windows", "", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "drive letter") {
			t.Error("expected no drive letter detection when preceded by letter")
		}
	}
}

func TestCoverage_LFI_WindowsDriveAtStart(t *testing.T) {
	// "c:" at position 0 should be detected
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"lfi": {Enabled: true, Multiplier: 1.0},
		},
	})

	ctx := makeContext("/files/c:\\windows\\system32", "", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	hasWindows := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "Windows") {
			hasWindows = true
		}
	}
	if !hasWindows {
		t.Error("expected Windows path detection for c:\\windows\\system32")
	}
}

func TestCoverage_SSRF_Process_CustomHeaders(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"ssrf": {Enabled: true, Multiplier: 1.0},
		},
	})

	ctx := makeContext("/proxy", "", "", "")
	ctx.Headers = map[string][]string{
		"X-Forwarded-Host": {"http://169.254.169.254/"},
	}
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Score <= 0 {
		t.Error("expected positive score for SSRF in X-Forwarded-Host header")
	}
}

func TestCoverage_SSRF_Process_UserAgent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"ssrf": {Enabled: true, Multiplier: 1.0},
		},
	})

	ctx := makeContext("/proxy", "", "", "")
	ctx.Headers = map[string][]string{
		"User-Agent": {"http://169.254.169.254/latest/meta-data/"},
	}
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	// User-Agent scores should be halved but still positive
	if result.Score <= 0 {
		t.Error("expected positive score for SSRF in User-Agent")
	}
}
