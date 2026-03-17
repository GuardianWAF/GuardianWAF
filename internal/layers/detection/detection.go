package detection

import (
	"strings"

	"github.com/ersinkoc/guardianwaf/internal/engine"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/cmdi"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/lfi"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/sqli"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/ssrf"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/xss"
	"github.com/ersinkoc/guardianwaf/internal/layers/detection/xxe"
)

// DetectorConfig holds the configuration for a single detector.
type DetectorConfig struct {
	Enabled    bool
	Multiplier float64
}

// Config holds the configuration for the detection layer.
type Config struct {
	Enabled    bool
	Detectors  map[string]DetectorConfig // keyed by: sqli, xss, lfi, cmdi, xxe, ssrf
	Exclusions []Exclusion
}

// Exclusion defines a path-based detection exclusion.
type Exclusion struct {
	PathPrefix string
	Detectors  []string // detector names to skip
	Reason     string
}

// Layer implements engine.Layer and runs all attack detectors.
type Layer struct {
	config    Config
	detectors []engine.Detector
}

// NewLayer creates a new detection layer with the given configuration.
func NewLayer(cfg Config) *Layer {
	l := &Layer{config: cfg}

	// Initialize detectors based on config
	if dc, ok := cfg.Detectors["sqli"]; ok {
		l.detectors = append(l.detectors, sqli.NewDetector(dc.Enabled, dc.Multiplier))
	}
	if dc, ok := cfg.Detectors["xss"]; ok {
		l.detectors = append(l.detectors, xss.NewDetector(dc.Enabled, dc.Multiplier))
	}
	if dc, ok := cfg.Detectors["lfi"]; ok {
		l.detectors = append(l.detectors, lfi.NewDetector(dc.Enabled, dc.Multiplier))
	}
	if dc, ok := cfg.Detectors["cmdi"]; ok {
		l.detectors = append(l.detectors, cmdi.NewDetector(dc.Enabled, dc.Multiplier))
	}
	if dc, ok := cfg.Detectors["xxe"]; ok {
		l.detectors = append(l.detectors, xxe.NewDetector(dc.Enabled, dc.Multiplier))
	}
	if dc, ok := cfg.Detectors["ssrf"]; ok {
		l.detectors = append(l.detectors, ssrf.NewDetector(dc.Enabled, dc.Multiplier))
	}

	return l
}

func (l *Layer) Name() string { return "detection" }

func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding
	totalScore := 0

	for _, det := range l.detectors {
		// Check exclusions
		if l.isExcluded(det.DetectorName(), ctx.Path) {
			continue
		}

		result := det.Process(ctx)
		allFindings = append(allFindings, result.Findings...)
		totalScore += result.Score
	}

	action := engine.ActionPass
	if len(allFindings) > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: allFindings,
		Score:    totalScore,
	}
}

func (l *Layer) isExcluded(detectorName, path string) bool {
	for _, exc := range l.config.Exclusions {
		if strings.HasPrefix(path, exc.PathPrefix) {
			for _, d := range exc.Detectors {
				if d == detectorName {
					return true
				}
			}
		}
	}
	return false
}
