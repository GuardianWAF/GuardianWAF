package detection

import (
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/cmdi"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/lfi"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/sqli"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/ssrf"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/xss"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/xxe"
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
	mu        sync.RWMutex
	config    Config
	detectors []engine.Detector
}

// NewLayer creates a new detection layer with the given configuration.
func NewLayer(cfg *Config) *Layer {
	l := &Layer{config: *cfg}

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

// AddExclusion adds a detection exclusion dynamically at runtime.
func (l *Layer) AddExclusion(exc Exclusion) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Replace if same path prefix exists
	for i, e := range l.config.Exclusions {
		if e.PathPrefix == exc.PathPrefix {
			l.config.Exclusions[i] = exc
			return
		}
	}
	l.config.Exclusions = append(l.config.Exclusions, exc)
}

// RemoveExclusion removes a detection exclusion by path prefix. Returns true if found.
func (l *Layer) RemoveExclusion(pathPrefix string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.config.Exclusions {
		if e.PathPrefix == pathPrefix {
			l.config.Exclusions = append(l.config.Exclusions[:i], l.config.Exclusions[i+1:]...)
			return true
		}
	}
	return false
}

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
	l.mu.RLock()
	exclusions := make([]Exclusion, len(l.config.Exclusions))
	copy(exclusions, l.config.Exclusions)
	l.mu.RUnlock()

	for _, exc := range exclusions {
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
