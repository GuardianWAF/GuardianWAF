package sqli

import "github.com/ersinkoc/guardianwaf/internal/engine"

// Detector implements the engine.Detector interface for SQL injection detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new SQL injection detector.
// enabled controls whether the detector is active.
// multiplier scales all finding scores (e.g., based on paranoia level).
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "sqli-detector" }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "sqli" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"union-select",
		"tautology",
		"stacked-query",
		"time-based",
		"file-access",
		"comment-evasion",
	}
}

// Process scans the request context for SQL injection patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding

	// 1. URL path
	allFindings = append(allFindings, Detect(ctx.NormalizedPath, "path")...)

	// 2. Query parameters (each value separately)
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			allFindings = append(allFindings, Detect(v, "query")...)
		}
	}

	// 3. Body (if present)
	if ctx.NormalizedBody != "" {
		allFindings = append(allFindings, Detect(ctx.NormalizedBody, "body")...)
	}

	// 4. Cookie values
	for _, v := range ctx.Cookies {
		allFindings = append(allFindings, Detect(v, "cookie")...)
	}

	// 5. Referer header
	if refs, ok := ctx.Headers["Referer"]; ok {
		for _, v := range refs {
			allFindings = append(allFindings, Detect(v, "header")...)
		}
	}

	// 6. User-Agent (lower priority — scores halved)
	if uas, ok := ctx.Headers["User-Agent"]; ok {
		for _, v := range uas {
			uaFindings := Detect(v, "header")
			for i := range uaFindings {
				uaFindings[i].Score = int(float64(uaFindings[i].Score) * 0.5)
			}
			allFindings = append(allFindings, uaFindings...)
		}
	}

	// Apply multiplier to all findings
	for i := range allFindings {
		allFindings[i].Score = int(float64(allFindings[i].Score) * d.multiplier)
	}

	// Determine action and total score
	action := engine.ActionPass
	totalScore := 0
	for _, f := range allFindings {
		totalScore += f.Score
	}
	if totalScore > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: allFindings,
		Score:    totalScore,
	}
}
