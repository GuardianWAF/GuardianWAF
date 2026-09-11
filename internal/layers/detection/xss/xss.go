package xss

import (
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements the engine.Detector interface for XSS detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new XSS detector.
// enabled controls whether the detector is active.
// multiplier scales all finding scores (e.g., based on paranoia level).
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "xss-detector" }

func (d *Detector) Order() int { return 0 }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "xss" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"script-tag",
		"event-handler",
		"javascript-protocol",
		"data-uri",
		"css-expression",
		"dom-manipulation",
		"template-injection",
		"encoding-evasion",
		"svg-vector",
	}
}

// Process scans the request context for XSS patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var allFindings []engine.Finding

	// Scan BOTH the raw and the sanitizer-normalized form of every input: the
	// normalizer decodes evasion encodings, but it can also destroy bytes the
	// raw form preserves (e.g. a tab collapsed to a space inside
	// "jav\tascript:"). Mirrors the sibling detectors and their fail-open
	// guard for a disabled Sanitizer. Identical forms are detected once —
	// input-level dedup, so multi-tag scores are unaffected.
	scanInputs := func(location string, forms ...string) {
		seen := make(map[string]bool, len(forms))
		for _, form := range forms {
			if form == "" || seen[form] {
				continue
			}
			seen[form] = true
			allFindings = append(allFindings, Detect(form, location)...)
		}
	}

	// 1. URL path
	scanInputs("path", ctx.Path, ctx.NormalizedPath)

	// 2. Query parameters (each value separately, both forms)
	queryForms := make([]string, 0, 8)
	for _, values := range ctx.QueryParams {
		queryForms = append(queryForms, values...)
	}
	for _, values := range ctx.NormalizedQuery {
		queryForms = append(queryForms, values...)
	}
	scanInputs("query", queryForms...)

	// 3. Body (if present)
	scanInputs("body", ctx.BodyString, ctx.NormalizedBody)

	// 4. Cookie values
	for _, vals := range ctx.Cookies {
		for _, v := range vals {
			allFindings = append(allFindings, Detect(v, "cookie")...)
		}
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
	engine.ApplyMultiplier(allFindings, d.multiplier)

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
		Duration: time.Since(start),
	}
}
