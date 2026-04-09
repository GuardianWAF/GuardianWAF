package xxe

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements the engine.Detector interface for XXE (XML External Entity) detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new XXE detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "xxe-detector" }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "xxe" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"doctype-entity",
		"external-entity",
		"parameter-entity",
		"xi-include",
		"ssi-include",
	}
}

// Process scans the request context for XXE patterns.
// Only triggered when Content-Type contains "xml", "soap", or "rss".
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Only scan XML-like content types, but also scan if body looks like XML
	// (some backends parse XML regardless of Content-Type)
	if !isXMLContentType(ctx.ContentType) {
		body := strings.TrimSpace(ctx.BodyString)
		if !strings.HasPrefix(body, "<?xml") && !strings.HasPrefix(body, "<!DOCTYPE") &&
			!strings.HasPrefix(strings.ToLower(body), "<!doctype") {
			return engine.LayerResult{Action: engine.ActionPass}
		}
	}

	var allFindings []engine.Finding

	// Primarily scan body (where XML payloads live)
	if ctx.NormalizedBody != "" {
		allFindings = append(allFindings, Detect(ctx.NormalizedBody, "body")...)
	}

	// Also check raw body string
	if ctx.BodyString != "" && ctx.BodyString != ctx.NormalizedBody {
		allFindings = append(allFindings, Detect(ctx.BodyString, "body")...)
	}

	// Check query parameters for XML content
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			allFindings = append(allFindings, Detect(v, "query")...)
		}
	}

	// Apply multiplier
	for i := range allFindings {
		allFindings[i].Score = int(float64(allFindings[i].Score) * d.multiplier)
	}

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

// isXMLContentType returns true if the Content-Type suggests XML content.
func isXMLContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "xml") ||
		strings.Contains(lower, "soap") ||
		strings.Contains(lower, "rss")
}

// Detect scans a single input string for XXE patterns.
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}

	var findings []engine.Finding
	lower := strings.ToLower(input)

	// 1. DOCTYPE detection
	hasDoctype := checkDoctype(lower, location, &findings)

	// 2. ENTITY detection
	hasEntity := checkEntity(lower, location, &findings)

	// 3. SYSTEM keyword with protocols
	checkSystemProtocols(lower, location, &findings)

	// 4. Parameter entity (<!ENTITY %)
	checkParameterEntity(lower, location, &findings)

	// 5. Combined DOCTYPE + ENTITY (higher confidence)
	if hasDoctype && hasEntity {
		findings = append(findings, makeFinding(85, engine.SeverityCritical,
			"DOCTYPE with ENTITY declaration detected (likely XXE attempt)",
			extractContext(lower, "<!entity"), location, 0.90))
	}

	// 6. SSI include
	checkSSIInclude(lower, location, &findings)

	// 7. XInclude
	checkXInclude(lower, location, &findings)

	// 8. CDATA with suspicious content
	checkSuspiciousCDATA(lower, location, &findings)

	return findings
}

// makeFinding creates a Finding with standard XXE fields.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "xxe",
		Category:     "xxe",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// checkDoctype detects <!DOCTYPE declarations. Returns true if found.
func checkDoctype(lower, location string, findings *[]engine.Finding) bool {
	if strings.Contains(lower, "<!doctype") {
		*findings = append(*findings, makeFinding(25, engine.SeverityLow,
			"DOCTYPE declaration detected",
			extractContext(lower, "<!doctype"), location, 0.40))
		return true
	}
	return false
}

// checkEntity detects <!ENTITY declarations. Returns true if found.
func checkEntity(lower, location string, findings *[]engine.Finding) bool {
	if strings.Contains(lower, "<!entity") {
		*findings = append(*findings, makeFinding(65, engine.SeverityHigh,
			"ENTITY declaration detected",
			extractContext(lower, "<!entity"), location, 0.80))
		return true
	}
	return false
}

// checkSystemProtocols detects SYSTEM keyword with various protocol handlers.
func checkSystemProtocols(lower, location string, findings *[]engine.Finding) {
	if !strings.Contains(lower, "system") {
		return
	}

	protocols := []struct {
		pattern string
		score   int
		desc    string
		sev     engine.Severity
	}{
		{`system "file://`, 95, "XXE with file:// protocol detected", engine.SeverityCritical},
		{`system 'file://`, 95, "XXE with file:// protocol detected", engine.SeverityCritical},
		{`system "http://`, 75, "XXE with http:// protocol detected (SSRF risk)", engine.SeverityHigh},
		{`system 'http://`, 75, "XXE with http:// protocol detected (SSRF risk)", engine.SeverityHigh},
		{`system "https://`, 75, "XXE with https:// protocol detected (SSRF risk)", engine.SeverityHigh},
		{`system 'https://`, 75, "XXE with https:// protocol detected (SSRF risk)", engine.SeverityHigh},
		{`system "expect://`, 95, "XXE with expect:// protocol detected (RCE risk)", engine.SeverityCritical},
		{`system 'expect://`, 95, "XXE with expect:// protocol detected (RCE risk)", engine.SeverityCritical},
		{`system "php://`, 90, "XXE with php:// protocol detected", engine.SeverityCritical},
		{`system 'php://`, 90, "XXE with php:// protocol detected", engine.SeverityCritical},
	}

	for _, p := range protocols {
		if strings.Contains(lower, p.pattern) {
			*findings = append(*findings, makeFinding(p.score, p.sev,
				p.desc, extractContext(lower, p.pattern), location, 0.95))
		}
	}
}

// checkParameterEntity detects parameter entities (<!ENTITY % ...).
func checkParameterEntity(lower, location string, findings *[]engine.Finding) {
	// Look for <!ENTITY followed by %
	idx := strings.Index(lower, "<!entity")
	if idx < 0 {
		return
	}
	rest := lower[idx+8:] // after "<!entity"
	rest = strings.TrimSpace(rest)
	if rest != "" && rest[0] == '%' {
		*findings = append(*findings, makeFinding(80, engine.SeverityCritical,
			"Parameter entity declaration detected (<!ENTITY %)",
			extractContext(lower, "<!entity"), location, 0.90))
	}
}

// checkSSIInclude detects Server-Side Include directives in XML.
func checkSSIInclude(lower, location string, findings *[]engine.Finding) {
	if strings.Contains(lower, "<!--#include") {
		*findings = append(*findings, makeFinding(65, engine.SeverityHigh,
			"SSI include directive detected in XML",
			extractContext(lower, "<!--#include"), location, 0.80))
	}
}

// checkXInclude detects XInclude elements.
func checkXInclude(lower, location string, findings *[]engine.Finding) {
	if strings.Contains(lower, "<xi:include") {
		*findings = append(*findings, makeFinding(70, engine.SeverityHigh,
			"XInclude element detected",
			extractContext(lower, "<xi:include"), location, 0.80))
	}
}

// checkSuspiciousCDATA detects CDATA sections with suspicious content.
func checkSuspiciousCDATA(lower, location string, findings *[]engine.Finding) {
	cdataStart := strings.Index(lower, "<![cdata[")
	if cdataStart < 0 {
		return
	}
	cdataEnd := strings.Index(lower[cdataStart:], "]]>")
	if cdataEnd < 0 {
		return
	}

	content := lower[cdataStart+9 : cdataStart+cdataEnd]

	// Check for suspicious content inside CDATA
	suspicious := []string{
		"<!entity", "<!doctype", "system", "file://", "http://",
		"/etc/passwd", "/etc/shadow", "expect://", "php://",
	}

	for _, s := range suspicious {
		if strings.Contains(content, s) {
			*findings = append(*findings, makeFinding(40, engine.SeverityMedium,
				"CDATA section with suspicious content: "+s,
				extractContext(lower, "<![cdata["), location, 0.60))
			return // One finding per CDATA is enough
		}
	}
}

// extractContext extracts a context window around the matched pattern.
func extractContext(input, pattern string) string {
	idx := strings.Index(input, pattern)
	if idx < 0 {
		return input[:min(len(input), 100)]
	}
	start := max(idx-20, 0)
	end := min(idx+len(pattern)+40, len(input))
	result := input[start:end]
	if len(result) > 200 {
		return result[:197] + "..."
	}
	return result
}
