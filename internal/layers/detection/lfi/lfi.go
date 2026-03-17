package lfi

import (
	"strings"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Detector implements the engine.Detector interface for path traversal / LFI detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new LFI detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "lfi-detector" }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "lfi" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"path-traversal",
		"sensitive-path",
		"encoded-traversal",
		"null-byte",
		"wrapper-scheme",
	}
}

// Process scans the request context for path traversal / LFI patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding

	// 1. URL path
	allFindings = append(allFindings, Detect(ctx.NormalizedPath, "path")...)

	// 2. Query parameters
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			allFindings = append(allFindings, Detect(v, "query")...)
		}
	}

	// 3. Body
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

// Detect scans a single input string for path traversal / LFI patterns.
func Detect(input string, location string) []engine.Finding {
	if len(input) == 0 {
		return nil
	}

	var findings []engine.Finding
	lower := strings.ToLower(input)

	// 1. Encoded traversal patterns (check before decoding)
	findings = append(findings, checkEncodedTraversal(lower, location)...)

	// 2. Basic traversal: ../
	findings = append(findings, checkBasicTraversal(lower, location)...)

	// 3. Sensitive file paths
	findings = append(findings, checkSensitivePaths(lower, location)...)

	// 4. Windows paths
	findings = append(findings, checkWindowsPaths(lower, location)...)

	// 5. Wrapper/scheme patterns
	findings = append(findings, checkWrapperSchemes(lower, location)...)

	// 6. Bypass patterns (....// , ....\\)
	findings = append(findings, checkBypassPatterns(lower, location)...)

	return findings
}

// makeFinding creates a Finding with standard LFI fields.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "lfi",
		Category:     "lfi",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// checkBasicTraversal detects ../ patterns and counts traversal depth.
func checkBasicTraversal(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// Count ../ or ..\ occurrences
	count := 0
	for i := 0; i < len(lower)-2; i++ {
		if lower[i] == '.' && lower[i+1] == '.' && (lower[i+2] == '/' || lower[i+2] == '\\') {
			count++
			i += 2 // skip past the ../
		}
	}

	if count == 0 {
		return nil
	}

	if count >= 3 {
		// Deep traversal (3+ levels)
		findings = append(findings, makeFinding(65, engine.SeverityHigh,
			"Deep path traversal detected (3+ levels)",
			extractContext(lower, ".."), location, 0.85))
	} else {
		// Basic traversal
		findings = append(findings, makeFinding(30, engine.SeverityMedium,
			"Path traversal pattern detected (../)",
			extractContext(lower, ".."), location, 0.60))
	}

	return findings
}

// checkEncodedTraversal detects URL-encoded traversal patterns.
func checkEncodedTraversal(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// ..%2f or ..%2F (URL-encoded /)
	if strings.Contains(lower, "..%2f") || strings.Contains(lower, "..%5c") {
		findings = append(findings, makeFinding(75, engine.SeverityHigh,
			"URL-encoded path traversal detected",
			extractContext(lower, "..%"), location, 0.85))
	}

	// Double-encoded: ..%252f
	if strings.Contains(lower, "..%252f") || strings.Contains(lower, "..%255c") {
		findings = append(findings, makeFinding(75, engine.SeverityHigh,
			"Double URL-encoded path traversal detected",
			extractContext(lower, "..%25"), location, 0.90))
	}

	// Overlong UTF-8: ..%c0%af
	if strings.Contains(lower, "..%c0%af") || strings.Contains(lower, "..%c1%9c") {
		findings = append(findings, makeFinding(95, engine.SeverityCritical,
			"Overlong UTF-8 encoded path traversal detected",
			extractContext(lower, "..%c0"), location, 0.95))
	}

	// %0a newline injection in paths
	if strings.Contains(lower, "%00") {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"Null byte injection in path detected",
			extractContext(lower, "%00"), location, 0.85))
	}

	return findings
}

// checkSensitivePaths detects access to sensitive system files.
func checkSensitivePaths(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// Linux sensitive paths (high priority)
	criticalPaths := []struct {
		path  string
		score int
		desc  string
	}{
		{"/etc/passwd", 90, "Access to /etc/passwd detected"},
		{"/etc/shadow", 95, "Access to /etc/shadow detected"},
		{"/etc/master.passwd", 95, "Access to /etc/master.passwd detected"},
	}
	for _, cp := range criticalPaths {
		if strings.Contains(lower, cp.path) {
			findings = append(findings, makeFinding(cp.score, engine.SeverityCritical,
				cp.desc, extractContext(lower, cp.path), location, 0.95))
		}
	}

	// /proc/self/ paths
	if strings.Contains(lower, "/proc/self/") {
		findings = append(findings, makeFinding(85, engine.SeverityCritical,
			"Access to /proc/self/ detected",
			extractContext(lower, "/proc/self/"), location, 0.90))
	}

	// /var/log/ paths
	if strings.Contains(lower, "/var/log/") {
		findings = append(findings, makeFinding(60, engine.SeverityHigh,
			"Access to /var/log/ detected",
			extractContext(lower, "/var/log/"), location, 0.75))
	}

	// Check all sensitive paths from the embedded list
	for _, sp := range linuxSensitivePaths {
		spLower := strings.ToLower(sp)
		// Skip the ones already handled above to avoid double-counting
		if spLower == "/etc/passwd" || spLower == "/etc/shadow" || spLower == "/etc/master.passwd" {
			continue
		}
		if strings.HasPrefix(spLower, "/proc/self/") {
			continue
		}
		if strings.HasPrefix(spLower, "/var/log/") {
			continue
		}
		if strings.Contains(lower, spLower) {
			findings = append(findings, makeFinding(55, engine.SeverityHigh,
				"Access to sensitive Linux path: "+sp,
				extractContext(lower, spLower), location, 0.75))
		}
	}

	for _, sp := range macosSensitivePaths {
		spLower := strings.ToLower(sp)
		if strings.Contains(lower, spLower) {
			findings = append(findings, makeFinding(55, engine.SeverityHigh,
				"Access to sensitive macOS path: "+sp,
				extractContext(lower, spLower), location, 0.70))
		}
	}

	return findings
}

// checkWindowsPaths detects Windows path traversal and sensitive file access.
func checkWindowsPaths(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// C:\ or C:/ drive letter — only at start of string or after a boundary character
	for i := 0; i < len(lower)-2; i++ {
		if lower[i] >= 'a' && lower[i] <= 'z' && lower[i+1] == ':' && (lower[i+2] == '\\' || lower[i+2] == '/') {
			// Must be at start or preceded by a non-letter (boundary)
			if i == 0 || !isLetter(lower[i-1]) {
				findings = append(findings, makeFinding(55, engine.SeverityHigh,
					"Windows drive letter path detected",
					extractContext(lower, string(lower[i:i+3])), location, 0.75))
				break
			}
		}
	}

	// \windows\system32 or /windows/system32
	winSys := []string{
		"\\windows\\system32", "/windows/system32",
		"\\winnt\\system32", "/winnt/system32",
	}
	for _, ws := range winSys {
		if strings.Contains(lower, ws) {
			findings = append(findings, makeFinding(80, engine.SeverityCritical,
				"Windows system directory access detected",
				extractContext(lower, ws), location, 0.90))
			break
		}
	}

	// Check Windows sensitive paths
	for _, sp := range windowsSensitivePaths {
		spLower := strings.ToLower(sp)
		if strings.Contains(lower, spLower) {
			findings = append(findings, makeFinding(65, engine.SeverityHigh,
				"Access to sensitive Windows path: "+sp,
				extractContext(lower, spLower), location, 0.80))
			break // Only report the first match to avoid noise
		}
	}

	return findings
}

// checkWrapperSchemes detects PHP wrappers and file:// scheme.
func checkWrapperSchemes(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	schemes := []struct {
		prefix string
		score  int
		desc   string
		sev    engine.Severity
	}{
		{"file://", 65, "file:// wrapper scheme detected", engine.SeverityHigh},
		{"php://filter", 85, "php://filter wrapper detected", engine.SeverityCritical},
		{"php://input", 85, "php://input wrapper detected", engine.SeverityCritical},
		{"php://", 80, "php:// wrapper detected", engine.SeverityCritical},
		{"expect://", 90, "expect:// wrapper detected (RCE risk)", engine.SeverityCritical},
		{"data://", 65, "data:// wrapper detected", engine.SeverityHigh},
		{"zip://", 65, "zip:// wrapper detected", engine.SeverityHigh},
		{"phar://", 75, "phar:// wrapper detected", engine.SeverityCritical},
	}

	for _, s := range schemes {
		if strings.Contains(lower, s.prefix) {
			// For generic php:// avoid double-matching with php://filter and php://input
			if s.prefix == "php://" {
				if strings.Contains(lower, "php://filter") || strings.Contains(lower, "php://input") {
					continue
				}
			}
			findings = append(findings, makeFinding(s.score, s.sev,
				s.desc, extractContext(lower, s.prefix), location, 0.85))
		}
	}

	return findings
}

// checkBypassPatterns detects various traversal bypass techniques.
func checkBypassPatterns(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// ....// or ....\\ bypass
	bypasses := []string{"....//", "....\\\\", "..../", "....\\"}
	for _, bp := range bypasses {
		if strings.Contains(lower, bp) {
			findings = append(findings, makeFinding(70, engine.SeverityHigh,
				"Path traversal bypass pattern detected",
				extractContext(lower, bp), location, 0.80))
			break
		}
	}

	return findings
}

// isLetter returns true if the byte is an ASCII letter.
func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// extractContext extracts a context window around the matched pattern.
func extractContext(input, pattern string) string {
	idx := strings.Index(input, pattern)
	if idx < 0 {
		if len(input) > 100 {
			return input[:100]
		}
		return input
	}
	start := idx - 20
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 20
	if end > len(input) {
		end = len(input)
	}
	result := input[start:end]
	if len(result) > 200 {
		result = result[:197] + "..."
	}
	return result
}
