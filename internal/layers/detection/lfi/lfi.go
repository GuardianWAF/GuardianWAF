package lfi

import (
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
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

func (d *Detector) Order() int { return 0 }

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
	start := time.Now()
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var allFindings []engine.Finding

	// Scan THREE views of every input:
	//
	//  1. raw — carries literal "../" and single-encoded "%2e%2e%2f".
	//  2. sanitizer-normalized — decodes evasion encodings, but its
	//     CanonicalizePath step *resolves* "../" segments away, which destroys
	//     the traversal signal this detector relies on.
	//  3. recursively URL-decoded but NOT canonicalized — the only view that
	//     exposes multiply-encoded traversal such as "%252e%252e%252f", which is
	//     invisible in (1) as literal "%25" runs and already collapsed in (2).
	//
	// Identical strings are scanned once (dedup) so unchanged inputs aren't
	// double-counted. Mirrors xss/xxe fail-open guard for a disabled Sanitizer.
	seen := make(map[string]struct{})
	scanOnly := func(v, location string) {
		if v == "" {
			return
		}
		key := location + "\x00" + v
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		allFindings = append(allFindings, Detect(v, location)...)
	}
	scan := func(v, location string) {
		scanOnly(v, location)
		if decoded := sanitizer.DecodeURLRecursive(v); decoded != v {
			scanOnly(decoded, location)
		}
	}

	// 1. URL path (raw + normalized)
	scan(ctx.Path, "path")
	scan(ctx.NormalizedPath, "path")

	// 2. Query parameters (raw + normalized)
	for _, values := range ctx.QueryParams {
		for _, v := range values {
			scan(v, "query")
		}
	}
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			scan(v, "query")
		}
	}

	// 3. Body (raw + normalized)
	scan(ctx.BodyString, "body")
	scan(ctx.NormalizedBody, "body")

	// 4. Cookie values
	for _, vals := range ctx.Cookies {
		for _, v := range vals {
			scan(v, "cookie")
		}
	}

	// 5. Referer header (raw + normalized)
	if refs, ok := ctx.Headers["Referer"]; ok {
		for _, v := range refs {
			scan(v, "header")
		}
	}
	if refs, ok := ctx.NormalizedHeaders["Referer"]; ok {
		for _, v := range refs {
			scan(v, "header")
		}
	}

	// Apply multiplier
	engine.ApplyMultiplier(allFindings, d.multiplier)

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

// Detect scans a single input string for path traversal / LFI patterns.
func Detect(input, location string) []engine.Finding {
	if input == "" {
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
func checkBasicTraversal(lower, location string) []engine.Finding {
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
func checkEncodedTraversal(lower, location string) []engine.Finding {
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
// Uses a pre-built trie for O(k) lookup instead of O(n*m) linear scan.
// Each input character causes exactly one array lookup (O(1)) per trie level.
func checkSensitivePaths(lower, location string) []engine.Finding {
	return sensitiveTrie.checkWithTrie(lower, location)
}

// checkWindowsPaths detects Windows path traversal and sensitive file access.
func checkWindowsPaths(lower, location string) []engine.Finding {
	var findings []engine.Finding

	// C:\ or C:/ drive letter — only at start of string or after a non-letter
	// boundary character (avoids false positives like "abc:C:\foo").
	for i := 0; i < len(lower)-2; i++ {
		if lower[i] >= 'a' && lower[i] <= 'z' && lower[i+1] == ':' &&
			(lower[i+2] == '\\' || lower[i+2] == '/') {
			atStart := i == 0
			atBoundary := !atStart &&
				((lower[i-1] < 'a' || lower[i-1] > 'z') &&
					(lower[i-1] < 'A' || lower[i-1] > 'Z'))
			if atStart || atBoundary {
				findings = append(findings, makeFinding(55, engine.SeverityHigh,
					"Windows drive letter path detected",
					extractContext(lower, lower[i:i+3]), location, 0.75))
				break
			}
		}
	}

	// Windows 8.3 short-name bypass (e.g. PROGRA~1 for "Program Files").
	//
	// This used to fire on a bare '~' anywhere in the input, which is far too
	// broad: '~' is ordinary in URLs and version strings, so /~alice/photo.jpg
	// and ?v=~1.2.3 both scored 60 against a block threshold of 50. A real 8.3
	// name is a truncated basename followed by a tilde and an ordinal, so
	// require that actual shape.
	if idx := indexShortName(lower); idx >= 0 {
		findings = append(findings, makeFinding(60, engine.SeverityHigh,
			"Windows short name format detected (path traversal attempt)",
			extractContext(lower, lower[idx:min(idx+8, len(lower))]), location, 0.75))
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

	// Windows sensitive paths are now handled by checkSensitivePaths via trie.
	// Removing the duplicate linear scan here eliminates O(n) overhead per call.

	return findings
}

// checkWrapperSchemes detects PHP wrappers and file:// scheme.
func checkWrapperSchemes(lower, location string) []engine.Finding {
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
func checkBypassPatterns(lower, location string) []engine.Finding {
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

// extractContext extracts a context window around the matched pattern.
func extractContext(input, pattern string) string {
	idx := strings.Index(input, pattern)
	if idx < 0 {
		if len(input) > 100 {
			return safeTruncate(input, 100)
		}
		return input
	}
	start := max(idx-20, 0)
	end := min(idx+len(pattern)+20, len(input))
	result := input[start:end]
	if len(result) > 200 {
		return safeTruncate(result, 197) + "..."
	}
	return result
}

// safeTruncate truncates a string to at most maxBytes bytes without splitting
// a multi-byte UTF-8 rune. If truncation occurs, it returns the valid prefix.
func safeTruncate(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && s[maxBytes]&0xC0 == 0x80 {
		maxBytes--
	}
	return s[:maxBytes]
}

// indexShortName reports the start offset of a Windows 8.3 short name such as
// "progra~1", or -1 if the input contains none. The shape is 1-6 filename
// characters, a tilde, then a 1-2 digit ordinal — and the run must not be part
// of a longer word, so "a~1b" and a bare "~1.2.3" do not qualify.
func indexShortName(lower string) int {
	for i := 0; i < len(lower); i++ {
		if lower[i] != '~' {
			continue
		}
		// An ordinal must follow the tilde.
		j := i + 1
		digits := 0
		for j < len(lower) && lower[j] >= '0' && lower[j] <= '9' && digits < 2 {
			j++
			digits++
		}
		if digits == 0 {
			continue
		}
		// The ordinal must end the name segment, not run into more letters.
		if j < len(lower) && isShortNameChar(lower[j]) {
			continue
		}
		// A truncated basename of 1-6 characters must precede the tilde.
		start := i
		for start > 0 && isShortNameChar(lower[start-1]) && i-(start-1) <= 6 {
			start--
		}
		if start == i {
			continue // nothing before the tilde, e.g. "/~1" or "~1.2.3"
		}
		// The basename must start at a path or token boundary.
		if start > 0 && isShortNameChar(lower[start-1]) {
			continue // longer than 6 chars, so not a truncation
		}
		return start
	}
	return -1
}

// isShortNameChar reports whether c can appear in an 8.3 basename.
func isShortNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
