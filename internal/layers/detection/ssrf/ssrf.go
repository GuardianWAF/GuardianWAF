package ssrf

import (
	"strings"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Detector implements the engine.Detector interface for SSRF detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new SSRF detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "ssrf-detector" }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "ssrf" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"localhost-access",
		"private-ip",
		"metadata-endpoint",
		"decimal-ip",
		"octal-ip",
		"url-credential",
	}
}

// Process scans the request context for SSRF patterns.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding

	// 1. URL path
	allFindings = append(allFindings, Detect(ctx.NormalizedPath, "path")...)

	// 2. Query parameters (most common SSRF vector)
	for _, values := range ctx.NormalizedQuery {
		for _, v := range values {
			allFindings = append(allFindings, Detect(v, "query")...)
		}
	}

	// 3. Body (JSON string values, form data)
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

// Detect scans a single input string for SSRF patterns.
func Detect(input string, location string) []engine.Finding {
	if len(input) == 0 {
		return nil
	}

	var findings []engine.Finding
	lower := strings.ToLower(input)

	// 1. Localhost patterns
	findings = append(findings, checkLocalhostPatterns(lower, location)...)

	// 2. Cloud metadata endpoints
	findings = append(findings, checkMetadataEndpoints(lower, location)...)

	// 3. Private IP ranges
	findings = append(findings, checkPrivateIPs(lower, location)...)

	// 4. Decimal/Octal/Hex IP encoding
	findings = append(findings, checkEncodedIPs(lower, location)...)

	// 5. URL with @ (credential injection / redirect)
	findings = append(findings, checkURLCredential(lower, location)...)

	return findings
}

// makeFinding creates a Finding with standard SSRF fields.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "ssrf",
		Category:     "ssrf",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// checkLocalhostPatterns detects localhost and loopback access.
func checkLocalhostPatterns(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	patterns := []struct {
		pattern string
		score   int
		desc    string
	}{
		{"http://localhost", 80, "HTTP request to localhost detected"},
		{"https://localhost", 80, "HTTPS request to localhost detected"},
		{"http://127.0.0.1", 80, "HTTP request to 127.0.0.1 detected"},
		{"https://127.0.0.1", 80, "HTTPS request to 127.0.0.1 detected"},
		{"http://0.0.0.0", 85, "HTTP request to 0.0.0.0 detected"},
		{"https://0.0.0.0", 85, "HTTPS request to 0.0.0.0 detected"},
		{"http://[::1]", 85, "HTTP request to IPv6 loopback [::1] detected"},
		{"https://[::1]", 85, "HTTPS request to IPv6 loopback [::1] detected"},
		{"http://[0:0:0:0:0:0:0:1]", 85, "HTTP request to IPv6 loopback detected"},
		{"http://0177.0.0.1", 85, "HTTP request to octal loopback 0177.0.0.1 detected"},
	}

	for _, p := range patterns {
		if strings.Contains(lower, p.pattern) {
			findings = append(findings, makeFinding(p.score, engine.SeverityCritical,
				p.desc, extractContext(lower, p.pattern), location, 0.90))
		}
	}

	return findings
}

// checkMetadataEndpoints detects cloud metadata endpoint access.
func checkMetadataEndpoints(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	endpoints := []struct {
		pattern string
		score   int
		desc    string
	}{
		{"169.254.169.254", 95, "AWS/GCP metadata endpoint detected (169.254.169.254)"},
		{"metadata.google.internal", 95, "GCP metadata endpoint detected (metadata.google.internal)"},
		{"100.100.100.200", 90, "Alibaba Cloud metadata endpoint detected (100.100.100.200)"},
		{"metadata.azure", 90, "Azure metadata endpoint detected"},
		{"169.254.170.2", 90, "AWS ECS metadata endpoint detected"},
	}

	for _, e := range endpoints {
		if strings.Contains(lower, e.pattern) {
			findings = append(findings, makeFinding(e.score, engine.SeverityCritical,
				e.desc, extractContext(lower, e.pattern), location, 0.95))
		}
	}

	return findings
}

// checkPrivateIPs detects access to private IP ranges in URL-like contexts.
func checkPrivateIPs(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// Extract URL-like patterns and check for private IPs
	urlPrefixes := []string{"http://", "https://", "//"}

	for _, prefix := range urlPrefixes {
		idx := 0
		for {
			pos := strings.Index(lower[idx:], prefix)
			if pos < 0 {
				break
			}
			pos += idx
			hostStart := pos + len(prefix)
			if hostStart >= len(lower) {
				break
			}

			// Extract host portion (up to /, :, ?, #, or end)
			hostEnd := hostStart
			for hostEnd < len(lower) {
				c := lower[hostEnd]
				if c == '/' || c == ':' || c == '?' || c == '#' || c == ' ' {
					break
				}
				hostEnd++
			}
			host := lower[hostStart:hostEnd]

			// Check if host is a private IP
			ip := ParseIPv4(host)
			if ip != nil && IsPrivateIP(ip) {
				// Skip localhost/0.0.0.0 (handled by checkLocalhostPatterns)
				if !IsLoopback(ip) && !(ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
					findings = append(findings, makeFinding(65, engine.SeverityHigh,
						"HTTP request to private IP range detected: "+host,
						extractContext(lower, host), location, 0.80))
				}
			}

			idx = hostEnd
		}
	}

	return findings
}

// checkEncodedIPs detects decimal, octal, and hex encoded IPs in URLs.
func checkEncodedIPs(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	// Look for URL-like patterns with potential encoded IPs
	urlPrefixes := []string{"http://", "https://"}
	for _, prefix := range urlPrefixes {
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			continue
		}
		hostStart := idx + len(prefix)
		if hostStart >= len(lower) {
			continue
		}

		// Extract host
		hostEnd := hostStart
		for hostEnd < len(lower) {
			c := lower[hostEnd]
			if c == '/' || c == ':' || c == '?' || c == '#' || c == ' ' {
				break
			}
			hostEnd++
		}
		host := lower[hostStart:hostEnd]

		// Check for decimal IP (single large number like 2130706433)
		decIP := ParseDecimalIP(host)
		if decIP != nil {
			findings = append(findings, makeFinding(85, engine.SeverityCritical,
				"Decimal encoded IP address detected: "+host,
				extractContext(lower, host), location, 0.90))
			if IsPrivateIP(decIP) || IsLoopback(decIP) {
				findings = append(findings, makeFinding(85, engine.SeverityCritical,
					"Decimal encoded IP resolves to private/loopback range",
					extractContext(lower, host), location, 0.95))
			}
		}

		// Check for octal IP (0177.0.0.1)
		octalIP := ParseOctalIP(host)
		if octalIP != nil {
			findings = append(findings, makeFinding(85, engine.SeverityCritical,
				"Octal encoded IP address detected: "+host,
				extractContext(lower, host), location, 0.90))
		}

		// Check for hex IP (0x7f.0x0.0x0.0x1)
		hexIP := ParseHexIP(host)
		if hexIP != nil {
			findings = append(findings, makeFinding(85, engine.SeverityCritical,
				"Hex encoded IP address detected: "+host,
				extractContext(lower, host), location, 0.90))
		}
	}

	return findings
}

// checkURLCredential detects URLs with @ sign (credential/redirect injection).
func checkURLCredential(lower string, location string) []engine.Finding {
	var findings []engine.Finding

	urlPrefixes := []string{"http://", "https://"}
	for _, prefix := range urlPrefixes {
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			continue
		}
		afterScheme := lower[idx+len(prefix):]

		// Find the first / after the authority
		slashIdx := strings.Index(afterScheme, "/")
		authority := afterScheme
		if slashIdx >= 0 {
			authority = afterScheme[:slashIdx]
		}

		// Check for @ in authority part
		if strings.Contains(authority, "@") {
			findings = append(findings, makeFinding(70, engine.SeverityHigh,
				"URL with @ sign detected (possible credential injection or redirect)",
				extractContext(lower, "@"), location, 0.75))
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
