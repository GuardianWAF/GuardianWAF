package xss

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detect is the main entry point for XSS detection on a single input string.
// It returns all findings with their scores. The location parameter indicates
// where in the request this input was found (query, body, header, cookie, path).
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}

	findings := make([]engine.Finding, 0, 8)

	// Pre-process: remove null bytes for analysis (but keep original for evidence)
	cleaned := removeNullBytes(input)
	lower := strings.ToLower(cleaned)

	// Check for encoded < variants and add bonus if found
	hasEncoded := detectEncodedLT(input)

	// Decode common encodings (\x3c, %3c, &#60;, etc.) and also analyze decoded form
	decoded := decodeCommonEncodings(cleaned)
	decodedLower := strings.ToLower(decoded)
	// Use the decoded version for pattern matching if it differs (evasion detection)
	analysisStr := cleaned
	analysisLower := lower
	if decoded != cleaned {
		analysisStr = decoded
		analysisLower = decodedLower
	}

	// --- Pattern-based checks on the analysis input ---

	// 1. <script>...</script> (full script block) — score 95
	if containsScriptBlock(analysisLower) {
		findings = append(findings, makeFinding(95, engine.SeverityCritical,
			"Script block detected: <script>...</script>",
			truncateMatch(analysisStr), location, 0.98))
	} else if strings.Contains(analysisLower, "<script") {
		// 2. <script (tag open only) — score 90
		findings = append(findings, makeFinding(90, engine.SeverityCritical,
			"Script tag detected: <script",
			truncateMatch(analysisStr), location, 0.95))
	}

	// 3. Scan HTML tags for event handlers and dangerous patterns
	// Fast path: skip tag scanning if no < present
	var tags []htmlTag
	if strings.ContainsRune(analysisStr, '<') {
		tags = scanTags(analysisStr)
	}
	for _, tag := range tags {
		// SVG vectors: <svg/onload=...> — score 85
		if tag.Name == "svg" {
			if evtName, ok := hasEventHandler(tag.Attributes); ok {
				findings = append(findings, makeFinding(85, engine.SeverityCritical,
					"SVG vector with event handler: "+evtName,
					truncateMatch(tag.RawMatch), location, 0.95))
				continue
			}
		}

		// <img/svg/body/div + on[event]= — score 85
		if tag.Name == "img" || tag.Name == "svg" || tag.Name == "body" || tag.Name == "div" {
			if evtName, ok := hasEventHandler(tag.Attributes); ok {
				findings = append(findings, makeFinding(85, engine.SeverityCritical,
					"Dangerous tag with event handler: <"+tag.Name+" "+evtName+"=...>",
					truncateMatch(tag.RawMatch), location, 0.95))
				continue
			}
		}

		// Any other tag with event handler — score 70
		if evtName, ok := hasEventHandler(tag.Attributes); ok {
			findings = append(findings, makeFinding(70, engine.SeverityHigh,
				"Event handler attribute detected: "+evtName,
				truncateMatch(tag.RawMatch), location, 0.85))
		}

		// javascript: or data:text/html in attribute values
		if attrName, protocol, ok := hasJavaScriptProtocol(tag.Attributes); ok {
			score := 80
			desc := "JavaScript protocol in attribute: " + attrName
			if protocol == "data:text/html" {
				score = 75
				desc = "Data URI with text/html in attribute: " + attrName
			}
			findings = append(findings, makeFinding(score, engine.SeverityHigh,
				desc, truncateMatch(tag.RawMatch), location, 0.90))
		}

		// <iframe — score 50
		if tag.Name == "iframe" && !hasScoreForTag(findings, tag.RawMatch, 80) {
			findings = append(findings, makeFinding(50, engine.SeverityMedium,
				"Iframe tag detected",
				truncateMatch(tag.RawMatch), location, 0.70))
		}

		// <object — score 45
		if tag.Name == "object" {
			findings = append(findings, makeFinding(45, engine.SeverityMedium,
				"Object tag detected",
				truncateMatch(tag.RawMatch), location, 0.65))
		}

		// <embed — score 45
		if tag.Name == "embed" {
			findings = append(findings, makeFinding(45, engine.SeverityMedium,
				"Embed tag detected",
				truncateMatch(tag.RawMatch), location, 0.65))
		}

		// <form + action= — score 40
		if tag.Name == "form" {
			if _, hasAction := tag.Attributes["action"]; hasAction {
				findings = append(findings, makeFinding(40, engine.SeverityMedium,
					"Form tag with action attribute",
					truncateMatch(tag.RawMatch), location, 0.60))
			}
		}

		// <meta http-equiv=refresh — score 50
		if tag.Name == "meta" {
			if httpEquiv, ok := tag.Attributes["http-equiv"]; ok {
				if strings.EqualFold(httpEquiv, "refresh") {
					findings = append(findings, makeFinding(50, engine.SeverityMedium,
						"Meta refresh tag detected",
						truncateMatch(tag.RawMatch), location, 0.75))
				}
			}
		}
	}

	// 4. javascript: protocol outside of tags — score 80
	if strings.Contains(analysisLower, "javascript:") && !hasFindingDesc(findings, "JavaScript protocol") {
		findings = append(findings, makeFinding(80, engine.SeverityHigh,
			"JavaScript protocol detected",
			truncateMatch(analysisStr), location, 0.90))
	}

	// 5. data:text/html outside of tags — score 75
	if strings.Contains(analysisLower, "data:text/html") && !hasFindingDesc(findings, "Data URI") {
		findings = append(findings, makeFinding(75, engine.SeverityHigh,
			"Data URI with text/html detected",
			truncateMatch(analysisStr), location, 0.85))
	}

	// 6. expression( — CSS expression (IE) — score 70
	if strings.Contains(analysisLower, "expression(") {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"CSS expression() detected",
			truncateMatch(analysisStr), location, 0.85))
	}

	// 7. JS dangerous function: eval( — score 65
	if containsEvalCall(analysisLower) {
		findings = append(findings, makeFinding(65, engine.SeverityHigh,
			"Dangerous JS function call detected",
			truncateMatch(analysisStr), location, 0.85))
	}

	// 8. document.cookie — score 60
	if strings.Contains(analysisLower, "document.cookie") {
		findings = append(findings, makeFinding(60, engine.SeverityHigh,
			"document.cookie access detected",
			truncateMatch(analysisStr), location, 0.85))
	}

	// 9. document.write — score 55
	if strings.Contains(analysisLower, "document.write") {
		findings = append(findings, makeFinding(55, engine.SeverityMedium,
			"document.write() call detected",
			truncateMatch(analysisStr), location, 0.80))
	}

	// 10. innerHTML — score 50
	if strings.Contains(analysisLower, "innerhtml") {
		findings = append(findings, makeFinding(50, engine.SeverityMedium,
			"innerHTML manipulation detected",
			truncateMatch(analysisStr), location, 0.75))
	}

	// 11. Standalone on[event]= not already caught by tag scanning — score 70
	if !hasFindingDesc(findings, "event handler") && !hasFindingDesc(findings, "Event handler") &&
		containsEventHandler(analysisLower) {
		findings = append(findings, makeFinding(70, engine.SeverityHigh,
			"Inline event handler attribute detected",
			truncateMatch(analysisStr), location, 0.85))
	}

	// 12. Template injection: {{, ${, #{ — score 55
	templates := detectTemplateInjection(analysisStr)
	for _, tmpl := range templates {
		findings = append(findings, makeFinding(55, engine.SeverityMedium,
			"Template injection marker detected: "+tmpl,
			truncateMatch(analysisStr), location, 0.75))
	}

	// 13. Encoded < bonus: +20 to existing scores
	if hasEncoded && len(findings) > 0 {
		findings = append(findings, makeFinding(20, engine.SeverityMedium,
			"Encoded angle bracket evasion detected",
			truncateMatch(input), location, 0.70))
	} else if hasEncoded {
		// Encoded < on its own with no other findings: still flag it
		findings = append(findings, makeFinding(20, engine.SeverityLow,
			"Encoded angle bracket detected",
			truncateMatch(input), location, 0.50))
	}

	return findings
}

// containsScriptBlock checks for <script>...</script> pattern (case-insensitive).
func containsScriptBlock(lower string) bool {
	openIdx := strings.Index(lower, "<script")
	if openIdx < 0 {
		return false
	}
	closeIdx := strings.Index(lower, "</script")
	return closeIdx > openIdx
}

// containsEvalCall checks for the eval( pattern in lowercased input.
func containsEvalCall(lower string) bool {
	// We look for "eval(" literally in the lowercased string
	return strings.Contains(lower, "eval(")
}

// containsEventHandler checks if the lowercased input contains an on[a-z]+= pattern.
func containsEventHandler(lower string) bool {
	i := 0
	for i < len(lower)-3 {
		idx := strings.Index(lower[i:], "on")
		if idx < 0 {
			break
		}
		pos := i + idx
		// Check that the character after "on" is a lowercase letter
		nextPos := pos + 2
		if nextPos < len(lower) && lower[nextPos] >= 'a' && lower[nextPos] <= 'z' {
			// Scan forward to find =
			j := nextPos
			for j < len(lower) && lower[j] >= 'a' && lower[j] <= 'z' {
				j++
			}
			if j < len(lower) && lower[j] == '=' {
				return true
			}
		}
		i = pos + 2
	}
	return false
}

// hasScoreForTag checks if any existing finding references the given raw match
// and has a score >= minScore.
func hasScoreForTag(findings []engine.Finding, rawMatch string, minScore int) bool {
	truncated := truncateMatch(rawMatch)
	for _, f := range findings {
		if f.Score >= minScore && f.MatchedValue == truncated {
			return true
		}
	}
	return false
}

// hasFindingDesc checks if any existing finding's description contains substr.
func hasFindingDesc(findings []engine.Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Description, substr) {
			return true
		}
	}
	return false
}

// makeFinding creates a Finding with standard XSS fields.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "xss",
		Category:     "xss",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// truncateMatch truncates the matched value to at most 200 characters.
func truncateMatch(s string) string {
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}
