package cmdi

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements the engine.Detector interface for command injection detection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new command injection detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{
		enabled:    enabled,
		multiplier: multiplier,
	}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "cmdi-detector" }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "cmdi" }

// Patterns returns the list of attack patterns this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"shell-metachar",
		"command-sequence",
		"command-substitution",
		"pipe-chain",
		"shell-path",
		"encoded-injection",
	}
}

// Process scans the request context for command injection patterns.
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

// Detect scans a single input string for command injection patterns.
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}

	var findings []engine.Finding
	lower := strings.ToLower(input)

	// 1. Shell metacharacter + command patterns
	findings = append(findings, checkShellMetachars(input, lower, location)...)

	// 2. Command substitution: $(...) and backticks
	findings = append(findings, checkCommandSubstitution(input, lower, location)...)

	// 3. Shell paths (/bin/sh, /bin/bash, etc.)
	findings = append(findings, checkShellPaths(lower, location)...)

	// 4. Interpreter with -c or -e flag
	findings = append(findings, checkInterpreterFlags(lower, location)...)

	// 5. base64 + pipe pattern
	findings = append(findings, checkBase64Pipe(lower, location)...)

	// 6. Encoded newline injection
	findings = append(findings, checkEncodedNewline(lower, location)...)

	// 7. Redirection operators
	findings = append(findings, checkRedirection(input, lower, location)...)

	return findings
}

// makeFinding creates a Finding with standard CMDi fields.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "cmdi",
		Category:     "cmdi",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// checkShellMetachars detects shell metacharacters followed by commands.
func checkShellMetachars(_, lower, location string) []engine.Finding {
	var findings []engine.Finding

	// Check each metacharacter separator
	separators := []struct {
		sep   string
		score int
		desc  string
	}{
		{";", 75, "Semicolon command separator with command detected"},
		{"&&", 65, "AND operator with command detected"},
		{"||", 65, "OR operator with command detected"},
		{"|", 65, "Pipe operator with command detected"},
	}

	for _, s := range separators {
		parts := strings.Split(lower, s.sep)
		if len(parts) < 2 {
			continue
		}
		// Check each part after a separator for known commands
		for i := 1; i < len(parts); i++ {
			trimmed := strings.TrimSpace(parts[i])
			if trimmed == "" {
				continue
			}
			cmd := extractFirstWord(trimmed)
			if cmd == "" {
				continue
			}

			if isReconCommand(cmd) {
				score := max(s.score, 65)
				findings = append(findings, makeFinding(score, engine.SeverityHigh,
					s.desc+" (recon: "+cmd+")",
					extractContext(lower, s.sep), location, 0.85))
				break
			}
			if isNetworkCommand(cmd) {
				score := max(s.score, 75)
				findings = append(findings, makeFinding(score, engine.SeverityCritical,
					s.desc+" (network: "+cmd+")",
					extractContext(lower, s.sep), location, 0.90))
				break
			}
			if IsCommand(cmd) {
				findings = append(findings, makeFinding(s.score, engine.SeverityHigh,
					s.desc+" ("+cmd+")",
					extractContext(lower, s.sep), location, 0.80))
				break
			}
		}
	}

	return findings
}

// checkCommandSubstitution detects $(...) and backtick command substitution.
func checkCommandSubstitution(input, lower, location string) []engine.Finding {
	var findings []engine.Finding

	// $( ... ) pattern
	idx := strings.Index(lower, "$(")
	if idx >= 0 {
		end := strings.Index(lower[idx:], ")")
		content := ""
		if end > 2 {
			content = strings.TrimSpace(lower[idx+2 : idx+end])
		}
		cmd := extractFirstWord(content)
		score := 80
		desc := "Command substitution $() detected"
		if IsCommand(cmd) {
			desc = "Command substitution $(" + cmd + ") detected"
		}
		findings = append(findings, makeFinding(score, engine.SeverityCritical,
			desc, extractContext(lower, "$("), location, 0.90))
	}

	// Backtick pattern
	firstBt := strings.Index(input, "`")
	if firstBt >= 0 {
		secondBt := strings.Index(input[firstBt+1:], "`")
		if secondBt >= 0 {
			content := strings.TrimSpace(strings.ToLower(input[firstBt+1 : firstBt+1+secondBt]))
			cmd := extractFirstWord(content)
			score := 80
			desc := "Backtick command substitution detected"
			if IsCommand(cmd) {
				desc = "Backtick command substitution with " + cmd + " detected"
			}
			findings = append(findings, makeFinding(score, engine.SeverityCritical,
				desc, extractContext(lower, "`"), location, 0.90))
		}
	}

	return findings
}

// checkShellPaths detects references to shell interpreters.
func checkShellPaths(lower, location string) []engine.Finding {
	var findings []engine.Finding

	shellPaths := []string{
		"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
		"/bin/csh", "/bin/ksh", "/bin/tcsh",
		"/usr/bin/env sh", "/usr/bin/env bash",
		"/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
	}

	for _, sp := range shellPaths {
		if strings.Contains(lower, sp) {
			findings = append(findings, makeFinding(90, engine.SeverityCritical,
				"Shell path detected: "+sp,
				extractContext(lower, sp), location, 0.95))
			break
		}
	}

	return findings
}

// checkInterpreterFlags detects interpreter invocations with -c or -e flags.
func checkInterpreterFlags(lower, location string) []engine.Finding {
	var findings []engine.Finding

	interpreters := []string{
		"python", "python3", "perl", "ruby", "php", "node",
		"bash", "sh", "zsh", "dash", "csh", "ksh",
		"cmd", "powershell", "pwsh",
	}

	flags := []string{" -c ", " -e "}

	for _, interp := range interpreters {
		for _, flag := range flags {
			pattern := interp + flag
			if strings.Contains(lower, pattern) {
				findings = append(findings, makeFinding(80, engine.SeverityCritical,
					"Interpreter with execution flag detected: "+interp+flag,
					extractContext(lower, pattern), location, 0.90))
				return findings // One match is enough
			}
		}
	}

	return findings
}

// checkBase64Pipe detects base64 decode piped to shell.
func checkBase64Pipe(lower, location string) []engine.Finding {
	var findings []engine.Finding

	// Patterns like: base64 -d | sh, echo ... | base64 -d | bash
	if strings.Contains(lower, "base64") && (strings.Contains(lower, "|") || strings.Contains(lower, ";")) {
		findings = append(findings, makeFinding(85, engine.SeverityCritical,
			"base64 with pipe/chain detected (likely encoded command execution)",
			extractContext(lower, "base64"), location, 0.90))
	}

	return findings
}

// checkEncodedNewline detects URL-encoded newline injection.
func checkEncodedNewline(lower, location string) []engine.Finding {
	var findings []engine.Finding

	if strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d") {
		// Check if there's a command after the newline
		parts := strings.Split(lower, "%0a")
		if len(parts) < 2 {
			parts = strings.Split(lower, "%0d")
		}
		for i := 1; i < len(parts); i++ {
			trimmed := strings.TrimSpace(parts[i])
			cmd := extractFirstWord(trimmed)
			if IsCommand(cmd) {
				findings = append(findings, makeFinding(60, engine.SeverityHigh,
					"Newline injection with command detected: "+cmd,
					extractContext(lower, "%0"), location, 0.80))
				break
			}
		}
		if len(findings) == 0 && (strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d")) {
			findings = append(findings, makeFinding(60, engine.SeverityHigh,
				"Encoded newline injection detected",
				extractContext(lower, "%0"), location, 0.70))
		}
	}

	return findings
}

// checkRedirection detects output redirection operators.
func checkRedirection(input, lower, location string) []engine.Finding {
	var findings []engine.Finding

	// Check for > or >> but not inside URLs (like https://)
	for i := 0; i < len(input); i++ {
		if input[i] != '>' {
			continue
		}
		// Skip if preceded by / (likely a URL closing tag or similar)
		if i > 0 && input[i-1] == '/' {
			continue
		}
		// Skip if part of => (arrow operator)
		if i > 0 && input[i-1] == '=' {
			continue
		}
		// Skip HTML tags like <tag>
		if i > 0 {
			// Check if this is part of an HTML tag
			isHTMLTag := false
			for j := i - 1; j >= 0; j-- {
				if input[j] == '<' {
					isHTMLTag = true
					break
				}
				if input[j] == '>' || input[j] == ' ' {
					break
				}
			}
			if isHTMLTag {
				continue
			}
		}

		score := 45
		desc := "Output redirection operator detected"
		if i+1 < len(input) && input[i+1] == '>' {
			desc = "Append redirection operator detected"
		}
		findings = append(findings, makeFinding(score, engine.SeverityMedium,
			desc, extractContext(lower, ">"), location, 0.60))
		break
	}

	return findings
}

// extractFirstWord returns the first whitespace-delimited word from s.
func extractFirstWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	idx := strings.IndexAny(s, " \t\r\n")
	if idx < 0 {
		return s
	}
	return s[:idx]
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
	start := max(idx-20, 0)
	end := min(idx+len(pattern)+30, len(input))
	result := input[start:end]
	if len(result) > 200 {
		result = result[:197] + "..."
	}
	return result
}
