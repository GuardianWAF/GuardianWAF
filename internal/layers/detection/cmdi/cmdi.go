package cmdi

import (
	"fmt"
	"strings"
	"time"

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

func (d *Detector) Order() int { return 0 }

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
	start := time.Now()
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var allFindings []engine.Finding

	// Scan BOTH the raw and the sanitizer-normalized form of every input.
	// The sanitizer's CanonicalizePath treats query values as filesystem paths and
	// rejoins them on "/", which can mangle shell-metacharacter sequences (e.g.
	// "127.0.0.1;cat /etc/passwd"). Scanning the raw input as well preserves the
	// injection signal while keeping the decode-evasion benefit of normalization.
	// Identical strings are scanned once (dedup). Mirrors xss/xxe fail-open guard.
	seen := make(map[string]struct{})
	scan := func(v, location string) {
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
	// Collapse the same finding discovered in more than one representation of
	// the same field. Every input is scanned raw AND normalized, and when
	// normalization rewrites the string the two forms are no longer equal, so
	// the input-level dedup above lets both through and the identical finding
	// is scored twice. That doubling is what pushed a markdown table row
	// ("| id | name |") from a deliberately sub-threshold 35 to a blocking 70.
	allFindings = dedupeFindings(allFindings)

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
	findings = append(findings, checkEncodedNewline(input, lower, location)...)

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
		{"\n", 75, "Newline command separator with command detected"},
		{"\r", 75, "Carriage-return command separator with command detected"},
	}

	// A command reached through more than one separator pattern must be
	// reported once. "test || id" splits on both "||" and "|", which produced
	// two findings for the same "id" and doubled its score.
	reported := make(map[string]bool)

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
			if reported[cmd] {
				continue
			}

			// A command name that is also an everyday word carries almost no
			// signal on its own: "| id | name |" from a markdown table and
			// "127.0.0.1;id" are the same shape to a substring matcher. Record
			// it, but keep it below the default block threshold unless the
			// invocation is corroborated by real arguments. Applies to every
			// branch below — "id" is classified as a recon command, so guarding
			// only the generic branch left the markdown table blocking.
			downgrade := isAmbiguousCommand(cmd) && !hasCommandArguments(trimmed, cmd)

			if isReconCommand(cmd) || isNetworkCommand(cmd) || IsCommand(cmd) {
				reported[cmd] = true
			}

			switch {
			case isReconCommand(cmd):
				score, confidence := max(s.score, 65), 0.85
				if downgrade {
					score, confidence = ambiguousCommandScore, 0.40
				}
				findings = append(findings, makeFinding(score, engine.SeverityHigh,
					s.desc+" (recon: "+cmd+")",
					extractContext(lower, s.sep), location, confidence))
			case isNetworkCommand(cmd):
				score, confidence := max(s.score, 75), 0.90
				if downgrade {
					score, confidence = ambiguousCommandScore, 0.40
				}
				findings = append(findings, makeFinding(score, engine.SeverityCritical,
					s.desc+" (network: "+cmd+")",
					extractContext(lower, s.sep), location, confidence))
			case IsCommand(cmd):
				score, confidence := s.score, 0.80
				if downgrade {
					score, confidence = ambiguousCommandScore, 0.40
				}
				findings = append(findings, makeFinding(score, engine.SeverityHigh,
					s.desc+" ("+cmd+")",
					extractContext(lower, s.sep), location, confidence))
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
		contentStart := idx + 2
		contentEnd := len(lower)
		if end := strings.Index(lower[idx:], ")"); end > 2 {
			contentEnd = idx + end
		}
		content := ""
		if contentStart < contentEnd {
			content = strings.TrimSpace(lower[contentStart:contentEnd])
		}
		cmd := extractFirstWord(content)
		if IsCommand(cmd) || containsShellExecutionSignal(content) {
			score := 80
			desc := "Command substitution $() detected"
			if IsCommand(cmd) {
				desc = "Command substitution $(" + cmd + ") detected"
			}
			findings = append(findings, makeFinding(score, engine.SeverityCritical,
				desc, extractContext(lower, "$("), location, 0.90))
		}
	}

	// Backtick pattern
	firstBt := strings.Index(input, "`")
	if firstBt >= 0 {
		secondBt := strings.Index(input[firstBt+1:], "`")
		if secondBt >= 0 {
			content := strings.TrimSpace(strings.ToLower(input[firstBt+1 : firstBt+1+secondBt]))
			cmd := extractFirstWord(content)
			if IsCommand(cmd) || containsShellExecutionSignal(content) {
				score := 80
				desc := "Backtick command substitution detected"
				if IsCommand(cmd) {
					desc = "Backtick command substitution with " + cmd + " detected"
				}
				findings = append(findings, makeFinding(score, engine.SeverityCritical,
					desc, extractContext(lower, "`"), location, 0.90))
			}
		}
	}

	return findings
}

func containsShellExecutionSignal(content string) bool {
	return strings.Contains(content, "/bin/") ||
		strings.Contains(content, " -c ") ||
		strings.Contains(content, " -e ") ||
		strings.Contains(content, "|") ||
		strings.Contains(content, "&&") ||
		strings.Contains(content, "||")
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

// base64DecodeFlags are the flags that turn base64(1) into a decoder, which is
// what makes it useful in a command-injection chain.
var base64DecodeFlags = []string{"-d", "--decode", "-D", "--dec"}

// checkBase64Pipe detects base64 decode piped to a shell.
//
// The test used to be `contains("base64") && (contains("|") || contains(";"))`,
// which matches every data URI ever submitted: "data:image/png;base64,iVBOR..."
// contains both. That scored 85 against a block threshold of 50, so avatar
// uploads, rich-text embeds and canvas exports were all blocked. The attack
// this rule exists for is `... | base64 -d | sh`, so require the decode flag
// that distinguishes decoding from the encoding half of a data URI.
func checkBase64Pipe(lower, location string) []engine.Finding {
	var findings []engine.Finding

	idx := strings.Index(lower, "base64")
	if idx < 0 {
		return nil
	}
	if !strings.Contains(lower, "|") && !strings.Contains(lower, ";") {
		return nil
	}

	// The decode flag must follow the command name, not merely exist somewhere.
	rest := lower[idx+len("base64"):]
	hasDecodeFlag := false
	for _, flag := range base64DecodeFlags {
		if fieldFollows(rest, flag) {
			hasDecodeFlag = true
			break
		}
	}
	if !hasDecodeFlag {
		return nil
	}

	findings = append(findings, makeFinding(85, engine.SeverityCritical,
		"base64 decode with pipe/chain detected (likely encoded command execution)",
		extractContext(lower, "base64"), location, 0.90))

	return findings
}

// fieldFollows reports whether flag appears as a whitespace-delimited argument
// within the first few fields of rest, so "base64 -d" matches but the trailing
// payload of a data URI does not.
func fieldFollows(rest, flag string) bool {
	fields := strings.Fields(rest)
	for i, f := range fields {
		if i >= 3 {
			return false
		}
		if f == flag {
			return true
		}
	}
	return false
}

// checkEncodedNewline detects URL-encoded newline injection.
//
// Known limitation (M1 in docs/history/AUDIT.md): a "newline + known command"
// pattern fires the detector at score 60, confidence 0.80. Every
// command in commandDatabase is also a common English word or
// single character ("cat", "set", "at", "head", "tail", "more",
// "less", "find", "kill", "service", "host", "file", "last",
// "env", "w", "ip", etc.), so natural multi-line text that
// contains a URL-encoded newline followed by one of those words
// (e.g. "Hello%0Acat is great") produces a high-score finding
// that can trip default block thresholds on innocent traffic.
//
// This is not a "must-fix" because the heuristic fundamentally
// cannot distinguish an attack payload ("test%0awhoami") from
// natural text ("Hello%0Acat is great"): both are "URL-encoded
// newline + first-token-is-known-command + no shell metachar in
// the immediate vicinity." Any narrowing that suppresses the FP
// will also let the TP through (see git history for the
// reverted "must have a remainder" attempt that suppressed
// test%0awhoami). A correct fix requires either a context-aware
// parser (knowing the input is multi-line natural text vs. a
// deliberate payload) or a layered approach (lower the
// confidence on the no-remainder case so default block
// thresholds don't trip, while still logging). The current
// behavior is preserved; a regression test
// (TestDetect_NewlineInjection_CommonWordIsCommonWord) pins
// the FP-prone pattern so future maintainers confronting this
// trade-off are forced to update the test (and re-derive the
// reasoning above) rather than silently weaken the TP.
func checkEncodedNewline(input, lower, location string) []engine.Finding {
	// Count all newline occurrences (case-insensitive)
	newlineCount := strings.Count(lower, "%0a") + strings.Count(lower, "%0A") +
		strings.Count(lower, "%0d") + strings.Count(lower, "%0D")

	if newlineCount == 0 {
		return nil
	}

	// Score scales with newline count (each newline is suspicious)
	baseScore := 50
	newlineScore := min(baseScore+(newlineCount*10), 100)

	lowerInput := strings.ToLower(input)

	// Check if there's a command after any of the newlines
	// Check %0a variants
	parts := strings.Split(lowerInput, "%0a")
	for i := 1; i < len(parts); i++ {
		trimmed := strings.TrimSpace(parts[i])
		cmd := extractFirstWord(trimmed)
		if IsCommand(cmd) {
			return []engine.Finding{makeFinding(newlineScore, engine.SeverityHigh,
				fmt.Sprintf("Newline injection with command detected (%d newlines): %s", newlineCount, cmd),
				extractContext(lower, "%0"), location, 0.80)}
		}
	}
	// Check %0d variants
	parts = strings.Split(lowerInput, "%0d")
	for i := 1; i < len(parts); i++ {
		trimmed := strings.TrimSpace(parts[i])
		cmd := extractFirstWord(trimmed)
		if IsCommand(cmd) {
			return []engine.Finding{makeFinding(newlineScore, engine.SeverityHigh,
				fmt.Sprintf("Newline injection with command detected (%d newlines): %s", newlineCount, cmd),
				extractContext(lower, "%0"), location, 0.80)}
		}
	}

	return nil
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

		desc := "Output redirection operator detected"
		rest := input[i+1:]
		if strings.HasPrefix(rest, ">") {
			desc = "Append redirection operator detected"
			rest = rest[1:]
		}

		// A bare '>' is ambiguous: shell redirection and an ordinary comparison
		// look identical at this character. Real redirection names a target —
		// a path, a filename, or an fd duplication (2>&1) — whereas comparisons
		// like "price>100" or "5 > 3" are followed by a plain operand. Scoring
		// the comparison shape at 45 put it within one weak signal of the
		// default block threshold, which blocked filter APIs.
		score := 45
		confidence := 0.60
		if !redirectionTargetLooksLikeFileOrFD(rest) {
			desc = "Redirection-like character in comparison position"
			score = 10
			confidence = 0.25
		}
		findings = append(findings, makeFinding(score, engine.SeverityMedium,
			desc, extractContext(lower, ">"), location, confidence))
		break
	}

	return findings
}

// redirectionTargetLooksLikeFileOrFD reports whether what follows a '>' reads
// as a shell redirection target rather than the right-hand side of a
// comparison. Recognised: fd duplication (>&1), an absolute/relative/home path,
// a filename carrying an extension, and a dangling '>' at end of input.
func redirectionTargetLooksLikeFileOrFD(rest string) bool {
	trimmed := strings.TrimLeft(rest, " \t")
	if trimmed == "" {
		// Trailing '>' with nothing after it is not a comparison.
		return true
	}
	if trimmed[0] == '&' {
		return true // 2>&1 style fd duplication
	}
	if trimmed[0] == '/' || trimmed[0] == '\\' || trimmed[0] == '~' || trimmed[0] == '.' {
		return true // /tmp/x, ~/.bashrc, ./out
	}
	// First token: a path separator or an extension makes it a file target.
	word := trimmed
	if idx := strings.IndexAny(word, " \t\r\n&|;"); idx >= 0 {
		word = word[:idx]
	}
	return strings.ContainsAny(word, "/\\") || strings.Contains(word, ".")
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

// hasCommandArguments reports whether the text after a command name looks like
// an actual argument list — a flag, a path, a variable expansion, a redirect or
// a further chained command — rather than the next words of a sentence or the
// next cell of a markdown table. It is what upgrades an ambiguous command name
// back to a blocking score: ";cat /etc/passwd" corroborates, "| id | name |"
// does not.
func hasCommandArguments(trimmed, cmd string) bool {
	rest := strings.TrimSpace(strings.TrimPrefix(trimmed, cmd))
	if rest == "" {
		return false
	}
	switch rest[0] {
	case '-', '/', '$', '`', '>', '<', '*', '~', '\'', '"':
		return true
	}
	return strings.Contains(rest, "/") ||
		strings.Contains(rest, "$(") ||
		strings.Contains(rest, "&&") ||
		strings.Contains(rest, "\\")
}

// dedupeFindings collapses findings that describe the same detection at the
// same location, keeping the highest-scoring instance. Two representations of
// one field must contribute one finding, not one each.
func dedupeFindings(findings []engine.Finding) []engine.Finding {
	if len(findings) < 2 {
		return findings
	}

	type key struct{ desc, location string }
	best := make(map[key]int, len(findings))
	out := make([]engine.Finding, 0, len(findings))

	for _, f := range findings {
		k := key{f.Description, f.Location}
		if idx, ok := best[k]; ok {
			if f.Score > out[idx].Score {
				out[idx] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}
