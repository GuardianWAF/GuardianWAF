package sqli

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// AnalyzeTokens examines a token sequence and returns findings with scores.
func AnalyzeTokens(tokens []Token, location string) []engine.Finding {
	var findings []engine.Finding

	// Filter out whitespace for analysis
	significant := filterSignificant(tokens)

	// 1. UNION + SELECT pattern
	if f, ok := checkUnionSelect(significant, location); ok {
		findings = append(findings, f)
	}

	// 2. String literal + OR/AND keyword (with tautology check)
	findings = append(findings, checkBooleanInjection(significant, location)...)

	// 3. SEMICOLON + dangerous keyword (stacked queries)
	if f, ok := checkStackedQuery(significant, location); ok {
		findings = append(findings, f)
	}

	// 4. Dangerous function (SLEEP/BENCHMARK/WAITFOR)
	findings = append(findings, checkTimeBasedBlind(significant, location)...)

	// 5. File functions (LOAD_FILE/OUTFILE/DUMPFILE)
	findings = append(findings, checkFileAccess(significant, location)...)

	// 6. INTO + OUTFILE/DUMPFILE
	if f, ok := checkIntoOutfile(significant, location); ok {
		findings = append(findings, f)
	}

	// 7. Comment after string literal
	if f, ok := checkCommentAfterString(significant, location); ok {
		findings = append(findings, f)
	}

	// 8. EXEC/EXECUTE + string literal
	if f, ok := checkExecString(significant, location); ok {
		findings = append(findings, f)
	}

	// 9. CHAR/CONCAT with nested parens
	if f, ok := checkCharConcat(significant, location); ok {
		findings = append(findings, f)
	}

	// 10. Hex literal in comparison
	if f, ok := checkHexComparison(significant, location); ok {
		findings = append(findings, f)
	}

	// 11. Isolated SQL keywords (low score)
	findings = append(findings, checkIsolatedKeywords(significant, location)...)

	// 12. Multiple dangerous keywords bonus
	if f, ok := checkMultipleDangerousKeywords(significant, location); ok {
		findings = append(findings, f)
	}

	// 13. Subquery pattern: (SELECT ...) used in boolean context
	if f, ok := checkSubquery(significant, location); ok {
		findings = append(findings, f)
	}

	return findings
}

// Detect is the main entry point for SQLi detection on a single input string.
// It tokenizes the input and analyzes the token sequence.
func Detect(input, location string) []engine.Finding {
	if input == "" {
		return nil
	}
	tokens := Tokenize(input)
	return AnalyzeTokens(tokens, location)
}

// filterSignificant returns tokens with whitespace removed.
func filterSignificant(tokens []Token) []Token {
	result := make([]Token, 0, len(tokens))
	for _, t := range tokens {
		if t.Type != TokenWhitespace {
			result = append(result, t)
		}
	}
	return result
}

// tokenUpperValue returns the uppercase version of a token's value.
func tokenUpperValue(t Token) string {
	return strings.ToUpper(t.Value)
}

// makeFinding creates a Finding with standard fields filled in.
func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "sqli",
		Category:     "sqli",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}

// checkUnionSelect checks for UNION [ALL] SELECT pattern.
func checkUnionSelect(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenKeyword && tokenUpperValue(tokens[i]) == "UNION" {
			// Look ahead for SELECT, possibly with ALL in between
			for j := i + 1; j < len(tokens); j++ {
				if tokens[j].Type == TokenComment {
					continue
				}
				upper := tokenUpperValue(tokens[j])
				if tokens[j].Type == TokenKeyword && upper == "ALL" {
					continue
				}
				if tokens[j].Type == TokenKeyword && upper == "SELECT" {
					matched := extractRange(tokens, i, j)
					return makeFinding(90, engine.SeverityCritical,
						"UNION SELECT injection pattern detected",
						matched, location, 0.95), true
				}
				break
			}
		}
	}
	return engine.Finding{}, false
}

// checkBooleanInjection checks for string literal + OR/AND patterns, including tautology.
func checkBooleanInjection(tokens []Token, location string) []engine.Finding {
	var findings []engine.Finding
	for i := 0; i < len(tokens); i++ {
		upper := tokenUpperValue(tokens[i])
		if (tokens[i].Type == TokenKeyword || tokens[i].Type == TokenOperator) && (upper == "OR" || upper == "AND") {
			// Check if preceded by string literal or followed by tautology
			hasPrecedingString := false
			for j := i - 1; j >= 0; j-- {
				if tokens[j].Type == TokenComment {
					continue
				}
				if tokens[j].Type == TokenStringLiteral {
					hasPrecedingString = true
				}
				break
			}

			score := 0
			if hasPrecedingString {
				score = 30
			}

			// Check for tautology after the OR/AND
			if i+1 < len(tokens) && hasTautology(tokens, i+1) {
				score += 55
				matched := extractRange(tokens, max(0, i-1), min(len(tokens)-1, i+4))
				findings = append(findings, makeFinding(score, engine.SeverityHigh,
					"Boolean-based SQL injection with tautology detected",
					matched, location, 0.90))
			} else if hasPrecedingString && score > 0 {
				matched := extractRange(tokens, max(0, i-1), min(len(tokens)-1, i+1))
				findings = append(findings, makeFinding(score, engine.SeverityMedium,
					"Possible boolean-based SQL injection pattern",
					matched, location, 0.50))
			}
		}
	}
	return findings
}

// hasTautology checks for patterns like 1=1, 'a'='a', true=true starting at startIdx.
func hasTautology(tokens []Token, startIdx int) bool {
	if startIdx+2 >= len(tokens) {
		return false
	}

	// Skip comments
	idx := startIdx
	for idx < len(tokens) && tokens[idx].Type == TokenComment {
		idx++
	}
	if idx >= len(tokens) {
		return false
	}
	left := tokens[idx]

	// Find operator
	idx++
	for idx < len(tokens) && tokens[idx].Type == TokenComment {
		idx++
	}
	if idx >= len(tokens) {
		return false
	}
	op := tokens[idx]

	// Find right operand
	idx++
	for idx < len(tokens) && tokens[idx].Type == TokenComment {
		idx++
	}
	if idx >= len(tokens) {
		return false
	}
	right := tokens[idx]

	// Must have = operator
	if op.Type != TokenOperator || op.Value != "=" {
		return false
	}

	// Both sides must be the same type and value
	leftVal := tokenUpperValue(left)
	rightVal := tokenUpperValue(right)

	// Numeric tautology: 1=1, 2=2
	if left.Type == TokenNumericLiteral && right.Type == TokenNumericLiteral && left.Value == right.Value {
		return true
	}

	// String tautology: 'a'='a'
	if left.Type == TokenStringLiteral && right.Type == TokenStringLiteral && left.Value == right.Value {
		return true
	}

	// Keyword/Other tautology: true=true, null=null
	if left.Type == right.Type && leftVal == rightVal {
		return true
	}

	// Injection-style string tautology: 'a'='a where the trailing quote is
	// provided by the SQL context. Detected as: left='a' (StringLiteral),
	// right=' (unterminated StringLiteral), followed by Other token "a".
	// The inner value of left is "a", and right+next = "a".
	if left.Type == TokenStringLiteral && right.Type == TokenStringLiteral {
		leftInner := stripQuotes(left.Value)
		// If right is an unterminated single-char quote, check the next token
		if len(right.Value) == 1 && idx+1 < len(tokens) {
			next := tokens[idx+1]
			if next.Type == TokenOther || next.Type == TokenNumericLiteral || next.Type == TokenKeyword {
				rightInner := strings.ToUpper(next.Value)
				if strings.EqualFold(leftInner, rightInner) {
					return true
				}
			}
		}
	}

	// Cross-type: string literal vs Other/Keyword (e.g., 'a' = a in injection context)
	if left.Type == TokenStringLiteral && (right.Type == TokenOther || right.Type == TokenKeyword) {
		leftInner := strings.ToUpper(stripQuotes(left.Value))
		if leftInner == rightVal {
			return true
		}
	}

	return false
}

// checkStackedQuery checks for ; followed by dangerous keyword.
func checkStackedQuery(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenSemicolon {
			// Look ahead for dangerous keyword
			for j := i + 1; j < len(tokens); j++ {
				if tokens[j].Type == TokenComment {
					continue
				}
				if tokens[j].Type == TokenKeyword {
					upper := tokenUpperValue(tokens[j])
					if IsDangerousKeyword(upper) {
						matched := extractRange(tokens, i, min(len(tokens)-1, j+2))
						return makeFinding(95, engine.SeverityCritical,
							"Stacked query with dangerous keyword: "+upper,
							matched, location, 0.95), true
					}
				}
				break
			}
		}
	}
	return engine.Finding{}, false
}

// checkTimeBasedBlind checks for SLEEP(), BENCHMARK(), WAITFOR DELAY.
func checkTimeBasedBlind(tokens []Token, location string) []engine.Finding {
	var findings []engine.Finding
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenFunction {
			upper := tokenUpperValue(tokens[i])
			switch upper {
			case "SLEEP", "BENCHMARK":
				matched := extractRange(tokens, i, min(len(tokens)-1, i+3))
				findings = append(findings, makeFinding(90, engine.SeverityCritical,
					"Time-based blind injection using "+upper,
					matched, location, 0.95))
			case "WAITFOR":
				// Look for DELAY after WAITFOR
				for j := i + 1; j < len(tokens); j++ {
					if tokens[j].Type == TokenComment {
						continue
					}
					if tokens[j].Type == TokenFunction && tokenUpperValue(tokens[j]) == "DELAY" {
						matched := extractRange(tokens, i, min(len(tokens)-1, j+2))
						findings = append(findings, makeFinding(90, engine.SeverityCritical,
							"Time-based blind injection using WAITFOR DELAY",
							matched, location, 0.95))
					}
					break
				}
			}
		}
	}
	return findings
}

// checkFileAccess checks for LOAD_FILE, OUTFILE, DUMPFILE functions.
func checkFileAccess(tokens []Token, location string) []engine.Finding {
	var findings []engine.Finding
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenFunction {
			upper := tokenUpperValue(tokens[i])
			switch upper {
			case "LOAD_FILE":
				matched := extractRange(tokens, i, min(len(tokens)-1, i+3))
				findings = append(findings, makeFinding(100, engine.SeverityCritical,
					"File read attempt using LOAD_FILE",
					matched, location, 1.0))
			case "OUTFILE", "DUMPFILE":
				matched := extractRange(tokens, i, min(len(tokens)-1, i+2))
				findings = append(findings, makeFinding(100, engine.SeverityCritical,
					"File write attempt using "+upper,
					matched, location, 1.0))
			}
		}
	}
	return findings
}

// checkIntoOutfile checks for INTO OUTFILE/DUMPFILE pattern.
func checkIntoOutfile(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenKeyword && tokenUpperValue(tokens[i]) == "INTO" {
			for j := i + 1; j < len(tokens); j++ {
				if tokens[j].Type == TokenComment {
					continue
				}
				upper := tokenUpperValue(tokens[j])
				if tokens[j].Type == TokenFunction && (upper == "OUTFILE" || upper == "DUMPFILE") {
					matched := extractRange(tokens, i, min(len(tokens)-1, j+2))
					return makeFinding(100, engine.SeverityCritical,
						"File write attempt using INTO "+upper,
						matched, location, 1.0), true
				}
				break
			}
		}
	}
	return engine.Finding{}, false
}

// checkCommentAfterString checks for string literal followed by comment.
func checkCommentAfterString(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i].Type == TokenStringLiteral {
			// Look for comment immediately after (possibly with other tokens in between)
			for j := i + 1; j < len(tokens); j++ {
				if tokens[j].Type == TokenComment {
					matched := extractRange(tokens, i, j)
					return makeFinding(35, engine.SeverityMedium,
						"Comment used after string literal (possible evasion)",
						matched, location, 0.60), true
				}
				// Allow certain tokens between string and comment
				if tokens[j].Type == TokenOperator || tokens[j].Type == TokenOther {
					continue
				}
				break
			}
		}
	}
	return engine.Finding{}, false
}

// checkExecString checks for EXEC/EXECUTE followed by string literal.
func checkExecString(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenKeyword {
			upper := tokenUpperValue(tokens[i])
			if upper == "EXEC" || upper == "EXECUTE" {
				for j := i + 1; j < len(tokens); j++ {
					if tokens[j].Type == TokenComment {
						continue
					}
					// EXEC followed by anything useful (string, identifier, function)
					if tokens[j].Type == TokenStringLiteral || tokens[j].Type == TokenOther || tokens[j].Type == TokenFunction {
						matched := extractRange(tokens, i, min(len(tokens)-1, j+2))
						return makeFinding(80, engine.SeverityHigh,
							"EXEC/EXECUTE with dynamic argument",
							matched, location, 0.85), true
					}
					break
				}
			}
		}
	}
	return engine.Finding{}, false
}

// checkCharConcat checks for CHAR/CONCAT with parentheses (obfuscation pattern).
func checkCharConcat(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenFunction {
			upper := tokenUpperValue(tokens[i])
			if upper == "CHAR" || upper == "CONCAT" {
				// Look for opening paren
				if i+1 < len(tokens) && tokens[i+1].Type == TokenParenOpen {
					matched := extractRange(tokens, i, min(len(tokens)-1, i+5))
					return makeFinding(50, engine.SeverityMedium,
						"Potential SQL injection obfuscation using "+upper+"()",
						matched, location, 0.70), true
				}
			}
		}
	}
	return engine.Finding{}, false
}

// checkHexComparison checks for hex literals used in comparisons.
func checkHexComparison(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenNumericLiteral && len(tokens[i].Value) > 2 &&
			(strings.HasPrefix(tokens[i].Value, "0x") || strings.HasPrefix(tokens[i].Value, "0X")) {
			// Check if there's an operator nearby
			hasOperator := false
			for j := max(0, i-2); j < min(len(tokens), i+3); j++ {
				if tokens[j].Type == TokenOperator {
					hasOperator = true
					break
				}
			}
			if hasOperator {
				return makeFinding(40, engine.SeverityMedium,
					"Hex literal used in comparison (possible obfuscation)",
					tokens[i].Value, location, 0.55), true
			}
		}
	}
	return engine.Finding{}, false
}

// checkIsolatedKeywords reports isolated SQL keywords at low score.
func checkIsolatedKeywords(tokens []Token, location string) []engine.Finding {
	var findings []engine.Finding
	for _, t := range tokens {
		if t.Type == TokenKeyword {
			upper := tokenUpperValue(t)
			if IsDangerousKeyword(upper) {
				findings = append(findings, makeFinding(10, engine.SeverityLow,
					"SQL keyword found in input: "+upper,
					t.Value, location, 0.20))
			}
		}
	}
	return findings
}

// checkMultipleDangerousKeywords applies bonus scoring when multiple dangerous keywords appear.
func checkMultipleDangerousKeywords(tokens []Token, location string) (engine.Finding, bool) {
	dangerousCount := 0
	var dangerousWords []string
	seen := make(map[string]bool)
	for _, t := range tokens {
		if t.Type == TokenKeyword {
			upper := tokenUpperValue(t)
			if IsDangerousKeyword(upper) && !seen[upper] {
				seen[upper] = true
				dangerousCount++
				dangerousWords = append(dangerousWords, upper)
			}
		}
	}
	if dangerousCount >= 3 {
		return makeFinding(30, engine.SeverityHigh,
			"Multiple dangerous SQL keywords detected: "+strings.Join(dangerousWords, ", "),
			strings.Join(dangerousWords, " "), location, 0.80), true
	}
	return engine.Finding{}, false
}

// checkSubquery detects (SELECT ...) subquery patterns used in boolean injection context.
func checkSubquery(tokens []Token, location string) (engine.Finding, bool) {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].Type == TokenParenOpen {
			// Look for SELECT immediately after open paren
			if i+1 < len(tokens) && tokens[i+1].Type == TokenKeyword && tokenUpperValue(tokens[i+1]) == "SELECT" {
				// Find the matching close paren
				end := min(len(tokens)-1, i+10)
				for j := i + 2; j < len(tokens); j++ {
					if tokens[j].Type == TokenParenClose {
						end = j
						break
					}
				}
				matched := extractRange(tokens, i, end)
				return makeFinding(25, engine.SeverityMedium,
					"Subquery injection pattern: (SELECT ...)",
					matched, location, 0.70), true
			}
		}
	}
	return engine.Finding{}, false
}

// extractRange builds a string from tokens[start..end] inclusive.
func extractRange(tokens []Token, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end >= len(tokens) {
		end = len(tokens) - 1
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		if i > start {
			b.WriteByte(' ')
		}
		b.WriteString(tokens[i].Value)
	}
	return b.String()
}

// stripQuotes removes the surrounding quote characters from a string literal token value.
// For example, "'hello'" becomes "hello", "\"world\"" becomes "world".
// If the value has fewer than 2 characters or the first and last characters don't match,
// it returns the original value unchanged.
func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first := s[0]
	last := s[len(s)-1]
	if (first == '\'' || first == '"' || first == '`') && first == last {
		return s[1 : len(s)-1]
	}
	return s
}
