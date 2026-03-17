package response

import (
	"strings"
)

// MaskCreditCards masks credit card numbers in text, preserving last 4 digits.
// Detects 13-19 digit sequences optionally separated by dashes or spaces,
// and validates them with the Luhn algorithm before masking.
func MaskCreditCards(s string) string {
	result := []byte(s)
	i := 0
	for i < len(result) {
		// Look for a sequence of digits (possibly separated by dashes or spaces)
		if isDigit(result[i]) {
			digits := []byte{}
			positions := []int{} // positions of actual digits in result
			j := i
			for j < len(result) && (isDigit(result[j]) || result[j] == '-' || result[j] == ' ') {
				if isDigit(result[j]) {
					digits = append(digits, result[j])
					positions = append(positions, j)
				}
				j++
			}

			// Check if we have a valid card number length (13-19 digits)
			if len(digits) >= 13 && len(digits) <= 19 && luhnCheck(digits) {
				// Mask all but last 4 digits
				maskEnd := len(positions) - 4
				if maskEnd < 0 {
					maskEnd = 0
				}
				for k := 0; k < maskEnd; k++ {
					result[positions[k]] = '*'
				}
				i = j
				continue
			}
			// Skip past the entire digit sequence to avoid
			// re-scanning substrings of the same number.
			i = j
			continue
		}
		i++
	}
	return string(result)
}

// luhnCheck validates a sequence of ASCII digit bytes using the Luhn algorithm.
func luhnCheck(digits []byte) bool {
	if len(digits) < 2 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// isDigit returns true if b is an ASCII digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// MaskSSN masks Social Security Number patterns (XXX-XX-XXXX) in text.
func MaskSSN(s string) string {
	result := []byte(s)
	i := 0
	for i < len(result)-10 {
		// Check for pattern: 3 digits, dash, 2 digits, dash, 4 digits
		if i+10 < len(result) &&
			isDigit(result[i]) && isDigit(result[i+1]) && isDigit(result[i+2]) &&
			result[i+3] == '-' &&
			isDigit(result[i+4]) && isDigit(result[i+5]) &&
			result[i+6] == '-' &&
			isDigit(result[i+7]) && isDigit(result[i+8]) && isDigit(result[i+9]) && isDigit(result[i+10]) {

			// Validate it is not all zeros in any group
			g1 := string(result[i : i+3])
			g2 := string(result[i+4 : i+6])
			g3 := string(result[i+7 : i+11])
			if g1 != "000" && g2 != "00" && g3 != "0000" && g1 != "666" && result[i] != '9' {
				// Mask: ***-**-XXXX (preserve last 4)
				result[i] = '*'
				result[i+1] = '*'
				result[i+2] = '*'
				result[i+4] = '*'
				result[i+5] = '*'
				i += 11
				continue
			}
		}
		i++
	}
	return string(result)
}

// MaskAPIKeys masks common API key patterns in text.
// Looks for key/token/secret keywords followed by long hex/alphanumeric strings.
func MaskAPIKeys(s string) string {
	lower := strings.ToLower(s)
	result := []byte(s)

	keywords := []string{"key", "token", "secret", "apikey", "api_key", "api-key", "access_token", "auth_token", "password"}

	for _, kw := range keywords {
		searchFrom := 0
		for {
			idx := strings.Index(lower[searchFrom:], kw)
			if idx < 0 {
				break
			}
			pos := searchFrom + idx + len(kw)
			searchFrom = pos

			// Skip separators: = : " ' space
			for pos < len(result) && (result[pos] == '=' || result[pos] == ':' || result[pos] == '"' || result[pos] == '\'' || result[pos] == ' ' || result[pos] == '\t') {
				pos++
			}

			// Find the key value: alphanumeric, dash, underscore
			start := pos
			for pos < len(result) && isKeyChar(result[pos]) {
				pos++
			}

			keyLen := pos - start
			// Only mask if key is long enough to be a real key (16+ chars)
			if keyLen >= 16 {
				// Show first 4 and last 4, mask the rest
				maskStart := start + 4
				maskEnd := pos - 4
				if maskEnd <= maskStart {
					// Too short to show both ends, mask everything
					maskStart = start
					maskEnd = pos
				}
				for k := maskStart; k < maskEnd; k++ {
					result[k] = '*'
				}
			}
		}
	}
	return string(result)
}

// isKeyChar returns true if b is a valid character in an API key value.
func isKeyChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

// StripStackTraces removes common stack trace patterns from response text.
// Handles Go, Java, Python, and Node.js stack trace formats.
func StripStackTraces(s string) string {
	lines := strings.Split(s, "\n")
	var filtered []string
	inStackTrace := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Detect start of stack traces
		if isStackTraceStart(trimmed) {
			inStackTrace = true
			continue
		}

		// Detect continuation of stack traces
		if inStackTrace {
			if isStackTraceLine(trimmed) {
				continue
			}
			// End of stack trace
			inStackTrace = false
		}

		// Check if this single line is a stack trace line
		if isStackTraceLine(trimmed) {
			continue
		}

		filtered = append(filtered, line)
	}

	return strings.Join(filtered, "\n")
}

// isStackTraceStart detects the beginning of a stack trace.
func isStackTraceStart(line string) bool {
	lower := strings.ToLower(line)

	// Go: "goroutine N [...]:" pattern
	if strings.HasPrefix(lower, "goroutine ") && strings.Contains(line, "[") {
		return true
	}

	// Java: exception class names
	if strings.Contains(line, "Exception") && strings.Contains(line, ".") {
		return true
	}

	// Python: "Traceback (most recent call last):"
	if strings.HasPrefix(lower, "traceback") {
		return true
	}

	// Node.js / generic: "Error:" at start
	if strings.HasPrefix(line, "Error:") || strings.HasPrefix(line, "TypeError:") ||
		strings.HasPrefix(line, "ReferenceError:") || strings.HasPrefix(line, "SyntaxError:") {
		return true
	}

	return false
}

// isStackTraceLine detects individual stack trace frame lines.
func isStackTraceLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// Go: path/to/file.go:123 +0xABC
	if strings.Contains(trimmed, ".go:") && (strings.Contains(trimmed, "+0x") || strings.Contains(trimmed, "()")) {
		return true
	}

	// Java: "at package.Class.method(File.java:123)"
	if strings.HasPrefix(trimmed, "at ") && strings.Contains(trimmed, "(") && strings.Contains(trimmed, ".java:") {
		return true
	}

	// Python: "File \"...\", line N, in ..."
	if strings.HasPrefix(trimmed, "File \"") && strings.Contains(trimmed, ", line ") {
		return true
	}

	// Node.js: "at functionName (path:line:col)"
	if strings.HasPrefix(trimmed, "at ") && (strings.Contains(trimmed, ".js:") || strings.Contains(trimmed, ".ts:")) {
		return true
	}

	return false
}
