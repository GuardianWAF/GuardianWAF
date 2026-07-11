package xss

import (
	"strings"
)

// htmlTag represents a minimal parsed HTML tag found during scanning.
type htmlTag struct {
	Name       string            // lowercase tag name, e.g. "script", "img"
	Attributes map[string]string // lowercase attr name -> raw value
	RawMatch   string            // the raw text that was matched
}

// scanTags scans input for HTML-like tags and returns all tags found.
// This is intentionally NOT a full HTML parser -- it is an attack-surface
// scanner that extracts tag names and attributes from angle-bracket sequences.
func scanTags(input string) []htmlTag {
	var tags []htmlTag
	i := 0
	for i < len(input) {
		idx := strings.IndexByte(input[i:], '<')
		if idx < 0 {
			break
		}
		start := i + idx
		i = start + 1
		if i >= len(input) {
			break
		}

		// Skip closing tags (</...)
		if input[i] == '/' {
			// still extract it for completeness
			i++
		}

		// Extract tag name: read until whitespace, /, or >
		nameStart := i
		for i < len(input) && input[i] != ' ' && input[i] != '\t' &&
			input[i] != '\n' && input[i] != '\r' && input[i] != '>' &&
			input[i] != '/' && input[i] != '\x00' {
			i++
		}
		if i == nameStart {
			continue
		}
		tagName := strings.ToLower(input[nameStart:i])

		// Now parse attributes until we hit '>' or end of input
		attrs := make(map[string]string)
		for i < len(input) && input[i] != '>' {
			// Skip whitespace and null bytes
			if input[i] == ' ' || input[i] == '\t' || input[i] == '\n' ||
				input[i] == '\r' || input[i] == '\x00' || input[i] == '/' {
				i++
				continue
			}

			// Read attribute name
			attrStart := i
			for i < len(input) && input[i] != '=' && input[i] != ' ' &&
				input[i] != '\t' && input[i] != '>' && input[i] != '\x00' {
				i++
			}
			if i == attrStart {
				i++
				continue
			}
			attrName := strings.ToLower(input[attrStart:i])

			// Check for = sign
			attrVal := ""
			// Skip whitespace before =
			for i < len(input) && (input[i] == ' ' || input[i] == '\t' || input[i] == '\x00') {
				i++
			}
			if i < len(input) && input[i] == '=' {
				i++ // skip =
				// Skip whitespace after =
				for i < len(input) && (input[i] == ' ' || input[i] == '\t' || input[i] == '\x00') {
					i++
				}
				if i < len(input) && input[i] != '>' {
					if input[i] == '"' || input[i] == '\'' {
						quote := input[i]
						i++ // skip opening quote
						valStart := i
						for i < len(input) && input[i] != quote {
							i++
						}
						attrVal = input[valStart:i]
						if i < len(input) {
							i++ // skip closing quote
						}
					} else {
						// Unquoted attribute value
						valStart := i
						for i < len(input) && input[i] != ' ' && input[i] != '\t' &&
							input[i] != '>' && input[i] != '\x00' {
							i++
						}
						attrVal = input[valStart:i]
					}
				}
			}
			attrs[attrName] = attrVal
		}
		if i < len(input) && input[i] == '>' {
			i++ // skip >
		}

		end := i
		rawMatch := input[start:end]

		tags = append(tags, htmlTag{
			Name:       tagName,
			Attributes: attrs,
			RawMatch:   rawMatch,
		})
	}
	return tags
}

// hasEventHandler checks if any attribute starts with "on" followed by
// a lowercase letter (e.g., onclick, onerror, onload).
func hasEventHandler(attrs map[string]string) (string, bool) {
	for name := range attrs {
		if len(name) > 2 && name[0] == 'o' && name[1] == 'n' &&
			name[2] >= 'a' && name[2] <= 'z' {
			return name, true
		}
	}
	return "", false
}

// hasJavaScriptProtocol checks if any attribute value contains "javascript:" or
// "data:text/html" protocol.
func hasJavaScriptProtocol(attrs map[string]string) (attrName, protocol string, found bool) {
	for name, val := range attrs {
		lower := strings.ToLower(val)
		if strings.Contains(lower, "javascript:") {
			return name, "javascript:", true
		}
		if strings.Contains(lower, "data:text/html") {
			return name, "data:text/html", true
		}
	}
	return "", "", false
}

// detectTemplateInjection scans input for template injection markers with
// executable or probing content. Plain template variables such as
// "{{ user_name }}" and "${HOME}" are common in documentation and legitimate
// templates, so delimiters alone are not enough to report XSS.
func detectTemplateInjection(input string) []string {
	var found []string
	patterns := []string{"{{", "${", "#{"}
	for _, p := range patterns {
		if hasDangerousTemplateExpression(input, p) {
			found = append(found, p)
		}
	}
	return found
}

func hasDangerousTemplateExpression(input, open string) bool {
	lower := strings.ToLower(input)
	for from := 0; ; {
		idx := strings.Index(lower[from:], open)
		if idx < 0 {
			return false
		}
		start := from + idx + len(open)
		end := start + 96
		if end > len(lower) {
			end = len(lower)
		}
		body := lower[start:end]
		if hasTemplateArithmeticProbe(body) || hasTemplateExecutionToken(body) {
			return true
		}
		from = start
	}
}

func hasTemplateArithmeticProbe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '*' {
			continue
		}
		l := i - 1
		for l >= 0 && s[l] == ' ' {
			l--
		}
		if l < 0 || s[l] < '0' || s[l] > '9' {
			continue
		}
		r := i + 1
		for r < len(s) && s[r] == ' ' {
			r++
		}
		if r < len(s) && (s[r] == '\'' || s[r] == '"') {
			r++
		}
		if r < len(s) && s[r] >= '0' && s[r] <= '9' {
			return true
		}
	}
	return false
}

func hasTemplateExecutionToken(s string) bool {
	dangerous := []string{
		"alert(",
		"constructor",
		"eval(",
		"function(",
		"=>",
		"document.cookie",
		"document.write",
		"innerhtml",
		"javascript:",
		"location=",
		"window.",
		"system(",
		"exec(",
		"process.",
		"require(",
		"import(",
		"onerror",
		"onload",
	}
	for _, token := range dangerous {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}

// detectEncodedLT scans for encoded < variants that may be used to evade
// detection. Returns true if any encoding is found.
// Patterns: &#60, &#x3c, &#x3C, \x3c, \x3C, \u003c, \u003C, %3c, %3C
func detectEncodedLT(input string) bool {
	lower := strings.ToLower(input)
	encodedPatterns := []string{
		"&#60",    // HTML decimal entity
		"&#x3c",   // HTML hex entity
		"\\x3c",   // JS hex escape
		"\\u003c", // JS unicode escape
		"%3c",     // URL encoding
	}
	for _, p := range encodedPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// decodeCommonEncodings attempts to decode common encoding schemes used to
// evade XSS filters. It handles:
//   - \xHH (JS hex escapes)
//   - \uHHHH (JS unicode escapes)
//   - %HH (URL encoding)
//   - &#DD; / &#xHH; (HTML entities)
//
// It returns the decoded string. Non-decodable sequences are left as-is.
func decodeCommonEncodings(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// JS hex escape: \xHH
		if i+3 < len(s) && s[i] == '\\' && (s[i+1] == 'x' || s[i+1] == 'X') {
			hi := hexVal(s[i+2])
			lo := hexVal(s[i+3])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(hexPairByte(hi, lo))
				i += 4
				continue
			}
		}
		// JS unicode escape: \uHHHH
		if i+5 < len(s) && s[i] == '\\' && (s[i+1] == 'u' || s[i+1] == 'U') {
			h1 := hexVal(s[i+2])
			h2 := hexVal(s[i+3])
			h3 := hexVal(s[i+4])
			h4 := hexVal(s[i+5])
			if h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0 {
				b.WriteRune(codePointRune((h1 << 12) | (h2 << 8) | (h3 << 4) | h4))
				i += 6
				continue
			}
		}
		// URL encoding: %HH
		if i+2 < len(s) && s[i] == '%' {
			hi := hexVal(s[i+1])
			lo := hexVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(hexPairByte(hi, lo))
				i += 3
				continue
			}
		}
		// HTML decimal entity: &#DD; or &#DD (semicolon optional)
		if i+3 < len(s) && s[i] == '&' && s[i+1] == '#' && s[i+2] >= '0' && s[i+2] <= '9' {
			j := i + 2
			val := 0
			for j < len(s) && s[j] >= '0' && s[j] <= '9' && val < 0x110000 {
				val = val*10 + int(s[j]-'0')
				j++
			}
			if j > i+2 && val > 0 && val < 0x110000 {
				if j < len(s) && s[j] == ';' {
					j++
				}
				b.WriteRune(codePointRune(val))
				i = j
				continue
			}
		}
		// HTML hex entity: &#xHH; or &#xHH (semicolon optional)
		if i+4 < len(s) && s[i] == '&' && s[i+1] == '#' && (s[i+2] == 'x' || s[i+2] == 'X') {
			j := i + 3
			val := 0
			for j < len(s) && hexVal(s[j]) >= 0 && val < 0x110000 {
				val = val<<4 | hexVal(s[j])
				j++
			}
			if j > i+3 && val > 0 && val < 0x110000 {
				if j < len(s) && s[j] == ';' {
					j++
				}
				b.WriteRune(codePointRune(val))
				i = j
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hexVal returns the numeric value of a hex digit, or -1 if not a hex digit.
func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

func hexPairByte(hi, lo int) byte {
	// #nosec G115 -- hexVal constrains each nibble to 0..15 before this byte narrowing.
	return byte((hi << 4) | lo)
}

func codePointRune(val int) rune {
	if val <= 0 || val >= 0x110000 {
		return '\uFFFD'
	}
	// #nosec G115 -- val is bounded to the Unicode scalar range above.
	return rune(val)
}

// removeNullBytes strips null bytes from input. Attackers insert null bytes
// between tag characters to evade simple pattern matching (e.g., <\x00script>).
func removeNullBytes(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != 0 {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
