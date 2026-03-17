package sanitizer

import (
	"strings"
	"unicode/utf8"
)

// DecodeURLRecursive repeatedly URL-decodes until stable (max 5 iterations).
// Handles %XX and %uXXXX encoding.
func DecodeURLRecursive(s string) string {
	const maxIterations = 5
	for range maxIterations {
		decoded := decodeURLOnce(s)
		if decoded == s {
			return decoded
		}
		s = decoded
	}
	return s
}

// decodeURLOnce performs a single pass of URL decoding, handling both %XX and %uXXXX.
func decodeURLOnce(s string) string {
	// Quick check: if no '%' is present, nothing to decode.
	if !strings.Contains(s, "%") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}

		// Try %uXXXX (Unicode escape)
		if i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if h, ok := hexVal(s[i+2]); ok {
				if h2, ok2 := hexVal(s[i+3]); ok2 {
					if h3, ok3 := hexVal(s[i+4]); ok3 {
						if h4, ok4 := hexVal(s[i+5]); ok4 {
							r := rune(h<<12 | h2<<8 | h3<<4 | h4)
							b.WriteRune(r)
							i += 6
							continue
						}
					}
				}
			}
		}

		// Try %XX
		if i+2 < len(s) {
			if h, ok := hexVal(s[i+1]); ok {
				if h2, ok2 := hexVal(s[i+2]); ok2 {
					b.WriteByte(byte(h<<4 | h2))
					i += 3
					continue
				}
			}
		}

		// Not a valid encoding, keep the '%' as-is
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hexVal returns the numeric value of a hex character and whether it is valid.
func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	default:
		return 0, false
	}
}

// RemoveNullBytes strips \x00, %00, and \0 from input.
func RemoveNullBytes(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		// Literal null byte
		if s[i] == 0 {
			i++
			continue
		}

		// %00 sequence
		if s[i] == '%' && i+2 < len(s) && s[i+1] == '0' && s[i+2] == '0' {
			i += 3
			continue
		}

		// Backslash-zero sequence: \0
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '0' {
			i += 2
			continue
		}

		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// CanonicalizePath resolves ../, ./, //, trailing dots.
func CanonicalizePath(s string) string {
	if s == "" {
		return s
	}

	// Normalize backslashes to forward slashes first
	s = strings.ReplaceAll(s, "\\", "/")

	// Preserve leading slash
	hasLeadingSlash := len(s) > 0 && s[0] == '/'

	parts := strings.Split(s, "/")
	var resolved []string

	for _, part := range parts {
		switch part {
		case "", ".":
			// Skip empty segments (from // or ./)
			continue
		case "..":
			// Go up one level, but don't go above root
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		default:
			// Remove trailing dots from path segments
			cleaned := strings.TrimRight(part, ".")
			if cleaned == "" {
				continue
			}
			resolved = append(resolved, cleaned)
		}
	}

	result := strings.Join(resolved, "/")
	if hasLeadingSlash {
		result = "/" + result
	}
	if result == "" {
		return "/"
	}
	return result
}

// NormalizeUnicode maps fullwidth characters to ASCII equivalents.
// Handles fullwidth A-Z (U+FF21-FF3A), a-z (U+FF41-FF5A), 0-9 (U+FF10-FF19),
// and common symbols (U+FF01-FF0F).
func NormalizeUnicode(s string) string {
	// Quick check: if it's all ASCII, no work needed
	if isASCII(s) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteByte(s[i])
			i++
			continue
		}

		mapped := mapFullwidthToASCII(r)
		b.WriteRune(mapped)
		i += size
	}
	return b.String()
}

// isASCII checks if the string contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// mapFullwidthToASCII maps a fullwidth rune to its ASCII equivalent.
// If not a fullwidth character, returns the original rune.
func mapFullwidthToASCII(r rune) rune {
	switch {
	// Fullwidth digits 0-9: U+FF10-U+FF19 -> '0'-'9'
	case r >= 0xFF10 && r <= 0xFF19:
		return rune('0') + (r - 0xFF10)
	// Fullwidth uppercase A-Z: U+FF21-U+FF3A -> 'A'-'Z'
	case r >= 0xFF21 && r <= 0xFF3A:
		return rune('A') + (r - 0xFF21)
	// Fullwidth lowercase a-z: U+FF41-U+FF5A -> 'a'-'z'
	case r >= 0xFF41 && r <= 0xFF5A:
		return rune('a') + (r - 0xFF41)
	// Fullwidth symbols: U+FF01-U+FF0F -> '!'-'/'
	// FF01 = !, FF02 = ", FF03 = #, ... FF0F = /
	case r >= 0xFF01 && r <= 0xFF0F:
		return rune('!') + (r - 0xFF01)
	default:
		return r
	}
}

// DecodeHTMLEntities decodes &amp; &lt; &gt; &quot; &#xNN; &#NNN;
func DecodeHTMLEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}

		// Try to find the semicolon
		end := -1
		maxSearch := min(i+12, len(s)) // Named entities are at most ~10 chars
		for j := i + 1; j < maxSearch; j++ {
			if s[j] == ';' {
				end = j
				break
			}
		}
		if end == -1 {
			b.WriteByte(s[i])
			i++
			continue
		}

		entity := s[i+1 : end]

		// Numeric character reference &#...
		if len(entity) >= 2 && entity[0] == '#' {
			if entity[1] == 'x' || entity[1] == 'X' {
				// Hex: &#xNN;
				if val, ok := parseHexEntity(entity[2:]); ok {
					b.WriteRune(rune(val))
					i = end + 1
					continue
				}
			} else {
				// Decimal: &#NNN;
				if val, ok := parseDecEntity(entity[1:]); ok {
					b.WriteRune(rune(val))
					i = end + 1
					continue
				}
			}
		}

		// Named entity
		if decoded, ok := namedEntities[entity]; ok {
			b.WriteRune(decoded)
			i = end + 1
			continue
		}

		// Unknown entity, keep as-is
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// namedEntities maps common HTML entity names to their rune values.
var namedEntities = map[string]rune{
	"amp":   '&',
	"lt":    '<',
	"gt":    '>',
	"quot":  '"',
	"apos":  '\'',
	"nbsp":  '\u00A0',
	"tab":   '\t',
	"newl":  '\n',
	"colon": ':',
	"semi":  ';',
}

// parseHexEntity parses a hex numeric character reference value.
func parseHexEntity(s string) (int, bool) {
	if len(s) == 0 || len(s) > 6 {
		return 0, false
	}
	val := 0
	for _, c := range []byte(s) {
		h, ok := hexVal(c)
		if !ok {
			return 0, false
		}
		val = val*16 + h
	}
	return val, true
}

// parseDecEntity parses a decimal numeric character reference value.
func parseDecEntity(s string) (int, bool) {
	if len(s) == 0 || len(s) > 7 {
		return 0, false
	}
	val := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		val = val*10 + int(c-'0')
	}
	return val, true
}

// NormalizeCase returns lowercase for detection comparison.
func NormalizeCase(s string) string {
	return strings.ToLower(s)
}

// NormalizeWhitespace collapses runs of whitespace/control chars to single space, trims.
func NormalizeWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	inSpace := true // Start true to trim leading whitespace
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isWhitespaceOrControl(c) {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		b.WriteByte(c)
		inSpace = false
	}

	result := b.String()
	// Trim trailing space (from the last whitespace run)
	if len(result) > 0 && result[len(result)-1] == ' ' {
		result = result[:len(result)-1]
	}
	return result
}

// isWhitespaceOrControl returns true if the byte is whitespace or a control character.
func isWhitespaceOrControl(c byte) bool {
	return c <= 0x20 || c == 0x7F
}

// NormalizeBackslashes converts \ to / for path comparison.
func NormalizeBackslashes(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}

// NormalizeAll chains all normalization functions in the correct order:
// 1. URL decode recursive
// 2. Null byte removal
// 3. Path canonicalization
// 4. Unicode normalization
// 5. HTML entity decode
// 6. Whitespace normalization
// 7. Backslash normalization
// (Case normalization is separate - applied only for comparison)
func NormalizeAll(s string) string {
	s = DecodeURLRecursive(s)
	s = RemoveNullBytes(s)
	s = CanonicalizePath(s)
	s = NormalizeUnicode(s)
	s = DecodeHTMLEntities(s)
	s = NormalizeWhitespace(s)
	s = NormalizeBackslashes(s)
	return s
}
