package crs

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
	"github.com/guardianwaf/guardianwaf/internal/regexsafe"
)

// regexCache caches compiled regex patterns to avoid recompilation per request.
var (
	regexCache     sync.Map     // string → *regexp.Regexp
	regexCacheSize atomic.Int64 // track cache size for cap enforcement
)

const maxRegexCacheSize = 10000 // cap regex cache to prevent unbounded growth

// matchWithTimeout evaluates a regex match under the process-wide regexsafe
// budget (per-regex 500ms ceiling, per-request 2s total, semaphore cap 500).
// This replaces the previous C3 path (5s ceiling, no semaphore, no
// fail-closed, no per-request budget) which allowed a single request to
// keep a goroutine alive for 5s and a flood of slow matches to spawn
// unbounded goroutines — both exploitable for CPU exhaustion.
//
// d is the per-request regexsafe.Deadline created by the CRS layer
// Process call. A nil deadline means "no budget tracking" (tests).
//
// Returns nil when the regex does not match, the budget/semaphore is
// exhausted, or the per-regex timeout fires. Callers must treat nil as
// "no match"; this is the correct behavior for CRS SecRules where
// absence of a match means the rule did not fire (CRS is explicit
// allow/deny, not fail-closed-by-default).
func matchWithTimeout(re *regexp.Regexp, s string, d ...*regexsafe.Deadline) []string {
	var deadline *regexsafe.Deadline
	if len(d) > 0 {
		deadline = d[0]
	}
	return regexsafe.FindSubmatch(re, s, deadline)
}

// matchWithDeadline is retained for tests that need a custom timeout
// without a per-request deadline. Production callers should use
// matchWithTimeout (which threads the shared regexsafe.Deadline and
// semaphore).
func matchWithDeadline(re *regexp.Regexp, s string, timeout time.Duration) []string {
	// Create a one-shot deadline whose remaining budget equals the
	// requested timeout. This lets tests verify timeout behavior while
	// still routing through the shared regexsafe budget/semaphore.
	deadline := &regexsafe.Deadline{}
	deadline.SetTestDeadline(timeout)
	return regexsafe.FindSubmatch(re, s, deadline)
}

func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := regexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Enforce cache cap — if over limit, return compiled regex without caching
	if regexCacheSize.Load() >= maxRegexCacheSize {
		return re, nil
	}
	if _, loaded := regexCache.LoadOrStore(pattern, re); !loaded {
		regexCacheSize.Add(1)
	}
	actual, _ := regexCache.Load(pattern)
	return actual.(*regexp.Regexp), nil
}

// OperatorEvaluator evaluates SecRule operators against values.
type OperatorEvaluator struct {
	captureGroups []string

	// deadline is the per-request regexsafe budget shared by every
	// @rx evaluation in this transaction. A nil deadline means "no
	// budget tracking" (the production path always sets one; test
	// paths that bypass Process may leave it nil).
	deadline *regexsafe.Deadline
}

// NewOperatorEvaluator creates a new operator evaluator.
func NewOperatorEvaluator() *OperatorEvaluator {
	return &OperatorEvaluator{
		captureGroups: []string{},
	}
}

// SetDeadline installs the per-request regexsafe deadline that bounds
// @rx evaluations. Each Process call must create a fresh deadline;
// the same deadline must not be reused across requests.
func (oe *OperatorEvaluator) SetDeadline(d *regexsafe.Deadline) {
	oe.deadline = d
}

// Evaluate evaluates an operator against a value.
func (oe *OperatorEvaluator) Evaluate(op RuleOperator, value string) (bool, error) {
	// Apply transformation if any (simplified - transformations should be applied before)
	transformedValue := value

	// Handle negation at the end
	result, err := oe.evaluateOperator(op.Type, op.Argument, transformedValue)
	if err != nil {
		return false, err
	}

	if op.Negated {
		return !result, nil
	}

	return result, nil
}

// evaluateOperator evaluates the specific operator.
func (oe *OperatorEvaluator) evaluateOperator(opType, argument, value string) (bool, error) {
	switch opType {
	case "@rx":
		return oe.evaluateRx(argument, value)
	case "@eq":
		return value == argument, nil
	case "@streq":
		return value == argument, nil
	case "@contains":
		return strings.Contains(value, argument), nil
	case "@beginsWith":
		return strings.HasPrefix(value, argument), nil
	case "@endsWith":
		return strings.HasSuffix(value, argument), nil
	case "@ge":
		return oe.compareNumeric(value, argument, ">=")
	case "@le":
		return oe.compareNumeric(value, argument, "<=")
	case "@gt":
		return oe.compareNumeric(value, argument, ">")
	case "@lt":
		return oe.compareNumeric(value, argument, "<")
	case "@pm":
		return oe.evaluatePm(argument, value)
	case "@pmf":
		return oe.evaluatePmFromFile(argument, value)
	case "@within":
		return oe.evaluateWithin(argument, value)
	case "@ipMatch":
		return oe.evaluateIpMatch(argument, value)
	case "@ipMatchF":
		return oe.evaluateIpMatchFromFile(argument, value)
	case "@validateByteRange":
		return oe.evaluateByteRange(argument, value)
	case "@validateUrlEncoding":
		return oe.evaluateUrlEncoding(value)
	case "@validateUtf8Encoding":
		return oe.evaluateUtf8Encoding(value)
	default:
		// Unknown operator - try regex as default
		return oe.evaluateRx(opType, value)
	}
}

// evaluatePmFromFile evaluates the @pmf (phrase match from file) operator.
// The argument is normally a file path whose non-comment lines contribute
// phrases; when the path is not a readable file the argument itself is
// treated as a space-separated inline phrase list (the documented fallback).
func (oe *OperatorEvaluator) evaluatePmFromFile(argument, value string) (bool, error) {
	content, err := os.ReadFile(argument)
	if err != nil {
		return oe.evaluatePm(argument, value)
	}
	for _, phrase := range fileLines(content) {
		if strings.Contains(value, phrase) {
			return true, nil
		}
	}
	return false, nil
}

// evaluateIpMatchFromFile evaluates the @ipMatchF (IP match from file)
// operator. The argument is a file path; each non-comment line is an IP or
// CIDR network matched against the value.
func (oe *OperatorEvaluator) evaluateIpMatchFromFile(argument, value string) (bool, error) {
	content, err := os.ReadFile(argument)
	if err != nil {
		return false, fmt.Errorf("ipMatchF: reading IP file: %w", err)
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false, nil
	}
	for _, entry := range fileLines(content) {
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true, nil
			}
			continue
		}
		if parsed := net.ParseIP(entry); parsed != nil && parsed.String() == ip.String() {
			return true, nil
		}
	}
	return false, nil
}

// fileLines returns the non-empty, non-comment lines of a from-file
// operator's data file.
func fileLines(content []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// evaluateRx evaluates the @rx (regex) operator.
func (oe *OperatorEvaluator) evaluateRx(pattern, value string) (bool, error) {
	re, err := getCachedRegex(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Use timeout-wrapped matching to prevent CPU monopolization (H6 fix).
	// Thread the per-request deadline so the regexsafe budget (2s total,
	// 500ms per regex, semaphore cap 500) is actually enforced on the
	// production path. When the deadline is exhausted, FindSubmatch
	// returns nil and the rule does not fire — the documented CRS
	// behavior (no match => rule did not fire).
	matches := matchWithTimeout(re, value, oe.deadline)
	if matches == nil {
		return false, nil
	}

	// Store capture groups
	oe.captureGroups = matches
	return true, nil
}

// evaluatePm evaluates the @pm (phrase match) operator.
// Argument is space-separated phrases to match
func (oe *OperatorEvaluator) evaluatePm(argument, value string) (bool, error) {
	// Split argument into phrases
	phrases := strings.Fields(argument)
	if len(phrases) == 0 {
		return false, nil
	}

	// Try to match any phrase
	for _, phrase := range phrases {
		// Remove quotes if present
		phrase = strings.Trim(phrase, "\"'")
		if strings.Contains(value, phrase) {
			return true, nil
		}
	}

	return false, nil
}

// evaluateWithin evaluates the @within operator.
// Argument is space-separated values, value must be one of them
func (oe *OperatorEvaluator) evaluateWithin(argument, value string) (bool, error) {
	// Split argument into allowed values
	allowed := strings.Fields(argument)
	if len(allowed) == 0 {
		return false, nil
	}

	// Check if value is in allowed list
	for _, allowedVal := range allowed {
		allowedVal = strings.Trim(allowedVal, "\"'")
		if value == allowedVal {
			return true, nil
		}
	}

	return false, nil
}

// evaluateIpMatch evaluates the @ipMatch operator.
func (oe *OperatorEvaluator) evaluateIpMatch(argument, value string) (bool, error) {
	// Parse the IP to check
	ip := net.ParseIP(value)
	if ip == nil {
		// Try as hostname - resolve
		ips, err := net.LookupIP(value)
		if err != nil || len(ips) == 0 {
			return false, nil
		}
		ip = ips[0]
	}

	// Parse allowed networks
	networks := strings.Fields(argument)
	for _, network := range networks {
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			// Try as single IP
			targetIP := net.ParseIP(network)
			if targetIP != nil && ip.Equal(targetIP) {
				return true, nil
			}
			continue
		}

		if ipNet.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// evaluateByteRange evaluates the @validateByteRange operator.
// Format: 1-255 or 1-255,32-47
func (oe *OperatorEvaluator) evaluateByteRange(argument, value string) (bool, error) {
	// Parse byte ranges
	ranges := parseByteRanges(argument)

	// Check each byte in value
	for i := 0; i < len(value); i++ {
		b := value[i]
		valid := false
		for _, r := range ranges {
			if int(b) >= r.min && int(b) <= r.max {
				valid = true
				break
			}
		}
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// evaluateUrlEncoding validates URL encoding in value.
func (oe *OperatorEvaluator) evaluateUrlEncoding(value string) (bool, error) {
	// Check for invalid URL encoding
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if i+2 >= len(value) {
				return false, nil // Incomplete escape
			}
			// Check if next two chars are valid hex digits. ParseInt with
			// base 16 still honours a leading sign ("-1"/"+5"), which would
			// treat invalid escapes as valid, so verify the digits directly.
			if !isHexDigit(value[i+1]) || !isHexDigit(value[i+2]) {
				return false, nil
			}
		}
	}
	return true, nil
}

// isHexDigit reports whether b is an ASCII hexadecimal digit.
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// evaluateUtf8Encoding validates UTF-8 encoding in value.
func (oe *OperatorEvaluator) evaluateUtf8Encoding(value string) (bool, error) {
	// Check if value is valid UTF-8
	return isValidUTF8(value), nil
}

// compareNumeric compares numeric values.
func (oe *OperatorEvaluator) compareNumeric(value, argument, op string) (bool, error) {
	valNum, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, err
	}

	argNum, err := strconv.ParseFloat(argument, 64)
	if err != nil {
		return false, err
	}

	switch op {
	case "==":
		return valNum == argNum, nil
	case "!=":
		return valNum != argNum, nil
	case ">":
		return valNum > argNum, nil
	case ">=":
		return valNum >= argNum, nil
	case "<":
		return valNum < argNum, nil
	case "<=":
		return valNum <= argNum, nil
	default:
		return false, fmt.Errorf("unknown comparison operator: %s", op)
	}
}

// GetCaptureGroups returns the last regex capture groups.
func (oe *OperatorEvaluator) GetCaptureGroups() []string {
	return oe.captureGroups
}

// byteRange represents a byte range.
type byteRange struct {
	min int
	max int
}

// parseByteRanges parses byte range specifications.
func parseByteRanges(s string) []byteRange {
	ranges := []byteRange{}

	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse range (e.g., "1-255" or "32")
		if idx := strings.Index(part, "-"); idx > 0 {
			min, _ := strconv.Atoi(part[:idx])
			max, _ := strconv.Atoi(part[idx+1:])
			ranges = append(ranges, byteRange{min: min, max: max})
		} else {
			// Single byte
			val, _ := strconv.Atoi(part)
			ranges = append(ranges, byteRange{min: val, max: val})
		}
	}

	return ranges
}

// isValidUTF8 checks if a string is valid UTF-8.
func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD { // Replacement character
			return false
		}
	}
	return true
}

// Transform applies transformations to a value.
func Transform(value string, transformations []string) string {
	result := value

	for _, t := range transformations {
		switch t {
		case "lowercase", "t:lowercase":
			result = strings.ToLower(result)
		case "uppercase", "t:uppercase":
			result = strings.ToUpper(result)
		case "urlDecode", "t:urlDecode":
			result = urlDecode(result)
		case "urlDecodeUni", "t:urlDecodeUni":
			result = urlDecodeUni(result)
		case "urlEncode", "t:urlEncode":
			result = urlEncode(result)
		case "htmlEntityDecode", "t:htmlEntityDecode":
			result = htmlEntityDecode(result)
		case "removeWhitespace", "t:removeWhitespace":
			result = removeWhitespace(result)
		case "trim", "t:trim":
			// C-locale whitespace set only (ModSecurity t:trim parity): the
			// previous strings.TrimSpace stripped the full Unicode set,
			// silently removing NBSP, em space and similar edge characters
			// that ModSecurity preserves. Matches removeWhitespace (round 9).
			result = strings.Trim(result, " \t\n\v\f\r")
		case "removeNulls", "t:removeNulls":
			result = strings.ReplaceAll(result, "\x00", "")
		case "replaceNulls", "t:replaceNulls":
			result = strings.ReplaceAll(result, "\x00", " ")
		}
	}

	return result
}

// urlDecode decodes URL-encoded string (full percent-decoding).
func urlDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, okHi := hexVal(s[i+1])
			lo, okLo := hexVal(s[i+2])
			if okHi && okLo {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// hexVal returns the hex digit value and true if c is a valid hex char.
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// urlDecodeUni decodes percent-encoding including the legacy %uXXXX UTF-16
// form (ModSecurity's urlDecodeUni): %XX bytes decode as in urlDecode, and
// %uXXXX code units decode to UTF-8, with a %uD800-%uDBFF high surrogate
// followed by a %uDC00-%uDFFF low surrogate combining into one astral code
// point. Only the lowercase-u IE form is honored (%U stays literal); invalid
// sequences stay literal, matching urlDecode's handling.
func urlDecodeUni(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		// Legacy %uXXXX UTF-16 code unit.
		if s[i+1] == 'u' && i+6 <= len(s) {
			if r, ok := decodeHexWord(s[i+2 : i+6]); ok {
				// Combine a UTF-16 surrogate pair: %uD83D%uDE00 → one rune.
				if r >= 0xD800 && r <= 0xDBFF && i+12 <= len(s) && s[i+6] == '%' && s[i+7] == 'u' {
					if lo, okLo := decodeHexWord(s[i+8 : i+12]); okLo && lo >= 0xDC00 && lo <= 0xDFFF {
						b.WriteRune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))
						i += 11
						continue
					}
				}
				b.WriteRune(r) // unpaired surrogate → U+FFFD (Go WriteRune semantics)
				i += 5
				continue
			}
		}
		// Standard %XX.
		if i+2 < len(s) {
			hi, okHi := hexVal(s[i+1])
			lo, okLo := hexVal(s[i+2])
			if okHi && okLo {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeHexWord parses exactly 4 hex digits into a UTF-16 code unit.
func decodeHexWord(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var v rune
	for j := 0; j < 4; j++ {
		h, ok := hexVal(s[j])
		if !ok {
			return 0, false
		}
		v = v<<4 | rune(h)
	}
	return v, true
}

// urlEncode URL-encodes a string: every byte outside the RFC 3986 unreserved
// set (alphanumerics, '-', '.', '_', '~') is percent-encoded with uppercase
// hex, matching ModSecurity's t:urlEncode. The previous implementation only
// replaced spaces, leaving reserved characters ('/', '"', '%', '<', ...) and
// non-ASCII bytes raw.
func urlEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0F])
	}
	return b.String()
}

// htmlEntityDecode decodes HTML entities. It delegates to the sanitizer's
// canonical decoder so CRS transform chains get the same entity coverage as
// sanitizer-side normalization: numeric character references (&#x3C; hex,
// &#60; decimal) and whitespace entities (&Tab;, &NewLine;) in addition to
// the named entities. The previous 5-replacement stub left
// "&#x3C;script&#x3E;" and "jav&Tab;ascript:..." undecoded, so CRS rules with
// t:htmlEntityDecode missed those payloads.
func htmlEntityDecode(s string) string {
	return sanitizer.DecodeHTMLEntities(s)
}

// removeWhitespace removes all whitespace.
func removeWhitespace(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Full C-locale whitespace set (ModSecurity t:removeWhitespace
		// parity): space, tab, LF, vertical tab, form feed, CR. Leaving \v
		// or \f in place let VT/FF-obfuscated payloads survive rules that
		// rely on whitespace removal.
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' && r != '\v' && r != '\f' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
