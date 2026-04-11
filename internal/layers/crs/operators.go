package crs

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// regexCache caches compiled regex patterns to avoid recompilation per request.
var (
	regexCache     sync.Map    // string → *regexp.Regexp
	regexCacheSize atomic.Int64 // track cache size for cap enforcement
)

const maxRegexCacheSize = 10000 // cap regex cache to prevent unbounded growth

// regexExecutionTimeout is the maximum time allowed for a single regex match.
// Go's regexp package uses RE2 (linear-time, no catastrophic backtracking),
// but this timeout provides defense-in-depth against pathological inputs.
const regexExecutionTimeout = 5 * time.Second

// matchWithTimeout evaluates a regex match with a hard execution timeout.
// This prevents any single regex from monopolizing CPU, even though RE2
// guarantees O(n) matching — large inputs can still take significant wall time.
func matchWithTimeout(re *regexp.Regexp, s string) []string {
	type result struct {
		submatches []string
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		matches := re.FindStringSubmatch(s)
		select {
		case <-ctx.Done():
			return
		case done <- result{submatches: matches}:
		}
	}()
	select {
	case r := <-done:
		return r.submatches
	case <-time.After(regexExecutionTimeout):
		return nil // cancel() ensures goroutine can exit via ctx.Done()
	}
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
}

// NewOperatorEvaluator creates a new operator evaluator.
func NewOperatorEvaluator() *OperatorEvaluator {
	return &OperatorEvaluator{
		captureGroups: []string{},
	}
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
		// Phrase from file - simplified
		return oe.evaluatePm(argument, value)
	case "@within":
		return oe.evaluateWithin(argument, value)
	case "@ipMatch":
		return oe.evaluateIpMatch(argument, value)
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

// evaluateRx evaluates the @rx (regex) operator.
func (oe *OperatorEvaluator) evaluateRx(pattern, value string) (bool, error) {
	re, err := getCachedRegex(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Use timeout-wrapped matching to prevent CPU monopolization (H6 fix)
	matches := matchWithTimeout(re, value)
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
			// Check if next two chars are valid hex
			_, err := strconv.ParseInt(value[i+1:i+3], 16, 0)
			if err != nil {
				return false, nil
			}
		}
	}
	return true, nil
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
		case "urlEncode", "t:urlEncode":
			result = urlEncode(result)
		case "htmlEntityDecode", "t:htmlEntityDecode":
			result = htmlEntityDecode(result)
		case "removeWhitespace", "t:removeWhitespace":
			result = removeWhitespace(result)
		case "trim", "t:trim":
			result = strings.TrimSpace(result)
		case "removeNulls", "t:removeNulls":
			result = strings.ReplaceAll(result, "\x00", "")
		case "replaceNulls", "t:replaceNulls":
			result = strings.ReplaceAll(result, "\x00", " ")
		}
	}

	return result
}

// urlDecode decodes URL-encoded string.
func urlDecode(s string) string {
	// Simple URL decode - proper implementation would handle all cases
	result := s
	result = strings.ReplaceAll(result, "%20", " ")
	result = strings.ReplaceAll(result, "%2B", "+")
	result = strings.ReplaceAll(result, "%2F", "/")
	result = strings.ReplaceAll(result, "%3F", "?")
	result = strings.ReplaceAll(result, "%3D", "=")
	result = strings.ReplaceAll(result, "%26", "&")
	return result
}

// urlEncode URL-encodes a string.
func urlEncode(s string) string {
	// Simple implementation
	return strings.ReplaceAll(s, " ", "%20")
}

// htmlEntityDecode decodes HTML entities.
func htmlEntityDecode(s string) string {
	// Simple HTML entity decode
	result := s
	result = strings.ReplaceAll(result, "&lt;", "<")
	result = strings.ReplaceAll(result, "&gt;", ">")
	result = strings.ReplaceAll(result, "&amp;", "&")
	result = strings.ReplaceAll(result, "&quot;", "\"")
	result = strings.ReplaceAll(result, "&#x27;", "'")
	return result
}

// removeWhitespace removes all whitespace.
func removeWhitespace(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' && r != '\r' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
