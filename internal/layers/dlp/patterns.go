// Package dlp provides Data Loss Prevention with pattern detection for sensitive data.
package dlp

import (
	"regexp"
	"strings"
	"sync"
)

// PatternType identifies the type of sensitive data pattern.
type PatternType string

const (
	PatternCreditCard PatternType = "credit_card"
	PatternSSN        PatternType = "ssn"
	PatternIBAN       PatternType = "iban"
	PatternEmail      PatternType = "email"
	PatternPhone      PatternType = "phone"
	PatternAPIKey     PatternType = "api_key"
	PatternPrivateKey PatternType = "private_key"
	PatternPassport   PatternType = "passport"
	PatternTaxID      PatternType = "tax_id"
	PatternCustom     PatternType = "custom"
)

// Severity defines the risk level of detected patterns.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Pattern defines a detection pattern for sensitive data.
type Pattern struct {
	Type        PatternType
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	MaskFormat  string
	Description string
	Enabled     bool
}

// Match represents a detected pattern instance.
type Match struct {
	Type     PatternType
	Severity Severity
	Value    string
	Masked   string
	Position int
	Length   int
}

// PatternRegistry manages DLP patterns.
type PatternRegistry struct {
	mu       sync.RWMutex
	patterns map[PatternType]*Pattern
	custom   map[string]*Pattern
}

// NewPatternRegistry creates a new pattern registry with default patterns.
func NewPatternRegistry() *PatternRegistry {
	r := &PatternRegistry{
		patterns: make(map[PatternType]*Pattern),
		custom:   make(map[string]*Pattern),
	}
	r.registerDefaults()
	return r
}

// registerDefaults registers built-in patterns.
func (r *PatternRegistry) registerDefaults() {
	// Credit Card (Visa, MasterCard, Amex, Discover, JCB, Diners)
	// Matches cards with or without dashes/spaces
	r.patterns[PatternCreditCard] = &Pattern{
		Type:        PatternCreditCard,
		Name:        "Credit Card Number",
		Regex:       regexp.MustCompile(`\b(?:4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}|3(?:0[0-5]|[68]\d)\d{2}[\s-]?\d{6}[\s-]?\d{4}|6(?:011|5\d{2})\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|(?:2131|1800|35\d{3})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b`),
		Severity:    SeverityCritical,
		MaskFormat:  "****-****-****-${last4}",
		Description: "Credit card numbers (Visa, MasterCard, Amex, etc.)",
		Enabled:     true,
	}

	// SSN (US Social Security Number) - simplified without negative lookahead
	r.patterns[PatternSSN] = &Pattern{
		Type:        PatternSSN,
		Name:        "US Social Security Number",
		Regex:       regexp.MustCompile(`\b[0-8]\d{2}-\d{2}-\d{4}\b`),
		Severity:    SeverityCritical,
		MaskFormat:  "***-**-${last4}",
		Description: "US Social Security Numbers",
		Enabled:     true,
	}

	// IBAN (International Bank Account Number)
	r.patterns[PatternIBAN] = &Pattern{
		Type:        PatternIBAN,
		Name:        "IBAN",
		Regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[\s]*[A-Z0-9]{4}[\s]*[\d\s]{7,}(?:[\s]*[A-Z0-9]{1,4})?\b`),
		Severity:    SeverityHigh,
		MaskFormat:  "${country}****${last4}",
		Description: "International Bank Account Numbers",
		Enabled:     true,
	}

	// Email addresses
	r.patterns[PatternEmail] = &Pattern{
		Type:        PatternEmail,
		Name:        "Email Address",
		Regex:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		Severity:    SeverityMedium,
		MaskFormat:  "${userPrefix}***@${domain}",
		Description: "Email addresses",
		Enabled:     false, // Disabled by default - too noisy
	}

	// Phone numbers (international format)
	r.patterns[PatternPhone] = &Pattern{
		Type:        PatternPhone,
		Name:        "Phone Number",
		Regex:       regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`),
		Severity:    SeverityMedium,
		MaskFormat:  "(***) ***-${last4}",
		Description: "Phone numbers",
		Enabled:     false, // Disabled by default
	}

	// API Keys (generic pattern) - simplified
	r.patterns[PatternAPIKey] = &Pattern{
		Type:        PatternAPIKey,
		Name:        "API Key",
		Regex:       regexp.MustCompile(`\b(?:api[_-]?key|apikey|token)[\s]*[:=][\s]*['"]?([a-zA-Z0-9_\-]{16,})['"]?`),
		Severity:    SeverityHigh,
		MaskFormat:  "${prefix}****${suffix}",
		Description: "API keys and tokens",
		Enabled:     true,
	}

	// Private Keys
	r.patterns[PatternPrivateKey] = &Pattern{
		Type:        PatternPrivateKey,
		Name:        "Private Key",
		Regex:       regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity:    SeverityCritical,
		MaskFormat:  "[PRIVATE KEY REMOVED]",
		Description: "Cryptographic private keys",
		Enabled:     true,
	}

	// Passport numbers (generic)
	r.patterns[PatternPassport] = &Pattern{
		Type:        PatternPassport,
		Name:        "Passport Number",
		Regex:       regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),
		Severity:    SeverityHigh,
		MaskFormat:  "${prefix}****",
		Description: "Passport numbers",
		Enabled:     false, // Disabled by default
	}

	// Tax ID (EIN for US)
	r.patterns[PatternTaxID] = &Pattern{
		Type:        PatternTaxID,
		Name:        "Tax ID (EIN)",
		Regex:       regexp.MustCompile(`\b\d{2}-\d{7}\b`),
		Severity:    SeverityHigh,
		MaskFormat:  "**-${last4}",
		Description: "Employer Identification Numbers",
		Enabled:     true,
	}
}

// GetPattern returns a built-in pattern by type.
func (r *PatternRegistry) GetPattern(t PatternType) *Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.patterns[t]
}

// SetEnabled enables or disables a pattern.
func (r *PatternRegistry) SetEnabled(t PatternType, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.patterns[t]; ok {
		p.Enabled = enabled
	}
}

// GetAllPatterns returns all built-in patterns.
func (r *PatternRegistry) GetAllPatterns() []*Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	patterns := make([]*Pattern, 0, len(r.patterns))
	for _, p := range r.patterns {
		patterns = append(patterns, p)
	}
	return patterns
}

// AddCustomPattern adds a custom pattern.
func (r *PatternRegistry) AddCustomPattern(name string, regex *regexp.Regexp, severity Severity, maskFormat string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.custom[name] = &Pattern{
		Type:       PatternCustom,
		Name:       name,
		Regex:      regex,
		Severity:   severity,
		MaskFormat: maskFormat,
		Enabled:    true,
	}
}

// GetCustomPattern returns a custom pattern.
func (r *PatternRegistry) GetCustomPattern(name string) *Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.custom[name]
}

// RemoveCustomPattern removes a custom pattern by name.
func (r *PatternRegistry) RemoveCustomPattern(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.custom[name]; exists {
		delete(r.custom, name)
		return true
	}
	return false
}

// Scan scans text for sensitive patterns and returns matches.
func (r *PatternRegistry) Scan(text string) []Match {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matches []Match

	// Scan built-in patterns
	for _, pattern := range r.patterns {
		if !pattern.Enabled {
			continue
		}

		for _, loc := range pattern.Regex.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			match := Match{
				Type:     pattern.Type,
				Severity: pattern.Severity,
				Value:    "", // Cleared — only Masked retained to prevent raw data exposure
				Masked:   r.maskValue(value, pattern),
				Position: loc[0],
				Length:   loc[1] - loc[0],
			}
			matches = append(matches, match)
		}
	}

	// Scan custom patterns
	for _, pattern := range r.custom {
		if !pattern.Enabled {
			continue
		}

		for _, loc := range pattern.Regex.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			match := Match{
				Type:     pattern.Type,
				Severity: pattern.Severity,
				Value:    "", // Cleared — only Masked retained to prevent raw data exposure
				Masked:   r.maskValue(value, pattern),
				Position: loc[0],
				Length:   loc[1] - loc[0],
			}
			matches = append(matches, match)
		}
	}

	return matches
}

// maskValue masks a sensitive value according to the pattern's mask format.
func (r *PatternRegistry) maskValue(value string, pattern *Pattern) string {
	mask := pattern.MaskFormat

	switch pattern.Type {
	case PatternCreditCard:
		// Keep last 4 digits
		digits := extractDigits(value)
		if len(digits) >= 4 {
			mask = strings.ReplaceAll(mask, "${last4}", digits[len(digits)-4:])
		}
		return mask

	case PatternSSN:
		// Keep last 4
		parts := strings.Split(value, "-")
		if len(parts) == 3 {
			mask = strings.ReplaceAll(mask, "${last4}", parts[2])
		}
		return mask

	case PatternIBAN:
		// Keep country code and last 4
		cleaned := extractAlphanumeric(value)
		if len(cleaned) >= 6 {
			mask = strings.ReplaceAll(mask, "${country}", cleaned[:2])
			mask = strings.ReplaceAll(mask, "${last4}", cleaned[len(cleaned)-4:])
		}
		return mask

	case PatternEmail:
		// Mask user part, keep domain
		at := strings.Index(value, "@")
		if at > 0 {
			user := value[:at]
			domain := value[at+1:]
			prefix := ""
			if len(user) > 2 {
				prefix = user[:2]
			}
			mask = strings.ReplaceAll(mask, "${userPrefix}", prefix)
			mask = strings.ReplaceAll(mask, "${domain}", domain)
		}
		return mask

	case PatternAPIKey:
		// Keep first 4 and last 4
		if len(value) >= 8 {
			mask = strings.ReplaceAll(mask, "${prefix}", value[:4])
			mask = strings.ReplaceAll(mask, "${suffix}", value[len(value)-4:])
		}
		return mask

	case PatternTaxID:
		// Keep last 4
		parts := strings.Split(value, "-")
		if len(parts) == 2 {
			mask = strings.ReplaceAll(mask, "${last4}", parts[1][max(0, len(parts[1])-4):])
		}
		return mask
	}

	// Default: return mask format as-is or generic masking
	if mask == "" {
		return strings.Repeat("*", len(value))
	}
	return mask
}

// extractDigits extracts only digits from a string.
func extractDigits(s string) string {
	var result strings.Builder
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// extractAlphanumeric extracts letters and digits.
func extractAlphanumeric(s string) string {
	var result strings.Builder
	for _, ch := range s {
		if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			result.WriteRune(ch)
		}
	}
	return result.String()
}
