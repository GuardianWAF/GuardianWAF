package dlp

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewPatternRegistry(t *testing.T) {
	r := NewPatternRegistry()

	if r == nil {
		t.Fatal("expected registry, got nil")
	}

	// Check that default patterns exist
	cc := r.GetPattern(PatternCreditCard)
	if cc == nil {
		t.Error("expected credit card pattern")
	}

	ssn := r.GetPattern(PatternSSN)
	if ssn == nil {
		t.Error("expected SSN pattern")
	}
}

func TestPatternRegistry_Scan_CreditCard(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Visa card",
			input:    "My card number is 4111-1111-1111-1111",
			expected: 1,
		},
		{
			name:     "MasterCard",
			input:    "Card: 5500 0000 0000 0004",
			expected: 1,
		},
		{
			name:     "Amex",
			input:    "Amex: 3782 822463 10005",
			expected: 1,
		},
		{
			name:     "No card",
			input:    "Just some text without numbers",
			expected: 0,
		},
		{
			name:     "Multiple cards",
			input:    "Cards: 4111111111111111 and 5500000000000004",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
			}

			for _, m := range matches {
				if m.Type != PatternCreditCard {
					t.Errorf("expected credit_card type, got %v", m.Type)
				}
				if m.Severity != SeverityCritical {
					t.Errorf("expected critical severity, got %v", m.Severity)
				}
				if m.Masked == "" {
					t.Error("expected masked value")
				}
			}
		})
	}
}

func TestPatternRegistry_Scan_SSN(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Valid SSN",
			input:    "SSN: 123-45-6789",
			expected: 1,
		},
		{
			name:     "SSN starting with 0",
			input:    "SSN: 012-12-3456",
			expected: 1, // Simplified pattern matches this
		},
		{
			name:     "SSN with 666",
			input:    "SSN: 666-12-3456",
			expected: 1, // Simplified pattern matches this
		},
		{
			name:     "Invalid format",
			input:    "SSN: 123-456-789", // Wrong format
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
			}

			for _, m := range matches {
				if m.Type != PatternSSN {
					t.Errorf("expected ssn type, got %v", m.Type)
				}
			}
		})
	}
}

func TestPatternRegistry_Scan_IBAN(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "German IBAN",
			input:    "IBAN: DE89 3704 0044 0532 0130 00",
			expected: 1,
		},
		{
			name:     "UK IBAN",
			input:    "GB82 WEST 1234 5698 7654 32",
			expected: 1,
		},
		{
			name:     "US IBAN (not valid format)",
			input:    "US12 3456 7890",
			expected: 0, // Too short
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
			}

			for _, m := range matches {
				if m.Type != PatternIBAN {
					t.Errorf("expected iban type, got %v", m.Type)
				}
			}
		})
	}
}

func TestPatternRegistry_Scan_Email(t *testing.T) {
	r := NewPatternRegistry()
	r.SetEnabled(PatternEmail, true)

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Simple email",
			input:    "Contact: user@example.com",
			expected: 1,
		},
		{
			name:     "Email with dots",
			input:    "Email: first.last@company.co.uk",
			expected: 1,
		},
		{
			name:     "Multiple emails",
			input:    "To: user1@test.com, user2@test.com",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
			}

			for _, m := range matches {
				if m.Type != PatternEmail {
					t.Errorf("expected email type, got %v", m.Type)
				}
			}
		})
	}
}

func TestPatternRegistry_Scan_APIKey(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "API key",
			input:    `api_key: sk_live_abcdef1234567890`,
			expected: 1,
		},
		{
			name:     "Token with equals",
			input:    "token=ghp_xxxxxxxxxxxxxxxxxxxx",
			expected: 1,
		},
		{
			name:     "API key with underscore",
			input:    "api_key=secret1234567890123456",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			if len(matches) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(matches))
			}

			for _, m := range matches {
				if m.Type != PatternAPIKey {
					t.Errorf("expected api_key type, got %v", m.Type)
				}
			}
		})
	}
}

func TestPatternRegistry_Scan_PrivateKey(t *testing.T) {
	r := NewPatternRegistry()

	input := `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwMbRvI0MBZhpR
-----END RSA PRIVATE KEY-----`

	matches := r.Scan(input)
	if len(matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(matches))
	}

	if len(matches) > 0 && matches[0].Type != PatternPrivateKey {
		t.Errorf("expected private_key type, got %v", matches[0].Type)
	}
}

func TestMaskValue_CreditCard(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "4111111111111111",
			expected: "****-****-****-1111",
		},
		{
			input:    "5500-0000-0000-0004",
			expected: "****-****-****-0004",
		},
	}

	pattern := r.GetPattern(PatternCreditCard)
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			masked := r.maskValue(tt.input, pattern)
			if !strings.HasSuffix(masked, tt.expected[len(tt.expected)-4:]) {
				t.Errorf("expected mask to end with %s, got %s", tt.expected[len(tt.expected)-4:], masked)
			}
		})
	}
}

func TestMaskValue_SSN(t *testing.T) {
	r := NewPatternRegistry()

	input := "123-45-6789"
	pattern := r.GetPattern(PatternSSN)
	masked := r.maskValue(input, pattern)

	expectedSuffix := "6789"
	if !strings.HasSuffix(masked, expectedSuffix) {
		t.Errorf("expected mask to end with %s, got %s", expectedSuffix, masked)
	}
}

func TestPatternRegistry_SetEnabled(t *testing.T) {
	r := NewPatternRegistry()

	// Disable credit card
	r.SetEnabled(PatternCreditCard, false)

	input := "Card: 4111111111111111"
	matches := r.Scan(input)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches when disabled, got %d", len(matches))
	}

	// Re-enable
	r.SetEnabled(PatternCreditCard, true)
	matches = r.Scan(input)
	if len(matches) != 1 {
		t.Errorf("expected 1 match when enabled, got %d", len(matches))
	}
}

func TestPatternRegistry_AddCustomPattern(t *testing.T) {
	r := NewPatternRegistry()

	// Add a custom pattern for employee ID
	customRegex := regexp.MustCompile(`\bEMP-\d{6}\b`)
	r.AddCustomPattern("employee_id", customRegex, SeverityMedium, "EMP-******")

	input := "Employee ID: EMP-123456"
	matches := r.Scan(input)

	found := false
	for _, m := range matches {
		if strings.HasPrefix(m.Masked, "EMP-") {
			found = true
			if m.Severity != SeverityMedium {
				t.Errorf("expected medium severity, got %v", m.Severity)
			}
		}
	}

	if !found {
		t.Error("expected to find custom pattern match")
	}
}

func TestNewLayer(t *testing.T) {
	cfg := &Config{
		Enabled:      true,
		ScanRequest:  true,
		ScanResponse: true,
		Patterns:     []string{"credit_card", "ssn"},
	}

	layer := NewLayer(cfg)
	if layer == nil {
		t.Fatal("expected layer, got nil")
	}

	if !layer.config.Enabled {
		t.Error("expected layer to be enabled")
	}

	// Check that only configured patterns are enabled
	r := layer.GetRegistry()
	if !r.GetPattern(PatternCreditCard).Enabled {
		t.Error("expected credit_card to be enabled")
	}
	if !r.GetPattern(PatternSSN).Enabled {
		t.Error("expected ssn to be enabled")
	}
	if r.GetPattern(PatternIBAN).Enabled {
		t.Error("expected iban to be disabled")
	}
}

func TestLayer_scanContent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn"},
	})

	tests := []struct {
		name         string
		content      string
		expectedSafe bool
		minScore     int
	}{
		{
			name:         "Safe content",
			content:      "This is just regular text",
			expectedSafe: true,
			minScore:     0,
		},
		{
			name:         "Credit card detected",
			content:      "My card is 4111111111111111",
			expectedSafe: false,
			minScore:     40,
		},
		{
			name:         "Multiple PII types",
			content:      "SSN: 123-45-6789, Card: 4111111111111111",
			expectedSafe: false,
			minScore:     70, // Critical + Critical = 80, but might vary
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := layer.scanContent(tt.content)

			if result.Safe != tt.expectedSafe {
				t.Errorf("Safe = %v, want %v", result.Safe, tt.expectedSafe)
			}

			if result.RiskScore < tt.minScore {
				t.Errorf("RiskScore = %d, want >= %d", result.RiskScore, tt.minScore)
			}
		})
	}
}

func TestLayer_maskContent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn"},
	})

	content := "Card: 4111111111111111, SSN: 123-45-6789"
	result := layer.scanContent(content)

	if result.Safe {
		t.Fatal("expected to find PII")
	}

	masked := layer.maskContent(content, result.Matches)

	// Check that original values are not in masked content
	if strings.Contains(masked, "4111111111111111") {
		t.Error("masked content should not contain original credit card")
	}
	if strings.Contains(masked, "123-45-6789") {
		t.Error("masked content should not contain original SSN")
	}
}

func TestIsScannableContent(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/json", true},
		{"text/plain", true},
		{"text/html", true},
		{"application/xml", true},
		{"application/x-www-form-urlencoded", true},
		{"multipart/form-data", true},
		{"application/octet-stream", false},
		{"image/png", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			result := isScannableContent(tt.contentType)
			if result != tt.expected {
				t.Errorf("isScannableContent(%q) = %v, want %v", tt.contentType, result, tt.expected)
			}
		})
	}
}

func TestLayer_Name(t *testing.T) {
	layer := NewLayer(&Config{})
	if layer.Name() != "dlp" {
		t.Errorf("Name() = %s, want dlp", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer := NewLayer(&Config{})
	if layer.Order() != 550 {
		t.Errorf("Order() = %d, want 550", layer.Order())
	}
}
