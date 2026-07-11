package ssti

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDetectorNameAndOrder(t *testing.T) {
	detector := NewDetector(true, 1)
	if got := detector.Name(); got != "ssti-detector" {
		t.Fatalf("Name() = %q, want %q", got, "ssti-detector")
	}
	if got := detector.Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
}

func TestHasLiteralMultiplicationBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "asterisk first", input: "*7", want: false},
		{name: "spaces without left operand", input: "  *7", want: false},
		{name: "non-digit left operand", input: "x*7", want: false},
		{name: "missing right operand", input: "7*", want: false},
		{name: "spaces without right operand", input: "7*  ", want: false},
		{name: "quote without right operand", input: "7*'", want: false},
		{name: "non-digit right operand", input: "7*x", want: false},
		{name: "spaced quoted multiplication", input: "7 * '7'", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasLiteralMultiplication(tt.input); got != tt.want {
				t.Fatalf("hasLiteralMultiplication(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMakeFindingMatchedValueFallbackAndTruncation(t *testing.T) {
	context := strings.Repeat("x", 205)
	finding := makeFinding(1, engine.SeverityLow, "description", "", context, "body", 0.5)

	if got := len(finding.MatchedValue); got != 200 {
		t.Fatalf("len(MatchedValue) = %d, want 200", got)
	}
	if !strings.HasSuffix(finding.MatchedValue, "...") {
		t.Fatalf("MatchedValue = %q, want ellipsis suffix", finding.MatchedValue)
	}
}

func TestExtractContext(t *testing.T) {
	t.Run("missing pattern short input", func(t *testing.T) {
		if got := extractContext("short input", "absent"); got != "short input" {
			t.Fatalf("extractContext() = %q, want %q", got, "short input")
		}
	})

	t.Run("missing pattern long input", func(t *testing.T) {
		input := strings.Repeat("x", 101)
		if got := extractContext(input, "absent"); got != input[:100] {
			t.Fatalf("extractContext() length = %d, want 100", len(got))
		}
	})

	t.Run("long matching pattern is truncated", func(t *testing.T) {
		pattern := strings.Repeat("p", 201)
		input := "prefix" + pattern + "suffix"
		got := extractContext(input, pattern)
		if len(got) != 200 {
			t.Fatalf("extractContext() length = %d, want 200", len(got))
		}
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("extractContext() = %q, want ellipsis suffix", got)
		}
	})
}
