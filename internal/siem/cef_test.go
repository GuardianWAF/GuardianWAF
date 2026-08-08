package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestEncodeCEF(t *testing.T) {
	event := engine.Event{
		ID:        "evt-001",
		Timestamp: time.Date(2025, 1, 15, 12, 30, 45, 0, time.UTC),
		RequestID: "req-abc",
		ClientIP:  "192.168.1.100",
		Method:    "GET",
		Path:      "/search",
		Query:     "q=1' OR 1=1",
		Action:    engine.ActionBlock,
		Score:     85,
		Findings: []engine.Finding{
			{DetectorName: "sqli", Category: "sqli-detection", Severity: engine.SeverityHigh, Score: 85,
				Description: "SQL injection pattern detected", MatchedValue: "1' OR 1=1",
				Location: "query", Confidence: 0.95},
		},
		StatusCode: 403,
		UserAgent:  "Mozilla/5.0",
		Host:       "api.example.com",
		TenantID:   "tenant-42",
	}

	line := EncodeCEF(event, "GuardianWAF", "1.0")

	if !strings.HasPrefix(line, "CEF:0|GuardianWAF|GuardianWAF|1.0|") {
		t.Errorf("missing CEF prefix: %s", line)
	}
	if !strings.Contains(line, "act=blocked") {
		t.Errorf("missing act=blocked: %s", line)
	}
	if !strings.Contains(line, "src=192.168.1.100") {
		t.Errorf("missing src field: %s", line)
	}
	if !strings.Contains(line, "requestMethod=GET") {
		t.Errorf("missing requestMethod: %s", line)
	}
	if !strings.Contains(line, "cs1=tenant-42") {
		t.Errorf("missing tenant label: %s", line)
	}
	if !strings.Contains(line, "sproc=q=1' OR 1=1") {
		t.Errorf("missing query string: %s", line)
	}
	if !strings.Contains(line, "SQL injection pattern detected") {
		t.Errorf("missing finding description: %s", line)
	}
}

func TestEncodeCEF_EmptyFindings(t *testing.T) {
	event := engine.Event{
		ID:        "evt-002",
		Timestamp: time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		Action:    engine.ActionChallenge,
		Score:     40,
	}
	line := EncodeCEF(event, "GuardianWAF", "1.0")
	if !strings.Contains(line, "act=challenged") {
		t.Errorf("expected act=challenged: %s", line)
	}
}

func TestEncodeCEF_PipeEscaped(t *testing.T) {
	event := engine.Event{
		Path:   "/a|b",
		Query:  "x=y|z",
		Action: engine.ActionBlock,
		Score:  50,
		Findings: []engine.Finding{
			{Description: "rule|matched"},
		},
	}
	line := EncodeCEF(event, "GuardianWAF", "1.0")
	// Pipes in field values must be escaped as \| or the CEF parser will
	// mis-split the extension section.
	count := strings.Count(line, "|")
	escapedCount := strings.Count(line, "\\|")
	if count-escapedCount > 8 {
		t.Errorf("too many unescaped pipes in CEF line (%d total, %d escaped): %s", count, escapedCount, line)
	}
}

func TestEscapeCEF(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"a|b", "a\\|b"},
		{"a\nb", "a b"},
		{"a= b", "a= b"}, // = is only special at key boundaries, not in values
		{"tab\tchar", "tab char"},
	}
	for _, tt := range tests {
		got := escapeCEF(tt.input)
		if got != tt.want {
			t.Errorf("escapeCEF(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCEFSeverity(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "1"},
		{29, "3"},
		{49, "3"},
		{50, "6"},
		{74, "6"},
		{75, "8"},
		{90, "10"},
		{100, "10"},
	}
	for _, tt := range tests {
		got := cefSeverity(tt.score)
		if got != tt.want {
			t.Errorf("cefSeverity(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestCEFNameIncludesFindings(t *testing.T) {
	event := engine.Event{
		Action: engine.ActionBlock,
		Score:  60,
		Findings: []engine.Finding{
			{DetectorName: "sqli", Description: "SQL injection"},
			{DetectorName: "xss", Description: "XSS attempt"},
		},
	}
	line := EncodeCEF(event, "GuardianWAF", "1.0")
	if !strings.Contains(line, "sqli") {
		t.Errorf("missing first detector name: %s", line)
	}
	if !strings.Contains(line, "xss") {
		t.Errorf("missing second detector name: %s", line)
	}
}

func TestEncodeCEF_PortStrippedFromSrc(t *testing.T) {
	event := engine.Event{
		ClientIP: "10.0.0.5:54321",
		Action:   engine.ActionBlock,
		Score:    50,
	}
	line := EncodeCEF(event, "GuardianWAF", "1.0")
	// SplitHostPort should yield just the IP without the port.
	if !strings.Contains(line, "src=10.0.0.5 ") {
		t.Errorf("src should be just IP without port: %s", line)
	}
}
