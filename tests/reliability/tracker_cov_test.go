package testreliability

import (
	"os"
	"path/filepath"
	"testing"
)

// Flush: empty results (no write)
func TestCoverage_Flush_EmptyResults(t *testing.T) {
	rec := NewRecorder(filepath.Join(t.TempDir(), "empty.jsonl"))
	if err := rec.Flush(); err != nil {
		t.Errorf("Flush with no results should succeed, got %v", err)
	}
}

// Flush: bad path (write to a directory that is actually a file)
func TestCoverage_Flush_BadPath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocked")
	os.WriteFile(blocker, []byte("x"), 0600)
	// "blocked" is a file, not a directory, so opening "blocked/results.jsonl" should fail
	rec := NewRecorder(filepath.Join(blocker, "results.jsonl"))
	rec.Record("TestX", true, 1000000)
	if err := rec.Flush(); err == nil {
		t.Error("expected error writing to path blocked by file")
	}
}

// Flush: append to existing file
func TestCoverage_Flush_Append(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.jsonl")

	rec := NewRecorder(path)
	rec.Record("TestA", true, 1000000)
	rec.Flush()

	data1, _ := os.ReadFile(path)

	rec2 := NewRecorder(path)
	rec2.Record("TestB", false, 2000000)
	rec2.Flush()

	data2, _ := os.ReadFile(path)
	if len(data2) <= len(data1) {
		t.Error("expected file to grow after append")
	}
}

// DetectFlaky: corrupted JSONL lines
func TestCoverage_DetectFlaky_CorruptedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.jsonl")

	f, _ := os.Create(path)
	f.WriteString("not-json-at-all\n")
	f.WriteString(`{"name":"TestA","passed":true,"run_id":"r1"}` + "\n")
	f.WriteString("\n")
	f.WriteString(`{"name":"TestA","passed":false,"run_id":"r2"}` + "\n")
	f.WriteString("also not json\n")
	f.Close()

	flaky := DetectFlaky(path)
	if len(flaky) != 1 || flaky[0] != "TestA" {
		t.Errorf("expected TestA as flaky, got %v", flaky)
	}
}

// DetectFlaky: same test pass+fail in same run
func TestCoverage_DetectFlaky_SameRunBoth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "both.jsonl")

	f, _ := os.Create(path)
	f.WriteString(`{"name":"TestA","passed":true,"run_id":"r1"}` + "\n")
	f.WriteString(`{"name":"TestA","passed":false,"run_id":"r1"}` + "\n")
	f.Close()

	flaky := DetectFlaky(path)
	if len(flaky) != 1 {
		t.Errorf("expected 1 flaky, got %v", flaky)
	}
}

// DetectFlaky: all pass, no fail
func TestCoverage_DetectFlaky_AllPass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allpass.jsonl")

	f, _ := os.Create(path)
	f.WriteString(`{"name":"TestA","passed":true,"run_id":"r1"}` + "\n")
	f.WriteString(`{"name":"TestA","passed":true,"run_id":"r2"}` + "\n")
	f.Close()

	flaky := DetectFlaky(path)
	if len(flaky) != 0 {
		t.Errorf("expected no flaky, got %v", flaky)
	}
}

// DetectFlaky: all fail, no pass
func TestCoverage_DetectFlaky_AllFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allfail.jsonl")

	f, _ := os.Create(path)
	f.WriteString(`{"name":"TestA","passed":false,"run_id":"r1"}` + "\n")
	f.WriteString(`{"name":"TestA","passed":false,"run_id":"r2"}` + "\n")
	f.Close()

	flaky := DetectFlaky(path)
	if len(flaky) != 0 {
		t.Errorf("expected no flaky for all-fail, got %v", flaky)
	}
}

// splitLines: CRLF handling and edge cases
func TestCoverage_SplitLines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single line no newline", "hello", 1},
		{"single line with newline", "hello\n", 1},
		{"CRLF", "line1\r\nline2\r\n", 2},
		{"trailing text", "a\nb", 2},
		{"multiple empty lines", "\n\n\n", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := splitLines(tt.input)
			if len(lines) != tt.want {
				t.Errorf("splitLines(%q) returned %d lines, want %d: %v", tt.input, len(lines), tt.want, lines)
			}
		})
	}
}
