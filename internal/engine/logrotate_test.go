package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFileWriter_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotatingFileWriter(path, 1, 3, 0)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello world\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
	w.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(data) {
		t.Errorf("content = %q, want %q", string(b), string(data))
	}
}

func TestRotatingFileWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.log")

	// 100 byte max to trigger rotation easily
	w, err := NewRotatingFileWriter(path, 0, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Override max size for testing
	w.maxSize = 20

	chunk := []byte("0123456789") // 10 bytes
	for range 7 {
		w.Write(chunk)
	}
	w.Close()

	// Should have: rotate.log, rotate.log.1, rotate.log.2
	b, _ := os.ReadFile(path)
	if len(b) == 0 {
		t.Error("current log file is empty")
	}

	b1, _ := os.ReadFile(path + ".1")
	if len(b1) == 0 {
		t.Error("backup .1 is empty")
	}

	b2, _ := os.ReadFile(path + ".2")
	if len(b2) == 0 {
		t.Error("backup .2 is empty")
	}

	// .3 should not exist (maxBackups=2)
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("backup .3 should have been removed")
	}
}

func TestRotatingFileWriter_Append(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.log")

	// Write initial content
	w, _ := NewRotatingFileWriter(path, 1, 2, 0)
	w.Write([]byte("first\n"))
	w.Close()

	// Re-open and write more — should append
	w2, err := NewRotatingFileWriter(path, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	w2.Write([]byte("second\n"))
	w2.Close()

	b, _ := os.ReadFile(path)
	content := string(b)
	if !containsStr(content, "first") || !containsStr(content, "second") {
		t.Errorf("expected both lines, got: %q", content)
	}
}

func TestParseLogOutput_Stdout(t *testing.T) {
	w, err := ParseLogOutput("stdout", 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
}

func TestParseLogOutput_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.log")

	w, err := ParseLogOutput(path, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("test\n"))
	w.Close()

	b, _ := os.ReadFile(path)
	if string(b) != "test\n" {
		t.Errorf("got %q, want %q", string(b), "test\n")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && len(sub) > 0 && findSub(s, sub)))
}

func findSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
