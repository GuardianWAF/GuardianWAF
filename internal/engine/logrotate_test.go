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

func TestRotatingFileWriter_CreatesPrivateLogFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	path := filepath.Join(dir, "private.log")

	w, err := NewRotatingFileWriter(path, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Fatalf("log dir permissions = %o, want 0750", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("log file permissions = %o, want 0600", got)
	}
}

func TestCleanRotatingLogPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "relative", path: filepath.Join("logs", "..", "access.log"), want: "access.log"},
		{name: "empty", wantErr: true},
		{name: "nul", path: "access\x00.log", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cleanRotatingLogPath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("cleanRotatingLogPath: %v", err)
			}
			if got != tt.want {
				t.Fatalf("cleanRotatingLogPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRotatingFileWriterRejectsInvalidPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", "access\x00.log"} {
		if _, err := NewRotatingFileWriter(path, 1, 1, 0); err == nil {
			t.Fatalf("expected invalid path error for %q", path)
		}
	}
}

func TestParseLogOutputRejectsNULFilePath(t *testing.T) {
	t.Parallel()

	if _, err := ParseLogOutput("access\x00.log", 1, 1, 0); err == nil {
		t.Fatal("expected invalid file path error")
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

	currentInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := currentInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("rotated current log permissions = %o, want 0600", got)
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

func TestRotatingFileWriter_OpenFileError(t *testing.T) {
	_, err := NewRotatingFileWriter("/nonexistent/deep/dir/log.log", 1, 3, 0)
	if err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestRotatingFileWriter_CloseWithoutOpen(t *testing.T) {
	w := &RotatingFileWriter{}
	if err := w.Close(); err != nil {
		t.Fatalf("Close on zero writer: %v", err)
	}
}

func TestRotatingFileWriter_RotateWithNonexistentBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate.log")
	w, err := NewRotatingFileWriter(path, 100, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Write enough to trigger rotation
	big := make([]byte, 100)
	_, err = w.Write(big)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
}

func TestCleanRotatingLogPath_EmptyPath(t *testing.T) {
	_, err := cleanRotatingLogPath("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestCleanRotatingLogPath_NULPath(t *testing.T) {
	_, err := cleanRotatingLogPath("access\x00.log")
	if err == nil {
		t.Fatal("expected error for NUL path")
	}
}
