package apivalidation

import (
	"strings"
	"testing"
)

func TestWorkingDirError2(t *testing.T) {
	origWd := workingDirectory
	workingDirectory = func() (string, error) { return "/nonexistent_directory_for_testing", nil }
	defer func() { workingDirectory = origWd }()

	l := NewLayer(nil)
	_, err := l.readFile(".")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "cannot find") {
		t.Fatalf("expected filesystem error, got: %v", err)
	}
}
