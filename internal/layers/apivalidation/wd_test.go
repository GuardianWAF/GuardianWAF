package apivalidation

import (
	"os"
	"strings"
	"testing"
)

func TestWorkingDirError(t *testing.T) {
	// This test verifies the workingDirectory error branch
	origWd := workingDirectory
	workingDirectory = func() (string, error) { return "", os.ErrPermission }
	defer func() { workingDirectory = origWd }()

	l := &Layer{}
	_, err := l.readFile(".")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "working directory") {
		t.Fatalf("expected working directory error, got: %v", err)
	}
}
