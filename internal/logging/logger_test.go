package logging

import (
	"testing"
)

func TestLoggerInitialized(t *testing.T) {
	if Logger == nil {
		t.Fatal("Logger should be initialized by init()")
	}
}

func TestNewLogger(t *testing.T) {
	l := NewLogger("test-component")
	if l == nil {
		t.Fatal("NewLogger returned nil")
	}
}
