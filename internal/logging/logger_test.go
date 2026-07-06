package logging

import "testing"

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

func TestLoggerInitializedWithJSONLogEnv(t *testing.T) {
	t.Setenv("JSON_LOG", "1")
	initLogger()

	if Logger == nil {
		t.Fatal("Logger should be initialized by init() when JSON_LOG=1")
	}
	if l := NewLogger("json-test-component"); l == nil {
		t.Fatal("NewLogger returned nil when JSON_LOG=1")
	}
}
