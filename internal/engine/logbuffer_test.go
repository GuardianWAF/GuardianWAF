package engine

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

func TestLogBuffer_AddAndRecent(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Info("hello")
	lb.Warn("warning")
	lb.Error("error")

	entries := lb.Recent(10)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Most recent first
	if entries[0].Level != "error" {
		t.Errorf("expected 'error' first, got %q", entries[0].Level)
	}
	if entries[1].Level != "warn" {
		t.Errorf("expected 'warn' second, got %q", entries[1].Level)
	}
	if entries[2].Level != "info" {
		t.Errorf("expected 'info' third, got %q", entries[2].Level)
	}
}

func TestLogBuffer_Len(t *testing.T) {
	lb := NewLogBuffer(100)
	if lb.Len() != 0 {
		t.Errorf("expected 0, got %d", lb.Len())
	}
	lb.Info("a")
	lb.Info("b")
	if lb.Len() != 2 {
		t.Errorf("expected 2, got %d", lb.Len())
	}
}

func TestLogBuffer_RingWrap(t *testing.T) {
	lb := NewLogBuffer(3)
	lb.Info("a")
	lb.Info("b")
	lb.Info("c")
	lb.Info("d") // wraps around

	if lb.Len() != 3 {
		t.Errorf("expected 3 (full), got %d", lb.Len())
	}

	entries := lb.Recent(3)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	// Most recent is "d", then "c", then "b"
	if entries[0].Message != "d" {
		t.Errorf("expected 'd', got %q", entries[0].Message)
	}
	if entries[1].Message != "c" {
		t.Errorf("expected 'c', got %q", entries[1].Message)
	}
	if entries[2].Message != "b" {
		t.Errorf("expected 'b', got %q", entries[2].Message)
	}
}

func TestLogBuffer_RecentPartial(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Info("a")
	lb.Info("b")
	lb.Info("c")

	entries := lb.Recent(2)
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
	if entries[0].Message != "c" {
		t.Errorf("expected 'c', got %q", entries[0].Message)
	}
}

func TestLogBuffer_RecentZero(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Info("a")
	entries := lb.Recent(0)
	// 0 means "all"
	if len(entries) != 1 {
		t.Errorf("expected 1 (all), got %d", len(entries))
	}
}

func TestLogBuffer_RecentNegative(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Info("a")
	entries := lb.Recent(-1)
	if len(entries) != 1 {
		t.Errorf("expected 1 (all), got %d", len(entries))
	}
}

func TestLogBuffer_Formatted(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Infof("hello %s", "world")
	lb.Warnf("count %d", 42)
	lb.Errorf("error: %v", fmt.Errorf("test error"))

	entries := lb.Recent(10)
	if len(entries) != 3 {
		t.Fatalf("expected 3, got %d", len(entries))
	}
	if entries[2].Message != "hello world" {
		t.Errorf("expected 'hello world', got %q", entries[2].Message)
	}
	if entries[1].Message != "count 42" {
		t.Errorf("expected 'count 42', got %q", entries[1].Message)
	}
	if entries[0].Message != "error: test error" {
		t.Errorf("expected error msg, got %q", entries[0].Message)
	}
}

func TestLogBuffer_DefaultSize(t *testing.T) {
	lb := NewLogBuffer(0)
	if lb.maxSize != 1000 {
		t.Errorf("expected default 1000, got %d", lb.maxSize)
	}
	lb2 := NewLogBuffer(-5)
	if lb2.maxSize != 1000 {
		t.Errorf("expected default 1000 for negative, got %d", lb2.maxSize)
	}
}

func TestLogBuffer_Concurrent(t *testing.T) {
	lb := NewLogBuffer(100)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			lb.Infof("goroutine %d", id)
			lb.Recent(10)
			lb.Len()
		}(i)
	}
	wg.Wait()
	if lb.Len() != 50 {
		t.Errorf("expected 50, got %d", lb.Len())
	}
}

func TestLogBuffer_EmptyRecent(t *testing.T) {
	lb := NewLogBuffer(10)
	entries := lb.Recent(5)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty buffer, got %d", len(entries))
	}
}

// --- JSON MarshalJSON tests ---

func TestSeverity_MarshalJSON(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected string
	}{
		{SeverityCritical, `"critical"`},
		{SeverityHigh, `"high"`},
		{SeverityMedium, `"medium"`},
		{SeverityLow, `"low"`},
		{SeverityInfo, `"info"`},
	}
	for _, tt := range tests {
		data, err := tt.sev.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON error for %v: %v", tt.sev, err)
		}
		if string(data) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, data)
		}
	}
}

func TestAction_MarshalJSON(t *testing.T) {
	tests := []struct {
		act      Action
		expected string
	}{
		{ActionPass, `"pass"`},
		{ActionBlock, `"block"`},
		{ActionLog, `"log"`},
		{ActionChallenge, `"challenge"`},
	}
	for _, tt := range tests {
		data, err := tt.act.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON error for %v: %v", tt.act, err)
		}
		if string(data) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, data)
		}
	}
}

func TestFinding_JSONRoundtrip(t *testing.T) {
	f := Finding{
		DetectorName: "sqli",
		Category:     "injection",
		Severity:     SeverityHigh,
		Score:        80,
		Description:  "SQL injection detected",
		MatchedValue: "1' OR '1'='1",
		Location:     "query",
		Confidence:   0.95,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Verify severity is string
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["severity"] != "high" {
		t.Errorf("expected severity 'high' in JSON, got %v", raw["severity"])
	}
}

func TestAction_JSONInStruct(t *testing.T) {
	type testStruct struct {
		Action Action `json:"action"`
	}
	s := testStruct{Action: ActionBlock}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["action"] != "block" {
		t.Errorf("expected 'block' in JSON, got %v", raw["action"])
	}
}

// --- Engine coverage helpers (uses testEngine from engine_test.go) ---

func TestSetChallengeService(t *testing.T) {
	eng, _, _ := testEngine(t)
	eng.SetChallengeService(nil)
}

func TestFindLayer_Empty(t *testing.T) {
	eng, _, _ := testEngine(t)
	l := eng.FindLayer("nonexistent")
	if l != nil {
		t.Error("expected nil for nonexistent layer")
	}
}

func TestSetUAParser(t *testing.T) {
	SetUAParser(func(ua string) (browser, brVersion, os, deviceType string, isBot bool) {
		return "TestBrowser", "1.0", "TestOS", "desktop", false
	})
	defer SetUAParser(nil)
}

func TestLogBuffer_SetLevel_FilterDebug(t *testing.T) {
	lb := NewLogBuffer(100)
	// Default level is info — debug messages should be filtered
	lb.Debug("debug msg")
	lb.Info("info msg")
	lb.Warn("warn msg")
	lb.Error("error msg")

	entries := lb.Recent(100)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (debug filtered), got %d", len(entries))
	}
	for _, e := range entries {
		if e.Level == "debug" {
			t.Error("debug message should have been filtered at info level")
		}
	}
}

func TestLogBuffer_SetLevel_WarnOnly(t *testing.T) {
	lb := NewLogBuffer(100)
	lb.SetLevel("warn")

	lb.Debug("d")
	lb.Debugf("d%d", 1)
	lb.Info("i")
	lb.Infof("i%d", 1)
	lb.Warn("w")
	lb.Warnf("w%d", 1)
	lb.Error("e")
	lb.Errorf("e%d", 1)

	entries := lb.Recent(100)
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries (warn+error only), got %d", len(entries))
	}
	for _, e := range entries {
		if e.Level == "debug" || e.Level == "info" {
			t.Errorf("unexpected level %q at warn minimum", e.Level)
		}
	}
}

func TestLogBuffer_SetLevel_ErrorOnly(t *testing.T) {
	lb := NewLogBuffer(100)
	lb.SetLevel("error")

	lb.Info("i")
	lb.Warn("w")
	lb.Error("e")

	if lb.Len() != 1 {
		t.Errorf("expected 1 entry (error only), got %d", lb.Len())
	}
}

func TestLogBuffer_SetLevel_DebugAll(t *testing.T) {
	lb := NewLogBuffer(100)
	lb.SetLevel("debug")

	lb.Debug("d")
	lb.Info("i")
	lb.Warn("w")
	lb.Error("e")

	if lb.Len() != 4 {
		t.Errorf("expected 4 entries (all levels), got %d", lb.Len())
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  LogLevel
	}{
		{"debug", LogLevelDebug},
		{"info", LogLevelInfo},
		{"warn", LogLevelWarn},
		{"warning", LogLevelWarn},
		{"error", LogLevelError},
		{"", LogLevelInfo},
		{"unknown", LogLevelInfo},
	}
	for _, tt := range tests {
		got := ParseLogLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLogLevel(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
