package replay

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected replay to be disabled by default")
	}

	if cfg.StoragePath != "data/replay" {
		t.Errorf("storage_path = %s, want data/replay", cfg.StoragePath)
	}

	if cfg.Format != FormatJSON {
		t.Errorf("format = %s, want json", cfg.Format)
	}

	if cfg.MaxFileSize != 100 {
		t.Errorf("max_file_size = %d, want 100", cfg.MaxFileSize)
	}

	if cfg.RetentionDays != 30 {
		t.Errorf("retention_days = %d, want 30", cfg.RetentionDays)
	}
}

func TestNewRecorder(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:     true,
		StoragePath: tmpDir,
		Format:      FormatJSON,
		MaxFileSize: 1, // 1MB
	}

	recorder, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	defer recorder.Close()

	if recorder == nil {
		t.Fatal("expected recorder, got nil")
	}

	if recorder.config != cfg {
		t.Error("recorder config mismatch")
	}
}

func TestRecorder_Record(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:         true,
		StoragePath:     tmpDir,
		Format:          FormatJSON,
		MaxFileSize:     1,
		CaptureRequest:  true,
		CaptureResponse: false,
		SkipPaths:       []string{"/healthz"},
		SkipMethods:     []string{"OPTIONS"},
	}

	recorder, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	defer recorder.Close()

	// Create a test request
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "TestAgent")

	// Record the request
	err = recorder.Record(req, nil, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	// Force flush
	recorder.Close()

	// Verify file was created
	files, err := recorder.ListRecordings()
	if err != nil {
		t.Fatalf("ListRecordings failed: %v", err)
	}

	if len(files) == 0 {
		t.Error("expected recording files to be created")
	}
}

func TestRecorder_shouldRecord_SkipPaths(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:     true,
		StoragePath: tmpDir,
		SkipPaths:   []string{"/healthz", "/metrics"},
	}

	recorder, _ := NewRecorder(cfg)
	defer recorder.Close()

	// Request to /healthz should be skipped
	req, _ := http.NewRequest("GET", "http://example.com/healthz", nil)
	if recorder.shouldRecord(req) {
		t.Error("expected /healthz to be skipped")
	}

	// Request to /metrics should be skipped
	req, _ = http.NewRequest("GET", "http://example.com/metrics", nil)
	if recorder.shouldRecord(req) {
		t.Error("expected /metrics to be skipped")
	}

	// Request to /api/data should be recorded
	req, _ = http.NewRequest("GET", "http://example.com/api/data", nil)
	if !recorder.shouldRecord(req) {
		t.Error("expected /api/data to be recorded")
	}
}

func TestRecorder_shouldRecord_SkipMethods(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:     true,
		StoragePath: tmpDir,
		SkipMethods: []string{"OPTIONS", "HEAD"},
	}

	recorder, _ := NewRecorder(cfg)
	defer recorder.Close()

	// OPTIONS should be skipped
	req, _ := http.NewRequest("OPTIONS", "http://example.com/test", nil)
	if recorder.shouldRecord(req) {
		t.Error("expected OPTIONS to be skipped")
	}

	// GET should be recorded
	req, _ = http.NewRequest("GET", "http://example.com/test", nil)
	if !recorder.shouldRecord(req) {
		t.Error("expected GET to be recorded")
	}
}

func TestRecorder_ListRecordings(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:     true,
		StoragePath: tmpDir,
	}

	recorder, _ := NewRecorder(cfg)
	defer recorder.Close()

	// Create a dummy file
	dummyFile := filepath.Join(tmpDir, "requests-20260405-000.log")
	os.WriteFile(dummyFile, []byte("test"), 0644)

	files, err := recorder.ListRecordings()
	if err != nil {
		t.Fatalf("ListRecordings failed: %v", err)
	}

	if len(files) == 0 {
		t.Error("expected at least one recording file")
	}
}

func TestRecorder_GetStats(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Enabled:     true,
		StoragePath: tmpDir,
		Format:      FormatJSON,
	}

	recorder, _ := NewRecorder(cfg)
	defer recorder.Close()

	stats := recorder.GetStats()

	if stats["enabled"] != true {
		t.Error("expected enabled=true in stats")
	}

	if stats["format"] != FormatJSON {
		t.Errorf("format = %v, want json", stats["format"])
	}
}

func TestRecordedRequest_Marshal(t *testing.T) {
	req := &RecordedRequest{
		Timestamp:  time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		Method:     "POST",
		URL:        "http://example.com/api/test",
		Path:       "/api/test",
		Query:      "foo=bar",
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       []byte(`{"key":"value"}`),
		RemoteAddr: "192.168.1.1",
		RequestID:  "req-123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	// Verify it contains expected fields
	if !strings.Contains(string(data), "POST") {
		t.Error("expected JSON to contain method")
	}

	if !strings.Contains(string(data), "req-123") {
		t.Error("expected JSON to contain request_id")
	}
}

func TestParseRecords(t *testing.T) {
	// Create temp file with JSON records
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.log")

	// Write test records
	records := []string{
		`{"timestamp":"2026-04-05T12:00:00Z","method":"GET","url":"http://example.com/test1","path":"/test1"}`,
		`{"timestamp":"2026-04-05T12:01:00Z","method":"POST","url":"http://example.com/test2","path":"/test2"}`,
	}

	f, _ := os.Create(filePath)
	for _, rec := range records {
		f.WriteString(rec + "\n")
	}
	f.Close()

	// Parse records
	file, _ := os.Open(filePath)
	defer file.Close()

	replayer := NewReplayer(&ReplayerConfig{Enabled: true})
	parsed, err := replayer.parseRecords(file)
	if err != nil {
		t.Fatalf("parseRecords failed: %v", err)
	}

	if len(parsed) != 2 {
		t.Errorf("parsed %d records, want 2", len(parsed))
	}

	if parsed[0].Method != "GET" {
		t.Errorf("first record method = %s, want GET", parsed[0].Method)
	}

	if parsed[1].Method != "POST" {
		t.Errorf("second record method = %s, want POST", parsed[1].Method)
	}
}

func TestFilterRecords(t *testing.T) {
	replayer := NewReplayer(&ReplayerConfig{Enabled: true})

	records := []*RecordedRequest{
		{Method: "GET", Path: "/api/users", ResponseStatus: 200},
		{Method: "POST", Path: "/api/users", ResponseStatus: 201},
		{Method: "GET", Path: "/api/posts", ResponseStatus: 200},
		{Method: "DELETE", Path: "/api/users/1", ResponseStatus: 204},
	}

	// Filter by method
	filter := ReplayFilter{Methods: []string{"GET"}}
	filtered := replayer.filterRecords(records, filter)

	if len(filtered) != 2 {
		t.Errorf("filtered %d records, want 2", len(filtered))
	}

	// Filter by status
	filter = ReplayFilter{StatusCode: 201}
	filtered = replayer.filterRecords(records, filter)

	if len(filtered) != 1 {
		t.Errorf("filtered %d records, want 1", len(filtered))
	}

	// Filter by path
	filter = ReplayFilter{Paths: []string{"/api/users"}}
	filtered = replayer.filterRecords(records, filter)

	if len(filtered) != 3 {
		t.Errorf("filtered %d records, want 3", len(filtered))
	}
}

func TestDefaultReplayerConfig(t *testing.T) {
	cfg := DefaultReplayerConfig()

	if cfg.Enabled {
		t.Error("expected replayer to be disabled by default")
	}

	if cfg.RateLimit != 100 {
		t.Errorf("rate_limit = %d, want 100", cfg.RateLimit)
	}

	if cfg.Concurrency != 10 {
		t.Errorf("concurrency = %d, want 10", cfg.Concurrency)
	}

	if cfg.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", cfg.Timeout)
	}
}

func TestNewReplayer(t *testing.T) {
	cfg := &ReplayerConfig{
		Enabled:     true,
		RateLimit:   50,
		Concurrency: 5,
	}

	replayer := NewReplayer(cfg)

	if replayer == nil {
		t.Fatal("expected replayer, got nil")
	}

	if replayer.config != cfg {
		t.Error("config mismatch")
	}
}

func TestIsHopByHop(t *testing.T) {
	tests := []struct {
		header   string
		expected bool
	}{
		{"Connection", true},
		{"Keep-Alive", true},
		{"Proxy-Authorization", true},
		{"Content-Type", false},
		{"Authorization", false},
	}

	for _, tt := range tests {
		result := isHopByHop(tt.header)
		if result != tt.expected {
			t.Errorf("isHopByHop(%s) = %v, want %v", tt.header, result, tt.expected)
		}
	}
}

func TestLayer_Name(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Name() != "replay-recorder" {
		t.Errorf("Name() = %s, want replay-recorder", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Order() != 145 {
		t.Errorf("Order() = %d, want 145", layer.Order())
	}
}

func TestLayer_Process(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

func TestManager_NewManager(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &ManagerConfig{
		Recording: &Config{
			Enabled:     true,
			StoragePath: tmpDir,
		},
		Replay: &ReplayerConfig{
			Enabled: true,
		},
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer manager.Close()

	if manager == nil {
		t.Fatal("expected manager, got nil")
	}

	if manager.recorder == nil {
		t.Error("expected recorder to be initialized")
	}

	if manager.replayer == nil {
		t.Error("expected replayer to be initialized")
	}
}

func TestManager_Disabled(t *testing.T) {
	cfg := &ManagerConfig{
		Recording: &Config{
			Enabled: false,
		},
		Replay: &ReplayerConfig{
			Enabled: false,
		},
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer manager.Close()

	if manager.IsRecordingEnabled() {
		t.Error("expected recording to be disabled")
	}

	if manager.IsReplayEnabled() {
		t.Error("expected replay to be disabled")
	}
}
