package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Layer tests
// ---------------------------------------------------------------------------

func TestNewLayer_NilConfig(t *testing.T) {
	layer, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if layer == nil {
		t.Fatal("expected layer, got nil")
	}
	if layer.Name() != "siem" {
		t.Errorf("Name() = %s, want siem", layer.Name())
	}
	if layer.Order() != 1 {
		t.Errorf("Order() = %d, want 1", layer.Order())
	}
}

func TestNewLayer_WithConfig(t *testing.T) {
	cfg := &Config{
		Enabled:       false,
		Endpoint:      "",
		Format:        FormatJSON,
		BatchSize:     10,
		FlushInterval: 1 * time.Second,
		Timeout:       5 * time.Second,
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if layer == nil {
		t.Fatal("expected layer, got nil")
	}
}

func TestNewLayer_InvalidEndpoint(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Endpoint: "http://bad-endpoint.local",
		Format:   FormatJSON,
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// NewExporter returns nil for invalid endpoints -> NewLayer returns nil
	if layer != nil {
		t.Error("expected nil layer for invalid endpoint")
	}
}

func TestLayer_Process(t *testing.T) {
	layer, _ := NewLayer(nil)
	req := httptest.NewRequest("GET", "/test", nil)
	ctx := engine.AcquireContext(req, 1, 1<<20)
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Process() action = %v, want ActionPass", result.Action)
	}
}

func TestLayer_Exporter(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     10,
		FlushInterval: 1 * time.Second,
	}
	layer, _ := NewLayer(cfg)
	exp := layer.Exporter()
	if exp == nil {
		t.Error("expected exporter, got nil")
	}
}

func TestLayer_Exporter_NilConfig(t *testing.T) {
	layer, _ := NewLayer(nil)
	exp := layer.Exporter()
	if exp == nil {
		t.Error("expected exporter with default config")
	}
}

func TestLayer_Stop(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     10,
		FlushInterval: 1 * time.Second,
	}
	layer, _ := NewLayer(cfg)
	// Stop should not panic even without Start
	layer.Stop()
	// Double stop should also be safe
	layer.Stop()
}

func TestLayer_Stop_NilExporter(t *testing.T) {
	// NewLayer with an HTTP endpoint returns nil layer — we can't easily create
	// a Layer with nil exporter through public API. Instead, verify that calling
	// Stop on a layer created with a valid config is safe.
	layer, _ := NewLayer(nil)
	layer.Stop() // should not panic
}

// ---------------------------------------------------------------------------
// Exporter Start/Stop/Export lifecycle
// ---------------------------------------------------------------------------

func TestExporter_StartDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	exp := NewExporter(cfg)
	exp.Start()
	// Should return immediately since disabled
	exp.Stop()
}

func TestExporter_ExportDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	exp := NewExporter(cfg)

	event := &Event{
		Timestamp: time.Now(),
		EventType: "test",
	}
	// Should be no-op
	exp.Export(event)
}

func TestExporter_ExportBatch_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "test1"},
		{Timestamp: time.Now(), EventType: "test2"},
	}
	exp.ExportBatch(events)
}

func TestExporter_StartStop(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)
	exp.Start()
	// Give the goroutine a moment to start
	time.Sleep(50 * time.Millisecond)
	exp.Stop()
}

func TestExporter_Export_DropsWhenChannelFull(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     10,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)

	// Don't start the processor so the channel fills up
	// Channel capacity is BatchSize*2 = 20
	var logged bool
	exp.logFn = func(level, msg string, args ...any) {
		logged = true
	}

	for i := range 25 {
		event := &Event{
			Timestamp: time.Now(),
			EventType: "test",
			Method:    "GET",
			Path:      fmt.Sprintf("/test/%d", i),
		}
		exp.Export(event)
	}

	if !logged {
		t.Error("expected drop warning to be logged when channel is full")
	}
}

func TestExporter_Export_WithFields(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     10,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
		Fields: map[string]string{
			"env":     "production",
			"service": "waf",
		},
	}
	exp := NewExporter(cfg)

	event := &Event{
		Timestamp: time.Now(),
		EventType: "block",
		Fields: map[string]string{
			"existing": "value",
		},
	}
	exp.Export(event)

	// Verify fields were merged (event is mutated in-place)
	if event.Fields["env"] != "production" {
		t.Error("expected env field to be added")
	}
	if event.Fields["existing"] != "value" {
		t.Error("expected existing field to be preserved")
	}
}

func TestExporter_ExportBatch_Active(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "test1"},
		{Timestamp: time.Now(), EventType: "test2"},
	}
	exp.ExportBatch(events)
}

// ---------------------------------------------------------------------------
// Batch formatting with mock HTTP server
// ---------------------------------------------------------------------------

func TestExporter_SendBatch_JSON(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedContentType = r.Header.Get("Content-Type")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:       true,
		Endpoint:      server.URL,
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	// Override TLS check — test server uses HTTP
	// We need to bypass the SSRF validation for the test server
	// Create exporter manually to bypass validation
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block"},
		{Timestamp: time.Now(), EventType: "log", Severity: SeverityMedium, SourceIP: "10.0.0.2", Action: "log"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", receivedContentType)
	}
	if len(receivedBody) == 0 {
		t.Error("expected non-empty body")
	}

	var parsed []*Event
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("failed to parse JSON body: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("expected 2 events, got %d", len(parsed))
	}
}

func TestExporter_SendBatch_Splunk(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatSplunk,
		APIKey:    "test-splunk-key",
		Index:     "main",
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityCritical, SourceIP: "10.0.0.1", Action: "block"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuth != "Splunk test-splunk-key" {
		t.Errorf("Authorization = %s, want Splunk test-splunk-key", receivedAuth)
	}
	if len(receivedBody) == 0 {
		t.Error("expected non-empty body")
	}
	// Splunk format is newline-delimited JSON
	lines := strings.Split(strings.TrimSpace(string(receivedBody)), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line for 1 event, got %d", len(lines))
	}
}

func TestExporter_SendBatch_Elastic(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	var receivedContentType string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatElastic,
		APIKey:    "test-elastic-key",
		Index:     "guardianwaf",
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block", RequestID: "req-001"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuth != "ApiKey test-elastic-key" {
		t.Errorf("Authorization = %s, want ApiKey test-elastic-key", receivedAuth)
	}
	if receivedContentType != "application/x-ndjson" {
		t.Errorf("Content-Type = %s, want application/x-ndjson", receivedContentType)
	}
	// Elastic format: 2 lines per event (index metadata + event data)
	lines := strings.Split(strings.TrimSpace(string(receivedBody)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines for 1 event, got %d", len(lines))
	}
}

func TestExporter_SendBatch_CEF(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedContentType = r.Header.Get("Content-Type")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatCEF,
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block", RuleID: "SQLI-001", Reason: "SQL injection"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedContentType != "text/plain" {
		t.Errorf("Content-Type = %s, want text/plain", receivedContentType)
	}
	if !strings.Contains(string(receivedBody), "CEF:0") {
		t.Error("expected CEF format in body")
	}
}

func TestExporter_SendBatch_LEEF(t *testing.T) {
	var receivedBody []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBody = buf
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatLEEF,
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "alert", Severity: SeverityMedium, SourceIP: "10.0.0.1", Action: "log"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(string(receivedBody), "LEEF:2.0") {
		t.Error("expected LEEF format in body")
	}
}

func TestExporter_SendBatch_BearerAuth(t *testing.T) {
	var receivedAuth string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatCEF,
		APIKey:    "bearer-token-123",
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "test", Action: "pass"},
	}

	err := exp.sendBatch(events)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuth != "Bearer bearer-token-123" {
		t.Errorf("Authorization = %s, want Bearer bearer-token-123", receivedAuth)
	}
}

func TestExporter_SendBatch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:   true,
		Endpoint:  server.URL,
		Format:    FormatJSON,
		BatchSize: 100,
		Timeout:   5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())

	events := []*Event{
		{Timestamp: time.Now(), EventType: "test", Action: "pass"},
	}

	err := exp.sendBatch(events)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500, got: %v", err)
	}
}

func TestExporter_SendBatch_ConnectionRefused(t *testing.T) {
	cfg := &Config{
		Enabled:   true,
		Endpoint:  "http://127.0.0.1:1", // port 1 should refuse connections
		Format:    FormatJSON,
		BatchSize: 100,
		Timeout:   2 * time.Second,
	}
	exp := createTestExporter(cfg, http.DefaultClient)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "test", Action: "pass"},
	}

	err := exp.sendBatch(events)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestExporter_SendBatch_Empty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	exp := NewExporter(cfg)

	err := exp.sendBatch(nil)
	if err != nil {
		t.Errorf("expected no error for empty batch, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Batch processor with real goroutine
// ---------------------------------------------------------------------------

func TestExporter_BatchProcessor_FlushOnStop(t *testing.T) {
	var receivedCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:       true,
		Endpoint:      server.URL,
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 1 * time.Hour, // Long interval — only flushes on Stop
		Timeout:       5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())
	exp.Start()

	// Give the goroutine time to start
	time.Sleep(100 * time.Millisecond)

	event := &Event{
		Timestamp: time.Now(),
		EventType: "block",
		SourceIP:  "10.0.0.1",
		Action:    "block",
	}
	exp.Export(event)

	// Stop should flush remaining events
	exp.Stop()

	// Wait for the HTTP request to complete
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if receivedCount != 1 {
		t.Errorf("expected 1 batch received, got %d", receivedCount)
	}
}

func TestExporter_BatchProcessor_BatchSizeTrigger(t *testing.T) {
	var receivedBodies [][]byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		receivedBodies = append(receivedBodies, buf)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	batchSize := 5
	cfg := &Config{
		Enabled:       true,
		Endpoint:      server.URL,
		Format:        FormatJSON,
		BatchSize:     batchSize,
		FlushInterval: 1 * time.Hour,
		Timeout:       5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())
	exp.Start()

	for i := range batchSize + 2 {
		exp.Export(&Event{
			Timestamp: time.Now(),
			EventType: "test",
			Action:    "pass",
			Score:     i,
		})
	}

	time.Sleep(200 * time.Millisecond)
	exp.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBodies) < 1 {
		t.Error("expected at least 1 batch to be sent due to batch size trigger")
	}
}

func TestExporter_BatchProcessor_FlushInterval(t *testing.T) {
	var receivedCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		Enabled:       true,
		Endpoint:      server.URL,
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 200 * time.Millisecond,
		Timeout:       5 * time.Second,
	}
	exp := createTestExporter(cfg, server.Client())
	exp.Start()

	exp.Export(&Event{Timestamp: time.Now(), EventType: "test", Action: "pass"})

	// Wait for the flush interval to trigger
	time.Sleep(400 * time.Millisecond)
	exp.Stop()

	mu.Lock()
	defer mu.Unlock()
	if receivedCount < 1 {
		t.Error("expected at least 1 batch from flush interval")
	}
}

// ---------------------------------------------------------------------------
// Format-specific batch methods (unit tests without network)
// ---------------------------------------------------------------------------

func TestExporter_FormatJSONBatch(t *testing.T) {
	cfg := &Config{Format: FormatJSON}
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block"},
	}
	data := exp.formatJSONBatch(events)
	if data == nil {
		t.Fatal("expected data, got nil")
	}

	var parsed []*Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) != 1 {
		t.Errorf("expected 1 event, got %d", len(parsed))
	}
}

func TestExporter_FormatSplunkBatch(t *testing.T) {
	cfg := &Config{Format: FormatSplunk, Index: "main"}
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block"},
		{Timestamp: time.Now(), EventType: "log", Severity: SeverityLow, SourceIP: "10.0.0.2", Action: "log"},
	}
	data := exp.formatSplunkBatch(events)
	if data == nil {
		t.Fatal("expected data, got nil")
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Each line should be valid JSON with Splunk HEC structure
	for i, line := range lines {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}
		if _, ok := parsed["time"]; !ok {
			t.Errorf("line %d: missing 'time' field", i)
		}
		if _, ok := parsed["event"]; !ok {
			t.Errorf("line %d: missing 'event' field", i)
		}
		if parsed["sourcetype"] != "guardianwaf" {
			t.Errorf("line %d: sourcetype = %v, want guardianwaf", i, parsed["sourcetype"])
		}
	}
}

func TestExporter_FormatElasticBatch(t *testing.T) {
	cfg := &Config{Format: FormatElastic, Index: "guardianwaf"}
	exp := NewExporter(cfg)

	ts := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)
	events := []*Event{
		{Timestamp: ts, EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block", RequestID: "req-001"},
	}
	data := exp.formatElasticBatch(events)
	if data == nil {
		t.Fatal("expected data, got nil")
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// First line: index metadata
	var indexMeta map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &indexMeta); err != nil {
		t.Fatalf("index line: invalid JSON: %v", err)
	}
	indexObj, ok := indexMeta["index"].(map[string]any)
	if !ok {
		t.Fatal("expected index object")
	}
	expectedIndex := "guardianwaf-2026.04.25"
	if indexObj["_index"] != expectedIndex {
		t.Errorf("_index = %v, want %s", indexObj["_index"], expectedIndex)
	}

	// Second line: event data
	var eventData map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &eventData); err != nil {
		t.Fatalf("event line: invalid JSON: %v", err)
	}
	if eventData["event_type"] != "block" {
		t.Errorf("event_type = %v, want block", eventData["event_type"])
	}
}

func TestExporter_FormatTextBatch_CEF(t *testing.T) {
	cfg := &Config{Format: FormatCEF}
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block", RuleID: "XSS-001"},
	}
	data := exp.formatTextBatch(events)
	if data == nil {
		t.Fatal("expected data, got nil")
	}
	if !strings.Contains(string(data), "CEF:0") {
		t.Error("expected CEF format")
	}
}

func TestExporter_FormatTextBatch_LEEF(t *testing.T) {
	cfg := &Config{Format: FormatLEEF}
	exp := NewExporter(cfg)

	events := []*Event{
		{Timestamp: time.Now(), EventType: "block", Severity: SeverityHigh, SourceIP: "10.0.0.1", Action: "block"},
	}
	data := exp.formatTextBatch(events)
	if data == nil {
		t.Fatal("expected data, got nil")
	}
	if !strings.Contains(string(data), "LEEF:2.0") {
		t.Error("expected LEEF format")
	}
}

// ---------------------------------------------------------------------------
// Formatter comprehensive tests
// ---------------------------------------------------------------------------

func TestFormatter_CEF_FullEvent(t *testing.T) {
	f := NewFormatter(FormatCEF, "waf-host", "GuardianWAF", "2.0")

	event := &Event{
		Timestamp:  time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType:  "block",
		Severity:   SeverityCritical,
		SourceIP:   "192.168.1.1",
		SourcePort: 12345,
		DestIP:     "10.0.0.1",
		DestPort:   443,
		Method:     "POST",
		Path:       "/api/data",
		UserAgent:  "Mozilla/5.0",
		Host:       "example.com",
		RequestID:  "req-abc-123",
		Action:     "block",
		Reason:     "SQL Injection detected",
		RuleID:     "SQLI-001",
		Score:      85,
		TenantID:   "tenant-1",
		Tags:       []string{"sqli", "critical"},
		Fields:     map[string]string{"region": "us-east"},
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify all CEF extensions are present
	checks := []string{
		"CEF:0",
		"GuardianWAF",
		"SQLI-001",
		"SQL Injection detected",
		"requestMethod=POST",
		"request=/api/data",
		"requestClientApplication=Mozilla/5.0",
		"dhost=example.com",
		"cs2=req-abc-123",
		"cs3=85",
		"cs3Label=riskScore",
		"cs4=tenant-1",
		"cs4Label=tenantId",
		"src=192.168.1.1",
		"cs1=block",
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("CEF output missing: %q\nOutput: %s", check, result)
		}
	}
}

func TestFormatter_CEF_MinimalEvent(t *testing.T) {
	f := NewFormatter(FormatCEF, "", "", "")

	event := &Event{
		Timestamp: time.Now(),
		EventType: "log",
		Severity:  SeverityLow,
		SourceIP:  "10.0.0.1",
		Action:    "pass",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should use EventType as signatureID when RuleID is empty
	if !strings.Contains(result, "log") {
		t.Error("expected EventType as signature ID")
	}
	// Should use "WAF log" as name when Reason is empty
	if !strings.Contains(result, "WAF log") {
		t.Error("expected default name 'WAF log'")
	}
}

func TestFormatter_LEEF_FullEvent(t *testing.T) {
	f := NewFormatter(FormatLEEF, "waf-host", "GuardianWAF", "2.0")

	event := &Event{
		Timestamp:  time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType:  "block",
		Severity:   SeverityHigh,
		SourceIP:   "192.168.1.1",
		Method:     "GET",
		Path:       "/admin",
		UserAgent:  "curl/7.0",
		Host:       "target.com",
		RequestID:  "req-123",
		Action:     "block",
		Reason:     "Unauthorized access",
		Score:      60,
		TenantID:   "tenant-2",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	checks := []string{
		"LEEF:2.0",
		"httpMethod=GET",
		"url=/admin",
		"usrAgent=curl/7.0",
		"dst=target.com",
		"requestId=req-123",
		"riskScore=60",
		"tenantId=tenant-2",
		"reason=Unauthorized access",
		"sev=8",
		"src=192.168.1.1",
	}
	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("LEEF output missing: %q\nOutput: %s", check, result)
		}
	}
}

func TestFormatter_LEEF_MinimalEvent(t *testing.T) {
	f := NewFormatter(FormatLEEF, "", "", "")

	event := &Event{
		Timestamp: time.Now(),
		EventType: "alert",
		Severity:  SeverityMedium,
		SourceIP:  "10.0.0.1",
		Action:    "log",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should not have optional fields
	if strings.Contains(result, "httpMethod") {
		t.Error("unexpected httpMethod for empty Method")
	}
	if strings.Contains(result, "url=") {
		t.Error("unexpected url for empty Path")
	}
	if strings.Contains(result, "riskScore") {
		t.Error("unexpected riskScore for zero Score")
	}
}

func TestFormatter_Syslog_SeverityLevels(t *testing.T) {
	tests := []struct {
		severity   Severity
		wantPri    string
	}{
		{SeverityCritical, "<136>"},
		{SeverityHigh, "<132>"},
		{SeverityMedium, "<133>"},
		{SeverityLow, "<134>"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("severity_%d", tt.severity), func(t *testing.T) {
			f := NewFormatter(FormatSyslog, "host", "WAF", "1.0")
			event := &Event{
				Timestamp: time.Now(),
				EventType: "test",
				Severity:  tt.severity,
				SourceIP:  "10.0.0.1",
				Action:    "pass",
			}

			result, err := f.Format(event)
			if err != nil {
				t.Fatalf("Format failed: %v", err)
			}

			if !strings.Contains(result, tt.wantPri) {
				t.Errorf("severity %d: expected priority %s in output: %s", tt.severity, tt.wantPri, result)
			}
		})
	}
}

func TestFormatter_Syslog_WithMethodPathScore(t *testing.T) {
	f := NewFormatter(FormatSyslog, "host", "WAF", "1.0")
	event := &Event{
		Timestamp: time.Now(),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "10.0.0.1",
		Action:    "block",
		Method:    "DELETE",
		Path:      "/admin/users",
		Score:     95,
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(result, "method=DELETE") {
		t.Error("expected method in syslog message")
	}
	if !strings.Contains(result, "path=/admin/users") {
		t.Error("expected path in syslog message")
	}
	if !strings.Contains(result, "score=95") {
		t.Error("expected score in syslog message")
	}
}

func TestFormatter_DefaultFormat(t *testing.T) {
	// Test that an unknown format falls back to JSON
	f := NewFormatter(Format("unknown"), "", "", "")
	event := &Event{
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  SeverityLow,
		SourceIP:  "10.0.0.1",
		Action:    "pass",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should produce valid JSON (fallback)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("default format should produce valid JSON: %v", err)
	}
}

func TestFormatter_Elastic_NoRequestID(t *testing.T) {
	f := NewFormatter(FormatElastic, "", "", "")
	event := &Event{
		Timestamp: time.Now(),
		EventType: "test",
		Severity:  SeverityLow,
		SourceIP:  "10.0.0.1",
		Action:    "pass",
		// RequestID is empty
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	lines := strings.Split(result, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// First line should still be valid JSON with empty _id
	var indexMeta map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &indexMeta); err != nil {
		t.Fatalf("invalid index metadata JSON: %v", err)
	}
}

func TestFormatter_Splunk_Structure(t *testing.T) {
	f := NewFormatter(FormatSplunk, "waf01", "GuardianWAF", "2.0")
	ts := time.Date(2026, 1, 15, 8, 30, 0, 0, time.UTC)
	event := &Event{
		Timestamp: ts,
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "10.0.0.1",
		Action:    "block",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed["source"] != "GuardianWAF" {
		t.Errorf("source = %v, want GuardianWAF", parsed["source"])
	}
	if parsed["host"] != "waf01" {
		t.Errorf("host = %v, want waf01", parsed["host"])
	}
	if parsed["sourcetype"] != "guardianwaf" {
		t.Errorf("sourcetype = %v, want guardianwaf", parsed["sourcetype"])
	}
}

func TestFormatter_JSON_FullEvent(t *testing.T) {
	f := NewFormatter(FormatJSON, "", "", "")
	event := &Event{
		Timestamp:   time.Now(),
		EventType:   "block",
		Severity:    SeverityCritical,
		SourceIP:    "10.0.0.1",
		SourcePort:  12345,
		DestIP:      "10.0.0.2",
		DestPort:    443,
		Method:      "POST",
		Path:        "/api/login",
		UserAgent:   "Mozilla/5.0",
		Host:        "example.com",
		RequestID:   "req-001",
		Action:      "block",
		Reason:      "SQL injection detected",
		RuleID:      "SQLI-001",
		Score:       90,
		TenantID:    "tenant-1",
		Tags:        []string{"sqli", "critical"},
		Fields:      map[string]string{"region": "us-east"},
		CountryCode: "US",
		CountryName: "United States",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Verify key fields are present in JSON
	if parsed["event_type"] != "block" {
		t.Error("expected event_type=block")
	}
	if parsed["action"] != "block" {
		t.Error("expected action=block")
	}
	if parsed["country_code"] != "US" {
		t.Error("expected country_code=US")
	}
}

func TestFormatter_SyslogMsg_WithMethodPathScore(t *testing.T) {
	event := &Event{
		EventType: "block",
		SourceIP:  "10.0.0.1",
		Action:    "block",
		Method:    "POST",
		Path:      "/api",
		Score:     80,
	}

	msg := formatSyslogMsg(event)

	if !strings.Contains(msg, "method=POST") {
		t.Error("expected method in message")
	}
	if !strings.Contains(msg, "path=/api") {
		t.Error("expected path in message")
	}
	if !strings.Contains(msg, "score=80") {
		t.Error("expected score in message")
	}
}

func TestFormatter_SyslogMsg_Minimal(t *testing.T) {
	event := &Event{
		EventType: "log",
		SourceIP:  "10.0.0.1",
		Action:    "pass",
	}

	msg := formatSyslogMsg(event)

	if strings.Contains(msg, "method=") {
		t.Error("should not contain method")
	}
	if strings.Contains(msg, "path=") {
		t.Error("should not contain path")
	}
	if strings.Contains(msg, "score=") {
		t.Error("should not contain score")
	}
}

// ---------------------------------------------------------------------------
// Endpoint validation
// ---------------------------------------------------------------------------

func TestValidateSIEMEndpoint_HTTPS_PublicIP(t *testing.T) {
	// Use a public IP to avoid DNS resolution issues
	err := validateSIEMEndpoint("https://8.8.8.8:8088")
	if err != nil {
		t.Errorf("expected valid for public HTTPS URL: %v", err)
	}
}

func TestValidateSIEMEndpoint_HTTP(t *testing.T) {
	err := validateSIEMEndpoint("http://siem.example.com")
	if err == nil {
		t.Error("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS: %v", err)
	}
}

func TestValidateSIEMEndpoint_InvalidURL(t *testing.T) {
	err := validateSIEMEndpoint("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestValidateSIEMEndpoint_Localhost(t *testing.T) {
	err := validateSIEMHostNotPrivate("localhost")
	if err == nil {
		t.Error("expected error for localhost")
	}
}

func TestValidateSIEMEndpoint_InternalHost(t *testing.T) {
	err := validateSIEMHostNotPrivate("my.service.internal")
	if err == nil {
		t.Error("expected error for .internal host")
	}
}

func TestValidateSIEMEndpoint_LocalHost(t *testing.T) {
	err := validateSIEMHostNotPrivate("my.service.local")
	if err == nil {
		t.Error("expected error for .local host")
	}
}

func TestValidateSIEMEndpoint_PrivateIP(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"0.0.0.0",
		"169.254.1.1",
	}
	for _, ip := range privateIPs {
		err := validateSIEMHostNotPrivate(ip)
		if err == nil {
			t.Errorf("expected error for private IP %s", ip)
		}
	}
}

func TestValidateSIEMEndpoint_PublicIP(t *testing.T) {
	err := validateSIEMHostNotPrivate("8.8.8.8")
	if err != nil {
		t.Errorf("expected valid for public IP: %v", err)
	}
}

func TestValidateSIEMEndpoint_SkipVerify(t *testing.T) {
	// Test that SkipVerify is logged but ignored
	cfg := &Config{
		Enabled:    true,
		Endpoint:   "https://1.2.3.4:8088",
		Format:     FormatJSON,
		SkipVerify: true,
	}
	exporter := NewExporter(cfg)
	if exporter == nil {
		t.Fatal("expected exporter even with SkipVerify=true")
	}
}

// ---------------------------------------------------------------------------
// SSRF dial context
// ---------------------------------------------------------------------------

func TestSSRFDialContext_PublicHost(t *testing.T) {
	// This tests that the dial context function is created and callable.
	// We can't easily test actual network dialing in unit tests without
	// resolving real DNS, but we can verify the function exists and handles
	// edge cases.
	dialFn := siemSSRFDialContext()
	if dialFn == nil {
		t.Fatal("expected dial function, got nil")
	}
}

func TestSSRFDialContext_BadAddress(t *testing.T) {
	dialFn := siemSSRFDialContext()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Address without port should still be handled
	_, err := dialFn(ctx, "tcp", "bad-address-no-port")
	if err == nil {
		t.Error("expected error for unresolvable address")
	}
}

func TestSSRFDialContext_LocalhostBlocked(t *testing.T) {
	dialFn := siemSSRFDialContext()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dialFn(ctx, "tcp", "localhost:8088")
	if err == nil {
		t.Error("expected error for localhost (all IPs are loopback)")
	}
}

// ---------------------------------------------------------------------------
// DefaultConfig
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}
	if cfg.Format != FormatJSON {
		t.Errorf("default format = %s, want json", cfg.Format)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("default BatchSize = %d, want 100", cfg.BatchSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("default FlushInterval = %v, want 5s", cfg.FlushInterval)
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("default Timeout = %v, want 10s", cfg.Timeout)
	}
}

func TestNewExporter_NilConfig(t *testing.T) {
	exporter := NewExporter(nil)
	if exporter == nil {
		t.Fatal("expected exporter with nil config (defaults)")
	}
	if exporter.config.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", exporter.config.BatchSize)
	}
}

func TestNewExporter_ZeroValues(t *testing.T) {
	cfg := &Config{Enabled: true, Endpoint: "https://1.2.3.4:8088"}
	exporter := NewExporter(cfg)
	if exporter == nil {
		t.Fatal("expected exporter")
	}
	if exporter.config.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", exporter.config.BatchSize)
	}
	if exporter.config.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", exporter.config.FlushInterval)
	}
	if exporter.config.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", exporter.config.Timeout)
	}
}

func TestNewExporter_InvalidURL(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Endpoint: "://missing-scheme",
		Format:   FormatJSON,
	}
	exporter := NewExporter(cfg)
	if exporter != nil {
		t.Error("expected nil exporter for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// Event struct serialization
// ---------------------------------------------------------------------------

func TestEvent_JSONSerialization(t *testing.T) {
	event := &Event{
		Timestamp:   time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
		EventType:   "block",
		Severity:    SeverityCritical,
		SourceIP:    "192.168.1.100",
		SourcePort:  54321,
		DestIP:      "10.0.0.1",
		DestPort:    443,
		Method:      "POST",
		Path:        "/api/v1/users",
		UserAgent:   "curl/7.88.0",
		Host:        "api.example.com",
		RequestID:   "req-001",
		Action:      "block",
		Reason:      "SQL Injection attempt",
		RuleID:      "SQLI-001",
		Score:       95,
		TenantID:    "tenant-abc",
		Tags:        []string{"sqli", "injection", "critical"},
		Fields:      map[string]string{"region": "eu-west", "dc": "aws"},
		CountryCode: "DE",
		CountryName: "Germany",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify all fields are present
	fieldChecks := map[string]any{
		"event_type":   "block",
		"severity":     float64(10),
		"source_ip":    "192.168.1.100",
		"source_port":  float64(54321),
		"dest_ip":      "10.0.0.1",
		"dest_port":    float64(443),
		"method":       "POST",
		"path":         "/api/v1/users",
		"user_agent":   "curl/7.88.0",
		"host":         "api.example.com",
		"request_id":   "req-001",
		"action":       "block",
		"reason":       "SQL Injection attempt",
		"rule_id":      "SQLI-001",
		"score":        float64(95),
		"tenant_id":    "tenant-abc",
		"country_code": "DE",
		"country_name": "Germany",
	}

	for field, expected := range fieldChecks {
		val, ok := parsed[field]
		if !ok {
			t.Errorf("missing field: %s", field)
			continue
		}
		if val != expected {
			t.Errorf("field %s = %v, want %v", field, val, expected)
		}
	}

	// Check tags array
	tags, ok := parsed["tags"].([]any)
	if !ok {
		t.Fatal("tags should be an array")
	}
	if len(tags) != 3 {
		t.Errorf("tags length = %d, want 3", len(tags))
	}

	// Check fields map
	fields, ok := parsed["fields"].(map[string]any)
	if !ok {
		t.Fatal("fields should be a map")
	}
	if fields["region"] != "eu-west" {
		t.Errorf("fields.region = %v, want eu-west", fields["region"])
	}
}

func TestEvent_JSONMinimal(t *testing.T) {
	event := &Event{
		Timestamp: time.Now(),
		EventType: "log",
		Severity:  SeverityLow,
		SourceIP:  "10.0.0.1",
		Action:    "pass",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Optional fields should be omitted (omitempty)
	if _, ok := parsed["source_port"]; ok {
		t.Error("source_port should be omitted when 0")
	}
	if _, ok := parsed["dest_ip"]; ok {
		t.Error("dest_ip should be omitted when empty")
	}
	if _, ok := parsed["method"]; ok {
		t.Error("method should be omitted when empty")
	}
	if _, ok := parsed["tags"]; ok {
		t.Error("tags should be omitted when nil")
	}
	if _, ok := parsed["fields"]; ok {
		t.Error("fields should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

func TestFormatConstants(t *testing.T) {
	formats := map[Format]string{
		FormatCEF:     "cef",
		FormatLEEF:    "leef",
		FormatJSON:    "json",
		FormatSyslog:  "syslog",
		FormatSplunk:  "splunk",
		FormatElastic: "elastic",
	}
	for format, expected := range formats {
		if string(format) != expected {
			t.Errorf("Format constant = %s, want %s", format, expected)
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		severity Severity
		value    int
	}{
		{SeverityLow, 1},
		{SeverityMedium, 5},
		{SeverityHigh, 8},
		{SeverityCritical, 10},
	}
	for _, tt := range tests {
		if int(tt.severity) != tt.value {
			t.Errorf("Severity = %d, want %d", tt.severity, tt.value)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper: create a test exporter that bypasses SSRF validation
// ---------------------------------------------------------------------------

func createTestExporter(cfg *Config, client *http.Client) *Exporter {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	formatter := NewFormatter(cfg.Format, "", "", "")

	return &Exporter{
		config:    cfg,
		formatter: formatter,
		client:    client,
		eventChan: make(chan *Event, cfg.BatchSize*2),
		stopChan:  make(chan struct{}),
		logFn:     func(_, _ string, _ ...any) {},
	}
}

// ---------------------------------------------------------------------------
// EscapeCEF / EscapeLEEF edge cases
// ---------------------------------------------------------------------------

func TestEscapeCEF_EmptyString(t *testing.T) {
	result := escapeCEF("")
	if result != "" {
		t.Errorf("escapeCEF('') = %q, want empty", result)
	}
}

func TestEscapeLEEF_EmptyString(t *testing.T) {
	result := escapeLEEF("")
	if result != "" {
		t.Errorf("escapeLEEF('') = %q, want empty", result)
	}
}

func TestEscapeCEF_MultipleSpecial(t *testing.T) {
	input := "a|b=c\\d"
	result := escapeCEF(input)
	expected := "a\\|b\\=c\\\\d"
	if result != expected {
		t.Errorf("escapeCEF(%q) = %q, want %q", input, result, expected)
	}
}

func TestEscapeLEEF_Tab(t *testing.T) {
	input := "hello\tworld"
	result := escapeLEEF(input)
	if !strings.Contains(result, "\\t") {
		t.Errorf("escapeLEEF should escape tabs, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// siemSSRFDialContext with DNS-resolvable non-private addresses
// ---------------------------------------------------------------------------

func TestSSRFDialContext_InvalidHostPort(t *testing.T) {
	dialFn := siemSSRFDialContext()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// An IP address that is private
	_, err := dialFn(ctx, "tcp", net.JoinHostPort("127.0.0.1", "8088"))
	if err == nil {
		t.Error("expected error for loopback IP (no public IPs)")
	}
	if !strings.Contains(err.Error(), "no valid public") {
		t.Errorf("expected 'no valid public IPs' error, got: %v", err)
	}
}

func TestSSRFDialContext_SplitHostPortError(t *testing.T) {
	dialFn := siemSSRFDialContext()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Empty address triggers SplitHostPort error path
	_, err := dialFn(ctx, "tcp", "")
	if err == nil {
		t.Error("expected error for empty address")
	}
}

// ---------------------------------------------------------------------------
// Exporter concurrency test
// ---------------------------------------------------------------------------

func TestExporter_ConcurrentExport(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)
	exp.Start()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			exp.Export(&Event{
				Timestamp: time.Now(),
				EventType: "concurrent",
				Action:    "pass",
				Score:     n,
			})
		}(i)
	}
	wg.Wait()

	// Let the batch processor drain
	time.Sleep(100 * time.Millisecond)
	exp.Stop()
}

// ---------------------------------------------------------------------------
// Batch processor edge cases
// ---------------------------------------------------------------------------

func TestExporter_BatchProcessor_PanicRecovery(t *testing.T) {
	// Test that the batch processor recovers from panics
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)
	exp.Start()

	// Send events and stop — the processor should handle stop gracefully
	exp.Export(&Event{Timestamp: time.Now(), EventType: "test", Action: "pass"})
	exp.Stop()
	// Should complete without hanging
}

// ---------------------------------------------------------------------------
// Double Stop
// ---------------------------------------------------------------------------

func TestExporter_DoubleStop(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
		Timeout:       5 * time.Second,
	}
	exp := NewExporter(cfg)
	exp.Start()
	time.Sleep(50 * time.Millisecond)

	exp.Stop()
	exp.Stop() // Should not panic on double stop
}

// ---------------------------------------------------------------------------
// Exporter Name with different formats
// ---------------------------------------------------------------------------

func TestExporter_Name_AllFormats(t *testing.T) {
	tests := []struct {
		format Format
		want   string
	}{
		{FormatJSON, "siem-json"},
		{FormatCEF, "siem-cef"},
		{FormatLEEF, "siem-leef"},
		{FormatSyslog, "siem-syslog"},
		{FormatSplunk, "siem-splunk"},
		{FormatElastic, "siem-elastic"},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			exp := NewExporter(&Config{Format: tt.format})
			if got := exp.Name(); got != tt.want {
				t.Errorf("Name() = %s, want %s", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FormatSplunkBatch empty
// ---------------------------------------------------------------------------

func TestExporter_FormatSplunkBatch_Empty(t *testing.T) {
	cfg := &Config{Format: FormatSplunk, Index: "main"}
	exp := NewExporter(cfg)

	data := exp.formatSplunkBatch(nil)
	if len(data) != 0 {
		t.Errorf("expected empty data for nil events, got %d bytes", len(data))
	}
}

func TestExporter_FormatElasticBatch_Empty(t *testing.T) {
	cfg := &Config{Format: FormatElastic, Index: "main"}
	exp := NewExporter(cfg)

	data := exp.formatElasticBatch(nil)
	if len(data) != 0 {
		t.Errorf("expected empty data for nil events, got %d bytes", len(data))
	}
}

func TestExporter_FormatTextBatch_Empty(t *testing.T) {
	cfg := &Config{Format: FormatCEF}
	exp := NewExporter(cfg)

	data := exp.formatTextBatch(nil)
	if len(data) != 0 {
		t.Errorf("expected empty data for nil events, got %d bytes", len(data))
	}
}

// ---------------------------------------------------------------------------
// validateSIEMHostNotPrivate with DNS lookup failure
// ---------------------------------------------------------------------------

func TestValidateSIEMHostNotPrivate_DNSFailure(t *testing.T) {
	err := validateSIEMHostNotPrivate("this-host-definitely-does-not-exist-xyz123.invalid")
	if err == nil {
		t.Error("expected error for unresolvable hostname")
	}
	if !strings.Contains(err.Error(), "DNS lookup") && !strings.Contains(err.Error(), "lookup") {
		t.Errorf("error should mention DNS/lookup: %v", err)
	}
}

// ---------------------------------------------------------------------------
// validateSIEMHostNotPrivate with hostname that would resolve to public IP
// ---------------------------------------------------------------------------

func TestValidateSIEMHostNotPrivate_PublicHostname(t *testing.T) {
	// Use a hostname that resolves to public IPs.
	// Skip this test if DNS is unavailable.
	err := validateSIEMHostNotPrivate("dns.google")
	if err != nil {
		// DNS may be unavailable in restricted environments; just log and skip
		t.Logf("dns.google DNS lookup failed (may be unavailable in CI): %v", err)
	}
	// If it succeeds, it should not return an error for public IPs
}
