package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// mockEngine implements EngineInterface for testing.
type mockEngine struct {
	stats     any
	config    any
	mode      string
	detectors any
	events    any
	topIPs    any
}

func newMockEngine() *mockEngine {
	return &mockEngine{
		stats: map[string]any{
			"total_requests":   int64(100),
			"blocked_requests": int64(5),
			"passed_requests":  int64(95),
			"avg_latency_us":   int64(150),
		},
		config: map[string]any{
			"mode":   "enforce",
			"listen": ":8088",
		},
		mode: "enforce",
		detectors: []map[string]any{
			{"name": "sqli", "enabled": true, "multiplier": 1.0},
			{"name": "xss", "enabled": true, "multiplier": 1.0},
		},
		events: map[string]any{
			"events": []any{},
			"total":  0,
		},
		topIPs: []map[string]any{},
	}
}

func (m *mockEngine) GetStats() any                { return m.stats }
func (m *mockEngine) GetConfig() any               { return m.config }
func (m *mockEngine) GetMode() string              { return m.mode }
func (m *mockEngine) SetMode(mode string) error    { m.mode = mode; return nil }
func (m *mockEngine) AddWhitelist(ip string) error { return nil }
func (m *mockEngine) RemoveWhitelist(ip string) error {
	return nil
}
func (m *mockEngine) AddBlacklist(ip string) error    { return nil }
func (m *mockEngine) RemoveBlacklist(ip string) error { return nil }
func (m *mockEngine) AddRateLimit(rule any) error {
	return nil
}
func (m *mockEngine) RemoveRateLimit(id string) error { return nil }
func (m *mockEngine) AddExclusion(path string, detectors []string, reason string) error {
	return nil
}
func (m *mockEngine) RemoveExclusion(path string) error { return nil }
func (m *mockEngine) GetEvents(params json.RawMessage) (any, error) {
	return m.events, nil
}
func (m *mockEngine) GetTopIPs(n int) any { return m.topIPs }
func (m *mockEngine) GetDetectors() any   { return m.detectors }
func (m *mockEngine) TestRequest(method, url string, headers map[string]string) (any, error) {
	return map[string]any{
		"score":  0,
		"action": "pass",
	}, nil
}

func (m *mockEngine) GetAlertingStatus() any {
	return map[string]any{
		"enabled":       false,
		"webhook_count": 0,
		"email_count":   0,
	}
}

func (m *mockEngine) AddWebhook(name, url, webhookType string, events []string, minScore int, cooldown string) error {
	return nil
}
func (m *mockEngine) RemoveWebhook(name string) error { return nil }
func (m *mockEngine) AddEmailTarget(name, smtpHost string, smtpPort int, username, password, from string, to []string, useTLS bool, events []string, minScore int) error {
	return nil
}
func (m *mockEngine) RemoveEmailTarget(name string) error { return nil }
func (m *mockEngine) TestAlert(target string) error       { return nil }

// New Feature Methods - CRS
func (m *mockEngine) GetCRSRules(phase int, severity string) (any, error) {
	return map[string]any{"enabled": true, "rules": []any{}}, nil
}
func (m *mockEngine) EnableCRSRule(ruleID string, enabled bool) error { return nil }
func (m *mockEngine) SetParanoiaLevel(level int) error               { return nil }
func (m *mockEngine) AddCRSExclusion(ruleID, path, parameter, reason string) error {
	return nil
}

// New Feature Methods - Virtual Patch
func (m *mockEngine) GetVirtualPatches(severity string, activeOnly bool) (any, error) {
	return map[string]any{"enabled": true, "patches": []any{}}, nil
}
func (m *mockEngine) EnableVirtualPatch(patchID string, enabled bool) error { return nil }
func (m *mockEngine) AddCustomPatch(id, name, description, cveID, pattern, patternType, target, action, severity string, score int) error {
	return nil
}
func (m *mockEngine) UpdateCVEDatabase() error { return nil }

// New Feature Methods - API Validation
func (m *mockEngine) GetAPISchemas() (any, error) {
	return map[string]any{"enabled": true, "schemas": []any{}}, nil
}
func (m *mockEngine) UploadAPISchema(name, content, format string, strictMode bool) error { return nil }
func (m *mockEngine) RemoveAPISchema(name string) error                                  { return nil }
func (m *mockEngine) SetAPIValidationMode(validateRequest, validateResponse, strictMode, blockOnViolation *bool) error {
	return nil
}
func (m *mockEngine) TestAPISchema(method, path, body string) (any, error) {
	return map[string]any{"valid": true}, nil
}

// New Feature Methods - Client-Side Protection
func (m *mockEngine) GetClientSideStats() (any, error) {
	return map[string]any{"enabled": true}, nil
}
func (m *mockEngine) SetClientSideMode(mode string, magecartDetection, agentInjection, cspEnabled *bool) error {
	return nil
}
func (m *mockEngine) AddSkimmingDomain(domain string) error { return nil }
func (m *mockEngine) GetCSPReports(limit int) (any, error) {
	return map[string]any{"reports": []any{}}, nil
}

// New Feature Methods - DLP
func (m *mockEngine) GetDLPAlerts(limit int, patternType string) (any, error) {
	return map[string]any{"alerts": []any{}}, nil
}
func (m *mockEngine) AddDLPPattern(id, name, pattern, description, action string, score int) error {
	return nil
}
func (m *mockEngine) RemoveDLPPattern(id string) error { return nil }
func (m *mockEngine) TestDLPPattern(pattern, testData string) (any, error) {
	return map[string]any{"matched": false}, nil
}

// New Feature Methods - HTTP/3
func (m *mockEngine) GetHTTP3Status() (any, error) {
	return map[string]any{"enabled": false}, nil
}
func (m *mockEngine) SetHTTP3Config(enabled, enable0RTT, advertiseAltSvc *bool) error { return nil }

// sendRequest encodes a JSON-RPC request and returns the written bytes.
func sendRequest(id any, method string, params any) string {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		p, _ := json.Marshal(params)
		req["params"] = json.RawMessage(p)
	}
	data, _ := json.Marshal(req)
	return string(data) + "\n"
}

// readResponse parses a single JSON-RPC response from the output.
func readResponse(t *testing.T, output string) JSONRPCResponse {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("no response received")
	}
	// Return the last line (last response)
	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v\nraw: %s", err, lines[len(lines)-1])
	}
	return resp
}

// readAllResponses parses all JSON-RPC responses from the output.
func readAllResponses(t *testing.T, output string) []JSONRPCResponse {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	responses := make([]JSONRPCResponse, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v\nraw: %s", err, line)
		}
		responses = append(responses, resp)
	}
	return responses
}

func TestNewServer(t *testing.T) {
	r := strings.NewReader("")
	w := &bytes.Buffer{}
	s := NewServer(r, w)

	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.tools == nil {
		t.Fatal("tools map not initialized")
	}
	if s.reader == nil {
		t.Fatal("reader not initialized")
	}
	if s.writer == nil {
		t.Fatal("writer not initialized")
	}
}

func TestRegisterTool(t *testing.T) {
	s := NewServer(strings.NewReader(""), &bytes.Buffer{})

	handler := func(params json.RawMessage) (any, error) {
		return "ok", nil
	}

	s.RegisterTool("test_tool", handler)

	if s.ToolCount() != 1 {
		t.Fatalf("expected 1 tool, got %d", s.ToolCount())
	}

	// Register another
	s.RegisterTool("test_tool_2", handler)
	if s.ToolCount() != 2 {
		t.Fatalf("expected 2 tools, got %d", s.ToolCount())
	}
}

func TestRegisterAllTools(t *testing.T) {
	s := NewServer(strings.NewReader(""), &bytes.Buffer{})
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	if s.ToolCount() != 44 {
		t.Fatalf("expected 44 tools registered, got %d", s.ToolCount())
	}
}

func TestAllToolsDefinitions(t *testing.T) {
	tools := AllTools()
	if len(tools) != 44 {
		t.Fatalf("expected 44 tool definitions, got %d", len(tools))
	}

	// Verify all tools have required fields
	for _, tool := range tools {
		if tool.Name == "" {
			t.Error("tool has empty name")
		}
		if tool.Description == "" {
			t.Errorf("tool %s has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %s has nil input schema", tool.Name)
		}
		if !strings.HasPrefix(tool.Name, "guardianwaf_") {
			t.Errorf("tool %s does not have guardianwaf_ prefix", tool.Name)
		}
	}

	// Verify expected tool names
	expectedTools := []string{
		"guardianwaf_get_stats",
		"guardianwaf_get_events",
		"guardianwaf_add_whitelist",
		"guardianwaf_remove_whitelist",
		"guardianwaf_add_blacklist",
		"guardianwaf_remove_blacklist",
		"guardianwaf_add_ratelimit",
		"guardianwaf_remove_ratelimit",
		"guardianwaf_add_exclusion",
		"guardianwaf_remove_exclusion",
		"guardianwaf_set_mode",
		"guardianwaf_get_config",
		"guardianwaf_test_request",
		"guardianwaf_get_top_ips",
		"guardianwaf_get_detectors",
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}
	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("missing expected tool: %s", name)
		}
	}
}

func TestParseError(t *testing.T) {
	input := "this is not json\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	err := s.Run()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != ErrCodeParseError {
		t.Fatalf("expected parse error code %d, got %d", ErrCodeParseError, resp.Error.Code)
	}
}

func TestInvalidJSONRPCVersion(t *testing.T) {
	req := `{"jsonrpc":"1.0","id":1,"method":"initialize"}` + "\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(req), output)

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("expected invalid request error code %d, got %d", ErrCodeInvalidRequest, resp.Error.Code)
	}
}

func TestInitializeHandshake(t *testing.T) {
	input := sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "test-client",
			"version": "1.0.0",
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetServerInfo("guardianwaf", "1.2.3")

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.ID != float64(1) {
		t.Fatalf("expected id 1, got %v", resp.ID)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}

	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("serverInfo missing or not a map")
	}
	if serverInfo["name"] != "guardianwaf" {
		t.Fatalf("expected server name 'guardianwaf', got %v", serverInfo["name"])
	}
	if serverInfo["version"] != "1.2.3" {
		t.Fatalf("expected version '1.2.3', got %v", serverInfo["version"])
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("expected protocol version '2024-11-05', got %v", result["protocolVersion"])
	}
}

func TestToolsList(t *testing.T) {
	input := sendRequest(1, "tools/list", nil)
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}

	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatal("tools is not an array")
	}

	if len(tools) != 44 {
		t.Fatalf("expected 44 tools, got %d", len(tools))
	}
}

func TestToolsCallDispatch(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	mock := newMockEngine()
	s.SetEngine(mock)
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}
	content, ok := result["content"].([]any)
	if !ok {
		t.Fatal("content is not an array")
	}
	if len(content) == 0 {
		t.Fatal("content is empty")
	}
}

func TestToolsCallUnknownTool(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "nonexistent_tool",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Fatalf("expected invalid params error, got code %d", resp.Error.Code)
	}
}

func TestMethodNotFound(t *testing.T) {
	input := sendRequest(1, "unknown/method", nil)
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method not found error, got code %d", resp.Error.Code)
	}
}

func TestInvalidToolCallParams(t *testing.T) {
	// Send tools/call with invalid params (not a valid JSON object structure)
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}` + "\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Fatalf("expected invalid params error, got code %d", resp.Error.Code)
	}
}

func TestNotificationInitialized(t *testing.T) {
	// notifications/initialized should not produce a response
	input := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	_ = s.Run()

	if output.Len() != 0 {
		t.Fatalf("expected no response for notification, got: %s", output.String())
	}
}

func TestIOPipeRoundTrip(t *testing.T) {
	pr, pw := io.Pipe()
	output := &bytes.Buffer{}
	s := NewServer(pr, output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	done := make(chan error, 1)
	go func() {
		done <- s.Run()
	}()

	// Send initialize
	initReq := sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
	})
	_, _ = pw.Write([]byte(initReq))

	// Send tools/list
	listReq := sendRequest(2, "tools/list", nil)
	_, _ = pw.Write([]byte(listReq))

	// Send tools/call
	callReq := sendRequest(3, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	_, _ = pw.Write([]byte(callReq))

	// Close pipe to end the server
	pw.Close()

	err := <-done
	if err != nil {
		t.Fatalf("server returned error: %v", err)
	}

	responses := readAllResponses(t, output.String())
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d\noutput: %s", len(responses), output.String())
	}

	// Verify initialize response
	if responses[0].Error != nil {
		t.Fatalf("initialize error: %v", responses[0].Error)
	}

	// Verify tools/list response
	if responses[1].Error != nil {
		t.Fatalf("tools/list error: %v", responses[1].Error)
	}

	// Verify tools/call response
	if responses[2].Error != nil {
		t.Fatalf("tools/call error: %v", responses[2].Error)
	}
}

func TestMultipleRequestsSequential(t *testing.T) {
	var input strings.Builder

	// Initialize
	input.WriteString(sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
	}))

	// Notification (no response expected)
	input.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")

	// tools/list
	input.WriteString(sendRequest(2, "tools/list", nil))

	// Get stats via tools/call
	input.WriteString(sendRequest(3, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	}))

	// Set mode via tools/call
	input.WriteString(sendRequest(4, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": "monitor"},
	}))

	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input.String()), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	responses := readAllResponses(t, output.String())
	// Expected: initialize, tools/list, get_stats, set_mode (4 responses, notification has none)
	if len(responses) != 4 {
		t.Fatalf("expected 4 responses, got %d\noutput: %s", len(responses), output.String())
	}

	// All should be successful
	for i, resp := range responses {
		if resp.Error != nil {
			t.Errorf("response %d has error: %v", i, resp.Error)
		}
	}
}

func TestToolCallWithEngineError(t *testing.T) {
	// Test calling a tool when engine is nil
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	// No engine set
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		// JSON-RPC level error is not expected; tool errors are returned as content
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError to be true when engine is not available")
	}
}

func TestHandlerAddWhitelist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]any{"ip": "10.0.0.1"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddWhitelistMissingIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing ip")
	}
}

func TestHandlerSetMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": "monitor"},
	})
	output := &bytes.Buffer{}
	mock := newMockEngine()
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(mock)
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if mock.mode != "monitor" {
		t.Fatalf("expected mode to be 'monitor', got %s", mock.mode)
	}
}

func TestHandlerSetModeInvalid(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": "invalid"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for invalid mode")
	}
}

func TestHandlerTestRequest(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_request",
		"arguments": map[string]any{
			"method": "GET",
			"url":    "/search?q=test",
			"headers": map[string]string{
				"User-Agent": "test-agent",
			},
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerGetDetectors(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_detectors",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddRateLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_ratelimit",
		"arguments": map[string]any{
			"id":     "test-rule",
			"scope":  "ip",
			"limit":  100,
			"window": "1m",
			"action": "block",
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddExclusion(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_exclusion",
		"arguments": map[string]any{
			"path":      "/api/webhook",
			"detectors": []string{"sqli", "xss"},
			"reason":    "webhook endpoint",
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestEmptyLines(t *testing.T) {
	// Server should skip empty lines without error
	input := "\n\n" + sendRequest(1, "initialize", map[string]any{}) + "\n\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	_ = s.Run()

	responses := readAllResponses(t, output.String())
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}
	if responses[0].Error != nil {
		t.Fatalf("unexpected error: %v", responses[0].Error)
	}
}

func TestServerInfo(t *testing.T) {
	s := NewServer(strings.NewReader(""), &bytes.Buffer{})
	s.SetServerInfo("myserver", "2.0.0")

	if s.serverName != "myserver" {
		t.Fatalf("expected name 'myserver', got %s", s.serverName)
	}
	if s.serverVersion != "2.0.0" {
		t.Fatalf("expected version '2.0.0', got %s", s.serverVersion)
	}
}

func TestEOFReturnsNil(t *testing.T) {
	s := NewServer(strings.NewReader(""), &bytes.Buffer{})
	err := s.Run()
	if err != nil {
		t.Fatalf("expected nil error on EOF, got: %v", err)
	}
}

func TestBulkToolCallsAllTools(t *testing.T) {
	// Test that each of the 15 tools can be called successfully
	toolCalls := []struct {
		name string
		args map[string]any
	}{
		{"guardianwaf_get_stats", map[string]any{}},
		{"guardianwaf_get_events", map[string]any{}},
		{"guardianwaf_add_whitelist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_remove_whitelist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_add_blacklist", map[string]any{"ip": "5.6.7.8"}},
		{"guardianwaf_remove_blacklist", map[string]any{"ip": "5.6.7.8"}},
		{"guardianwaf_add_ratelimit", map[string]any{"id": "r1", "limit": 100, "window": "1m"}},
		{"guardianwaf_remove_ratelimit", map[string]any{"id": "r1"}},
		{"guardianwaf_add_exclusion", map[string]any{"path": "/test", "detectors": []string{"sqli"}}},
		{"guardianwaf_remove_exclusion", map[string]any{"path": "/test"}},
		{"guardianwaf_set_mode", map[string]any{"mode": "enforce"}},
		{"guardianwaf_get_config", map[string]any{}},
		{"guardianwaf_test_request", map[string]any{"url": "/test"}},
		{"guardianwaf_get_top_ips", map[string]any{"count": 5}},
		{"guardianwaf_get_detectors", map[string]any{}},
	}

	var input strings.Builder
	for i, tc := range toolCalls {
		input.WriteString(sendRequest(i+1, "tools/call", map[string]any{
			"name":      tc.name,
			"arguments": tc.args,
		}))
	}

	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input.String()), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	responses := readAllResponses(t, output.String())
	if len(responses) != len(toolCalls) {
		t.Fatalf("expected %d responses, got %d", len(toolCalls), len(responses))
	}

	for i, resp := range responses {
		if resp.Error != nil {
			t.Errorf("tool %s (response %d) returned JSON-RPC error: %v", toolCalls[i].name, i, resp.Error)
			continue
		}
		result, ok := resp.Result.(map[string]any)
		if !ok {
			t.Errorf("tool %s (response %d) result is not a map", toolCalls[i].name, i)
			continue
		}
		isError, _ := result["isError"].(bool)
		if isError {
			t.Errorf("tool %s (response %d) returned tool error", toolCalls[i].name, i)
		}
	}
}

func TestHandlerGetTopIPs(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_top_ips",
		"arguments": map[string]any{"count": 5},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestToolCallResultFormat(t *testing.T) {
	// Verify the MCP result format includes content array with text type
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result is not a map")
	}

	content, ok := result["content"].([]any)
	if !ok {
		t.Fatal("content is not an array")
	}

	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}

	item, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("content item is not a map")
	}

	if item["type"] != "text" {
		t.Fatalf("expected type 'text', got %v", item["type"])
	}

	text, ok := item["text"].(string)
	if !ok || text == "" {
		t.Fatal("text content is empty or not a string")
	}

	// The text should be valid JSON
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("content text is not valid JSON: %v\ntext: %s", err, text)
	}
}

func BenchmarkServerRequestHandling(b *testing.B) {
	mock := newMockEngine()

	for i := 0; i < b.N; i++ {
		input := sendRequest(i, "tools/call", map[string]any{
			"name":      "guardianwaf_get_stats",
			"arguments": map[string]any{},
		})
		output := &bytes.Buffer{}
		s := NewServer(strings.NewReader(input), output)
		s.SetEngine(mock)
		s.RegisterAllTools()
		_ = s.Run()
	}
}

func TestHandlerRemoveRateLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": map[string]any{"id": "test-rule"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerRemoveExclusion(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": map[string]any{"path": "/api/webhook"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddBlacklist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_blacklist",
		"arguments": map[string]any{"ip": "192.168.1.100"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerRemoveBlacklist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": map[string]any{"ip": "192.168.1.100"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

// Ensure unused import for fmt doesn't cause issues in tests
var _ = fmt.Sprintf

// --- Additional tests for uncovered handler error paths ---

func TestHandlerRemoveWhitelistMissingIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_whitelist",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing ip on remove_whitelist")
	}
}

func TestHandlerAddBlacklistMissingIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_blacklist",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing ip on add_blacklist")
	}
}

func TestHandlerRemoveBlacklistMissingIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing ip on remove_blacklist")
	}
}

func TestHandlerAddRateLimitMissingID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"limit": 100, "window": "1m"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing id on add_ratelimit")
	}
}

func TestHandlerAddRateLimitZeroLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "r1", "limit": 0, "window": "1m"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for zero limit on add_ratelimit")
	}
}

func TestHandlerAddRateLimitMissingWindow(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "r1", "limit": 100},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing window on add_ratelimit")
	}
}

func TestHandlerRemoveRateLimitMissingID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing id on remove_ratelimit")
	}
}

func TestHandlerAddExclusionMissingPath(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": map[string]any{"detectors": []string{"sqli"}},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing path on add_exclusion")
	}
}

func TestHandlerAddExclusionMissingDetectors(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": map[string]any{"path": "/test"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing detectors on add_exclusion")
	}
}

func TestHandlerRemoveExclusionMissingPath(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing path on remove_exclusion")
	}
}

func TestHandlerSetModeMissing(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing mode")
	}
}

func TestHandlerTestRequestMissingURL(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_test_request",
		"arguments": map[string]any{"method": "GET"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing url on test_request")
	}
}

func TestHandlerTestRequestDefaultMethod(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_test_request",
		"arguments": map[string]any{"url": "/test"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if isError {
		t.Fatal("expected success for test_request with default method")
	}
}

func TestHandlerGetTopIPsDefaultCount(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_top_ips",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerGetTopIPsNilParams(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_get_top_ips",
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerGetEvents(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_events",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerGetConfig(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_config",
		"arguments": map[string]any{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerInvalidJSON(t *testing.T) {
	// Test handler with completely invalid JSON as arguments
	tests := []struct {
		name string
		tool string
	}{
		{"add_whitelist", "guardianwaf_add_whitelist"},
		{"remove_whitelist", "guardianwaf_remove_whitelist"},
		{"add_blacklist", "guardianwaf_add_blacklist"},
		{"remove_blacklist", "guardianwaf_remove_blacklist"},
		{"add_ratelimit", "guardianwaf_add_ratelimit"},
		{"remove_ratelimit", "guardianwaf_remove_ratelimit"},
		{"add_exclusion", "guardianwaf_add_exclusion"},
		{"remove_exclusion", "guardianwaf_remove_exclusion"},
		{"set_mode", "guardianwaf_set_mode"},
		{"test_request", "guardianwaf_test_request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Send with invalid arguments (a string instead of object)
			reqStr := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":"not-json-object"}}`, tt.tool)
			input := reqStr + "\n"
			output := &bytes.Buffer{}
			s := NewServer(strings.NewReader(input), output)
			s.SetEngine(newMockEngine())
			s.RegisterAllTools()
			_ = s.Run()

			resp := readResponse(t, output.String())
			if resp.Error != nil {
				// Some may fail at JSON-RPC level
				return
			}
			result, ok := resp.Result.(map[string]any)
			if !ok {
				return
			}
			isError, _ := result["isError"].(bool)
			if !isError {
				t.Fatalf("expected isError=true for invalid arguments to %s", tt.tool)
			}
		})
	}
}

func TestHandlerNoEngineAllTools(t *testing.T) {
	// Test each handler returns error when engine is nil
	tools := []struct {
		name string
		args map[string]any
	}{
		{"guardianwaf_get_stats", map[string]any{}},
		{"guardianwaf_get_events", map[string]any{}},
		{"guardianwaf_get_config", map[string]any{}},
		{"guardianwaf_get_detectors", map[string]any{}},
		{"guardianwaf_get_top_ips", map[string]any{"count": 5}},
		{"guardianwaf_add_whitelist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_remove_whitelist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_add_blacklist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_remove_blacklist", map[string]any{"ip": "1.2.3.4"}},
		{"guardianwaf_set_mode", map[string]any{"mode": "enforce"}},
		{"guardianwaf_add_ratelimit", map[string]any{"id": "r1", "limit": 100, "window": "1m"}},
		{"guardianwaf_remove_ratelimit", map[string]any{"id": "r1"}},
		{"guardianwaf_add_exclusion", map[string]any{"path": "/test", "detectors": []string{"sqli"}}},
		{"guardianwaf_remove_exclusion", map[string]any{"path": "/test"}},
		{"guardianwaf_test_request", map[string]any{"url": "/test"}},
	}

	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			input := sendRequest(1, "tools/call", map[string]any{
				"name":      tt.name,
				"arguments": tt.args,
			})
			output := &bytes.Buffer{}
			s := NewServer(strings.NewReader(input), output)
			// No engine set
			s.RegisterAllTools()
			_ = s.Run()

			resp := readResponse(t, output.String())
			if resp.Error != nil {
				return
			}
			result, ok := resp.Result.(map[string]any)
			if !ok {
				t.Fatal("result is not a map")
			}
			isError, _ := result["isError"].(bool)
			if !isError {
				t.Fatalf("expected isError=true for %s with no engine", tt.name)
			}
		})
	}
}

func TestHandlerAddRateLimitDefaults(t *testing.T) {
	// Test that scope and action default values are applied
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_ratelimit",
		"arguments": map[string]any{
			"id":     "test",
			"limit":  100,
			"window": "1m",
			// scope and action omitted
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()
	_ = s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if isError {
		t.Fatal("expected success for add_ratelimit with defaults")
	}
}

// --- Empty IP validation ---

func TestHandleAddWhitelist_EmptyIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]any{"ip": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	if resp.Error != nil {
		t.Fatalf("unexpected protocol error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty IP")
	}
}

func TestHandleRemoveWhitelist_EmptyIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_whitelist",
		"arguments": map[string]any{"ip": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty IP")
	}
}

func TestHandleAddBlacklist_EmptyIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_blacklist",
		"arguments": map[string]any{"ip": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty IP on add_blacklist")
	}
}

func TestHandleRemoveBlacklist_EmptyIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": map[string]any{"ip": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty IP on remove_blacklist")
	}
}

func TestHandleRemoveRateLimit_EmptyID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": map[string]any{"id": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty ID on remove_ratelimit")
	}
}

func TestHandleAddExclusion_EmptyDetectors(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": map[string]any{"path": "/api", "detectors": []string{}},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty detectors on add_exclusion")
	}
}

func TestHandleRemoveExclusion_EmptyPath(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": map[string]any{"path": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty path on remove_exclusion")
	}
}

func TestHandleSetMode_EmptyMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": ""},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty mode on set_mode")
	}
}

func TestRun_EmptyLine(t *testing.T) {
	// Empty line followed by valid request — empty line should be skipped
	input := "\n" + sendRequest(1, "tools/list", nil)
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestRun_ReadError(t *testing.T) {
	// Reader that returns an error (not EOF)
	r := &errReader{err: fmt.Errorf("read failure")}
	var out bytes.Buffer
	srv := NewServer(r, &out)
	err := srv.Run()
	if err == nil {
		t.Fatal("expected error from Run when reader fails")
	}
}

type errReader struct {
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, r.err
}

// failEngine returns errors for all mutating operations.
type failEngine struct {
	mockEngine
}

func newFailEngine() *failEngine {
	return &failEngine{mockEngine: *newMockEngine()}
}

func (m *failEngine) AddWhitelist(ip string) error    { return fmt.Errorf("fail") }
func (m *failEngine) RemoveWhitelist(ip string) error { return fmt.Errorf("fail") }
func (m *failEngine) AddBlacklist(ip string) error    { return fmt.Errorf("fail") }
func (m *failEngine) RemoveBlacklist(ip string) error { return fmt.Errorf("fail") }
func (m *failEngine) AddRateLimit(rule any) error     { return fmt.Errorf("fail") }
func (m *failEngine) RemoveRateLimit(id string) error { return fmt.Errorf("fail") }
func (m *failEngine) AddExclusion(path string, detectors []string, reason string) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) RemoveExclusion(path string) error { return fmt.Errorf("fail") }
func (m *failEngine) SetMode(mode string) error         { return fmt.Errorf("fail") }

// New Feature Methods - fail versions
func (m *failEngine) GetCRSRules(phase int, severity string) (any, error) { return nil, fmt.Errorf("fail") }
func (m *failEngine) EnableCRSRule(ruleID string, enabled bool) error    { return fmt.Errorf("fail") }
func (m *failEngine) SetParanoiaLevel(level int) error                   { return fmt.Errorf("fail") }
func (m *failEngine) AddCRSExclusion(ruleID, path, parameter, reason string) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) GetVirtualPatches(severity string, activeOnly bool) (any, error) {
	return nil, fmt.Errorf("fail")
}
func (m *failEngine) EnableVirtualPatch(patchID string, enabled bool) error { return fmt.Errorf("fail") }
func (m *failEngine) AddCustomPatch(id, name, description, cveID, pattern, patternType, target, action, severity string, score int) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) UpdateCVEDatabase() error                               { return fmt.Errorf("fail") }
func (m *failEngine) GetAPISchemas() (any, error)                            { return nil, fmt.Errorf("fail") }
func (m *failEngine) UploadAPISchema(name, content, format string, strictMode bool) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) RemoveAPISchema(name string) error                      { return fmt.Errorf("fail") }
func (m *failEngine) SetAPIValidationMode(validateRequest, validateResponse, strictMode, blockOnViolation *bool) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) TestAPISchema(method, path, body string) (any, error) { return nil, fmt.Errorf("fail") }
func (m *failEngine) GetClientSideStats() (any, error)                      { return nil, fmt.Errorf("fail") }
func (m *failEngine) SetClientSideMode(mode string, magecartDetection, agentInjection, cspEnabled *bool) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) AddSkimmingDomain(domain string) error               { return fmt.Errorf("fail") }
func (m *failEngine) GetCSPReports(limit int) (any, error)                { return nil, fmt.Errorf("fail") }
func (m *failEngine) GetDLPAlerts(limit int, patternType string) (any, error) {
	return nil, fmt.Errorf("fail")
}
func (m *failEngine) AddDLPPattern(id, name, pattern, description, action string, score int) error {
	return fmt.Errorf("fail")
}
func (m *failEngine) RemoveDLPPattern(id string) error                    { return fmt.Errorf("fail") }
func (m *failEngine) TestDLPPattern(pattern, testData string) (any, error) { return nil, fmt.Errorf("fail") }
func (m *failEngine) GetHTTP3Status() (any, error)                        { return nil, fmt.Errorf("fail") }
func (m *failEngine) SetHTTP3Config(enabled, enable0RTT, advertiseAltSvc *bool) error {
	return fmt.Errorf("fail")
}

func TestHandleAddWhitelist_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]any{"ip": "10.0.0.1"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleRemoveWhitelist_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_whitelist",
		"arguments": map[string]any{"ip": "10.0.0.1"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleAddBlacklist_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_blacklist",
		"arguments": map[string]any{"ip": "10.0.0.1"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleRemoveBlacklist_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": map[string]any{"ip": "10.0.0.1"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleAddRateLimit_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "r1", "limit": 10, "window": "1m"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleRemoveRateLimit_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": map[string]any{"id": "r1"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleAddExclusion_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": map[string]any{"path": "/api", "detectors": []string{"sqli"}, "reason": "test"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleRemoveExclusion_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": map[string]any{"path": "/api"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

func TestHandleSetMode_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": "enforce"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error from engine")
	}
}

// --- Invalid JSON params for handlers ---

func TestHandleAddWhitelist_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_whitelist",
		"arguments": "not-json",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleRemoveWhitelist_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_whitelist",
		"arguments": "not-json",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleAddBlacklist_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_blacklist",
		"arguments": "not-json",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleRemoveBlacklist_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": "not-json",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleAddRateLimit_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": "bad",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleRemoveRateLimit_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": "bad",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleAddExclusion_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": "bad",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleRemoveExclusion_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": "bad",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleSetMode_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": "bad",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestHandleSetMode_InvalidModeValue(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]any{"mode": "invalid_mode"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for invalid mode value")
	}
}

func TestHandleAddExclusion_EmptyPath(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_exclusion",
		"arguments": map[string]any{"path": "", "detectors": []string{"sqli"}},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty path on add_exclusion")
	}
}

func TestHandleAddRateLimit_MissingFields(t *testing.T) {
	// Missing window
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "test", "limit": 10},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for missing window")
	}
}

func TestHandleAddRateLimit_ZeroLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "test", "limit": 0, "window": "1m"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for zero limit")
	}
}

func TestHandleAddRateLimit_EmptyID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_ratelimit",
		"arguments": map[string]any{"id": "", "limit": 10, "window": "1m"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error for empty ID")
	}
}
