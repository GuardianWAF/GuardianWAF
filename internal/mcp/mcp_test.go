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
	stats     interface{}
	config    interface{}
	mode      string
	detectors interface{}
	events    interface{}
	topIPs    interface{}
}

func newMockEngine() *mockEngine {
	return &mockEngine{
		stats: map[string]interface{}{
			"total_requests":   int64(100),
			"blocked_requests": int64(5),
			"passed_requests":  int64(95),
			"avg_latency_us":   int64(150),
		},
		config: map[string]interface{}{
			"mode":   "enforce",
			"listen": ":8080",
		},
		mode: "enforce",
		detectors: []map[string]interface{}{
			{"name": "sqli", "enabled": true, "multiplier": 1.0},
			{"name": "xss", "enabled": true, "multiplier": 1.0},
		},
		events: map[string]interface{}{
			"events": []interface{}{},
			"total":  0,
		},
		topIPs: []map[string]interface{}{},
	}
}

func (m *mockEngine) GetStats() interface{}       { return m.stats }
func (m *mockEngine) GetConfig() interface{}       { return m.config }
func (m *mockEngine) GetMode() string              { return m.mode }
func (m *mockEngine) SetMode(mode string) error    { m.mode = mode; return nil }
func (m *mockEngine) AddWhitelist(ip string) error { return nil }
func (m *mockEngine) RemoveWhitelist(ip string) error {
	return nil
}
func (m *mockEngine) AddBlacklist(ip string) error    { return nil }
func (m *mockEngine) RemoveBlacklist(ip string) error { return nil }
func (m *mockEngine) AddRateLimit(rule interface{}) error {
	return nil
}
func (m *mockEngine) RemoveRateLimit(id string) error { return nil }
func (m *mockEngine) AddExclusion(path string, detectors []string, reason string) error {
	return nil
}
func (m *mockEngine) RemoveExclusion(path string) error { return nil }
func (m *mockEngine) GetEvents(params json.RawMessage) (interface{}, error) {
	return m.events, nil
}
func (m *mockEngine) GetTopIPs(n int) interface{} { return m.topIPs }
func (m *mockEngine) GetDetectors() interface{}   { return m.detectors }
func (m *mockEngine) TestRequest(method, url string, headers map[string]string) (interface{}, error) {
	return map[string]interface{}{
		"score":  0,
		"action": "pass",
	}, nil
}

// sendRequest encodes a JSON-RPC request and returns the written bytes.
func sendRequest(id interface{}, method string, params interface{}) string {
	req := map[string]interface{}{
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
	var responses []JSONRPCResponse
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

	handler := func(params json.RawMessage) (interface{}, error) {
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

	if s.ToolCount() != 15 {
		t.Fatalf("expected 15 tools registered, got %d", s.ToolCount())
	}
}

func TestAllToolsDefinitions(t *testing.T) {
	tools := AllTools()
	if len(tools) != 15 {
		t.Fatalf("expected 15 tool definitions, got %d", len(tools))
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

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("expected invalid request error code %d, got %d", ErrCodeInvalidRequest, resp.Error.Code)
	}
}

func TestInitializeHandshake(t *testing.T) {
	input := sendRequest(1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "test-client",
			"version": "1.0.0",
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetServerInfo("guardianwaf", "1.2.3")

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.ID != float64(1) {
		t.Fatalf("expected id 1, got %v", resp.ID)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
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

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("tools is not an array")
	}

	if len(tools) != 15 {
		t.Fatalf("expected 15 tools, got %d", len(tools))
	}
}

func TestToolsCallDispatch(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	mock := newMockEngine()
	s.SetEngine(mock)
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}
	content, ok := result["content"].([]interface{})
	if !ok {
		t.Fatal("content is not an array")
	}
	if len(content) == 0 {
		t.Fatal("content is empty")
	}
}

func TestToolsCallUnknownTool(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "nonexistent_tool",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.RegisterAllTools()

	s.Run()

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

	s.Run()

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

	s.Run()

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

	s.Run()

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
	initReq := sendRequest(1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
	})
	pw.Write([]byte(initReq))

	// Send tools/list
	listReq := sendRequest(2, "tools/list", nil)
	pw.Write([]byte(listReq))

	// Send tools/call
	callReq := sendRequest(3, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]interface{}{},
	})
	pw.Write([]byte(callReq))

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
	input.WriteString(sendRequest(1, "initialize", map[string]interface{}{
		"protocolVersion": "2024-11-05",
	}))

	// Notification (no response expected)
	input.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")

	// tools/list
	input.WriteString(sendRequest(2, "tools/list", nil))

	// Get stats via tools/call
	input.WriteString(sendRequest(3, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]interface{}{},
	}))

	// Set mode via tools/call
	input.WriteString(sendRequest(4, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]interface{}{"mode": "monitor"},
	}))

	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input.String()), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

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
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	// No engine set
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		// JSON-RPC level error is not expected; tool errors are returned as content
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError to be true when engine is not available")
	}
}

func TestHandlerAddWhitelist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]interface{}{"ip": "10.0.0.1"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddWhitelistMissingIP(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_add_whitelist",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for missing ip")
	}
}

func TestHandlerSetMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]interface{}{"mode": "monitor"},
	})
	output := &bytes.Buffer{}
	mock := newMockEngine()
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(mock)
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if mock.mode != "monitor" {
		t.Fatalf("expected mode to be 'monitor', got %s", mock.mode)
	}
}

func TestHandlerSetModeInvalid(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_set_mode",
		"arguments": map[string]interface{}{"mode": "invalid"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true for invalid mode")
	}
}

func TestHandlerTestRequest(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name": "guardianwaf_test_request",
		"arguments": map[string]interface{}{
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

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerGetDetectors(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_detectors",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddRateLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name": "guardianwaf_add_ratelimit",
		"arguments": map[string]interface{}{
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

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddExclusion(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name": "guardianwaf_add_exclusion",
		"arguments": map[string]interface{}{
			"path":      "/api/webhook",
			"detectors": []string{"sqli", "xss"},
			"reason":    "webhook endpoint",
		},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestEmptyLines(t *testing.T) {
	// Server should skip empty lines without error
	input := "\n\n" + sendRequest(1, "initialize", map[string]interface{}{}) + "\n\n"
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)

	s.Run()

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
		args map[string]interface{}
	}{
		{"guardianwaf_get_stats", map[string]interface{}{}},
		{"guardianwaf_get_events", map[string]interface{}{}},
		{"guardianwaf_add_whitelist", map[string]interface{}{"ip": "1.2.3.4"}},
		{"guardianwaf_remove_whitelist", map[string]interface{}{"ip": "1.2.3.4"}},
		{"guardianwaf_add_blacklist", map[string]interface{}{"ip": "5.6.7.8"}},
		{"guardianwaf_remove_blacklist", map[string]interface{}{"ip": "5.6.7.8"}},
		{"guardianwaf_add_ratelimit", map[string]interface{}{"id": "r1", "limit": 100, "window": "1m"}},
		{"guardianwaf_remove_ratelimit", map[string]interface{}{"id": "r1"}},
		{"guardianwaf_add_exclusion", map[string]interface{}{"path": "/test", "detectors": []string{"sqli"}}},
		{"guardianwaf_remove_exclusion", map[string]interface{}{"path": "/test"}},
		{"guardianwaf_set_mode", map[string]interface{}{"mode": "enforce"}},
		{"guardianwaf_get_config", map[string]interface{}{}},
		{"guardianwaf_test_request", map[string]interface{}{"url": "/test"}},
		{"guardianwaf_get_top_ips", map[string]interface{}{"count": 5}},
		{"guardianwaf_get_detectors", map[string]interface{}{}},
	}

	var input strings.Builder
	for i, tc := range toolCalls {
		input.WriteString(sendRequest(i+1, "tools/call", map[string]interface{}{
			"name":      tc.name,
			"arguments": tc.args,
		}))
	}

	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input.String()), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	responses := readAllResponses(t, output.String())
	if len(responses) != len(toolCalls) {
		t.Fatalf("expected %d responses, got %d", len(toolCalls), len(responses))
	}

	for i, resp := range responses {
		if resp.Error != nil {
			t.Errorf("tool %s (response %d) returned JSON-RPC error: %v", toolCalls[i].name, i, resp.Error)
			continue
		}
		result, ok := resp.Result.(map[string]interface{})
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
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_top_ips",
		"arguments": map[string]interface{}{"count": 5},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestToolCallResultFormat(t *testing.T) {
	// Verify the MCP result format includes content array with text type
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]interface{}{},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result is not a map")
	}

	content, ok := result["content"].([]interface{})
	if !ok {
		t.Fatal("content is not an array")
	}

	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}

	item, ok := content[0].(map[string]interface{})
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
	var parsed interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("content text is not valid JSON: %v\ntext: %s", err, text)
	}
}

func BenchmarkServerRequestHandling(b *testing.B) {
	mock := newMockEngine()

	for i := 0; i < b.N; i++ {
		input := sendRequest(i, "tools/call", map[string]interface{}{
			"name":      "guardianwaf_get_stats",
			"arguments": map[string]interface{}{},
		})
		output := &bytes.Buffer{}
		s := NewServer(strings.NewReader(input), output)
		s.SetEngine(mock)
		s.RegisterAllTools()
		s.Run()
	}
}

func TestHandlerRemoveRateLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_remove_ratelimit",
		"arguments": map[string]interface{}{"id": "test-rule"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerRemoveExclusion(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_remove_exclusion",
		"arguments": map[string]interface{}{"path": "/api/webhook"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerAddBlacklist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_add_blacklist",
		"arguments": map[string]interface{}{"ip": "192.168.1.100"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandlerRemoveBlacklist(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]interface{}{
		"name":      "guardianwaf_remove_blacklist",
		"arguments": map[string]interface{}{"ip": "192.168.1.100"},
	})
	output := &bytes.Buffer{}
	s := NewServer(strings.NewReader(input), output)
	s.SetEngine(newMockEngine())
	s.RegisterAllTools()

	s.Run()

	resp := readResponse(t, output.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

// Ensure unused import for fmt doesn't cause issues in tests
var _ = fmt.Sprintf
