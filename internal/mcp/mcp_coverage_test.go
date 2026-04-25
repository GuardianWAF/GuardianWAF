package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// Authentication tests (SetAPIKey, isAuthenticated, checkAuth, markAuthenticated)
// ============================================================================

func TestSetAPIKey(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("my-secret-key")
	if srv.apiKey != "my-secret-key" {
		t.Fatalf("expected apiKey 'my-secret-key', got %q", srv.apiKey)
	}
	srv.SetAPIKey("")
	if srv.apiKey != "" {
		t.Fatalf("expected empty apiKey, got %q", srv.apiKey)
	}
}

func TestIsAuthenticated_NoKey(t *testing.T) {
	srv := NewServer(nil, nil)
	if !srv.isAuthenticated("anything") {
		t.Fatal("expected authenticated when no key is set")
	}
	if !srv.isAuthenticated("") {
		t.Fatal("expected authenticated with empty key when no key is set")
	}
}

func TestIsAuthenticated_WithKey(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("secret123")
	if srv.isAuthenticated("wrong") {
		t.Fatal("expected NOT authenticated with wrong key")
	}
	if !srv.isAuthenticated("secret123") {
		t.Fatal("expected authenticated with correct key")
	}
}

func TestCheckAuth(t *testing.T) {
	srv := NewServer(nil, nil)
	if srv.checkAuth() {
		t.Fatal("expected checkAuth=false when not yet authenticated")
	}
	srv.markAuthenticated()
	if !srv.checkAuth() {
		t.Fatal("expected checkAuth=true after markAuthenticated")
	}
}

// ============================================================================
// handleInitialize with authentication
// ============================================================================

func TestHandleInitialize_AuthRequired_NoKey(t *testing.T) {
	input := sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetAPIKey("secret")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

	resp := readResponse(t, out.String())
	if resp.Error == nil {
		t.Fatal("expected error when api_key not provided")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized error code %d, got %d", ErrCodeUnauthorized, resp.Error.Code)
	}
}

func TestHandleInitialize_AuthRequired_WrongKey(t *testing.T) {
	input := sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"api_key":         "wrong-key",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetAPIKey("correct-key")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

	resp := readResponse(t, out.String())
	if resp.Error == nil {
		t.Fatal("expected error with wrong api_key")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized error, got code %d", resp.Error.Code)
	}
}

func TestHandleInitialize_AuthRequired_CorrectKey(t *testing.T) {
	input := sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"api_key":         "correct-key",
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetAPIKey("correct-key")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

	resp := readResponse(t, out.String())
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if !srv.authenticated {
		t.Fatal("expected server to be authenticated after correct init")
	}
}

func TestHandleInitialize_AuthRequired_CorrectKeyThenToolCall(t *testing.T) {
	var input strings.Builder
	input.WriteString(sendRequest(1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"api_key":         "my-key",
	}))
	input.WriteString(sendRequest(2, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	}))

	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input.String()), &out)
	srv.SetAPIKey("my-key")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

	responses := readAllResponses(t, out.String())
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(responses))
	}
	if responses[0].Error != nil {
		t.Fatalf("initialize error: %v", responses[0].Error)
	}
	if responses[1].Error != nil {
		t.Fatalf("tools/call error: %v", responses[1].Error)
	}
}

func TestHandleToolsCall_AuthRequired(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.SetAPIKey("secret")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

	resp := readResponse(t, out.String())
	if resp.Error == nil {
		t.Fatal("expected error when calling tool without auth")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized error, got code %d", resp.Error.Code)
	}
}

// ============================================================================
// HandleRequestJSON + processRequest + processToolsCall paths
// ============================================================================

func TestHandleRequestJSON_MethodNotFound(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method not found error, got %d", resp.Error.Code)
	}
}

func TestHandleRequestJSON_ToolsCall(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats","arguments":{}}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandleRequestJSON_ToolsCallAuthRequired(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("secret")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats","arguments":{}}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error for unauthenticated tools/call")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected unauthorized error, got %d", resp.Error.Code)
	}
}

func TestHandleRequestJSON_ToolsCallInvalidParams(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad-params"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Fatalf("expected invalid params error, got %d", resp.Error.Code)
	}
}

func TestHandleRequestJSON_ToolsCallUnknownTool(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestHandleRequestJSON_ToolsCallHandlerError(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newFailEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_add_whitelist","arguments":{"ip":"1.2.3.4"}}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected isError=true when handler returns error")
	}
}

func TestHandleRequestJSON_NotificationsInitialized(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
}

func TestHandleRequestJSON_ToolsListViaProcessRequest(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatal("tools not a slice")
	}
	if len(tools) != 44 {
		t.Fatalf("expected 44 tools, got %d", len(tools))
	}
}

func TestHandleRequestJSON_InitializeViaProcessRequest(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetServerInfo("test-server", "9.9.9")

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response not valid JSON: %v", jsonErr)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("result not a map")
	}
	info, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatal("serverInfo not a map")
	}
	if info["name"] != "test-server" {
		t.Fatalf("expected name 'test-server', got %v", info["name"])
	}
}

// ============================================================================
// Alerting handlers (6 handlers)
// ============================================================================

func TestHandleGetAlertingStatus(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_alerting_status",
		"arguments": map[string]any{},
	})
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

func TestHandleGetAlertingStatus_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_alerting_status",
		"arguments": map[string]any{},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

func TestHandleAddWebhook(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"name": "test-webhook", "url": "https://hooks.slack.com/test",
			"type": "slack", "events": []string{"block"}, "min_score": 50, "cooldown": "30s",
		},
	})
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

func TestHandleAddWebhook_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"url": "https://example.com", "type": "slack",
		},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleAddWebhook_MissingURL(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"name": "test", "type": "slack",
		},
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
		t.Fatal("expected error for missing url")
	}
}

func TestHandleAddWebhook_InvalidURLScheme(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"name": "test", "url": "gopher://evil.com", "type": "generic",
		},
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
		t.Fatal("expected error for invalid URL scheme")
	}
}

func TestHandleAddWebhook_MissingType(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"name": "test", "url": "https://example.com",
		},
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
		t.Fatal("expected error for missing type")
	}
}

func TestHandleAddWebhook_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_webhook",
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

func TestHandleAddWebhook_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_webhook",
		"arguments": map[string]any{
			"name": "test", "url": "https://example.com", "type": "slack",
		},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

func TestHandleRemoveWebhook(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_webhook",
		"arguments": map[string]any{"name": "test-webhook"},
	})
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

func TestHandleRemoveWebhook_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_webhook",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleRemoveWebhook_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_webhook",
		"arguments": map[string]any{"name": "test"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

func TestHandleAddEmailTarget(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"name": "ops", "smtp_host": "smtp.example.com", "smtp_port": 587,
			"username": "user", "password": "pass", "from": "waf@example.com",
			"to": []string{"admin@example.com"}, "use_tls": true,
		},
	})
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

func TestHandleAddEmailTarget_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"smtp_host": "smtp.example.com", "from": "waf@ex.com", "to": []string{"a@ex.com"},
		},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleAddEmailTarget_MissingSMTPHost(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"name": "test", "from": "waf@ex.com", "to": []string{"a@ex.com"},
		},
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
		t.Fatal("expected error for missing smtp_host")
	}
}

func TestHandleAddEmailTarget_MissingFrom(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"name": "test", "smtp_host": "smtp.example.com", "to": []string{"a@ex.com"},
		},
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
		t.Fatal("expected error for missing from")
	}
}

func TestHandleAddEmailTarget_MissingTo(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"name": "test", "smtp_host": "smtp.example.com", "from": "waf@ex.com",
		},
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
		t.Fatal("expected error for missing to")
	}
}

func TestHandleAddEmailTarget_InvalidJSON(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_email_target",
		"arguments": "invalid",
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
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandleAddEmailTarget_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_email_target",
		"arguments": map[string]any{
			"name": "test", "smtp_host": "smtp.example.com",
			"from": "waf@ex.com", "to": []string{"a@ex.com"},
		},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

func TestHandleRemoveEmailTarget(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_email_target",
		"arguments": map[string]any{"name": "test-target"},
	})
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

func TestHandleRemoveEmailTarget_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_email_target",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleRemoveEmailTarget_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_email_target",
		"arguments": map[string]any{"name": "test"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

func TestHandleTestAlert(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_test_alert",
		"arguments": map[string]any{"target": "test-webhook"},
	})
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

func TestHandleTestAlert_MissingTarget(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_test_alert",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing target")
	}
}

func TestHandleTestAlert_NoEngine(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_test_alert",
		"arguments": map[string]any{"target": "test"},
	})
	var out bytes.Buffer
	srv := NewServer(strings.NewReader(input), &out)
	srv.RegisterAllTools()
	_ = srv.Run()
	resp := readResponse(t, out.String())
	result, _ := resp.Result.(map[string]any)
	isError, _ := result["isError"].(bool)
	if !isError {
		t.Fatal("expected error with no engine")
	}
}

// ============================================================================
// CRS handlers (4 handlers)
// ============================================================================

func TestHandleGetCRSRules(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_crs_rules",
		"arguments": map[string]any{},
	})
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

func TestHandleGetCRSRules_WithFilters(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_get_crs_rules",
		"arguments": map[string]any{
			"phase": 1, "severity": "CRITICAL",
		},
	})
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

func TestHandleEnableCRSRule(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_enable_crs_rule",
		"arguments": map[string]any{
			"rule_id": "942100", "enabled": true,
		},
	})
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

func TestHandleEnableCRSRule_Disable(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_enable_crs_rule",
		"arguments": map[string]any{
			"rule_id": "942100", "enabled": false,
		},
	})
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

func TestHandleEnableCRSRule_MissingRuleID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_enable_crs_rule",
		"arguments": map[string]any{
			"enabled": true,
		},
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
		t.Fatal("expected error for missing rule_id")
	}
}

func TestHandleSetParanoiaLevel(t *testing.T) {
	for _, level := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			input := sendRequest(1, "tools/call", map[string]any{
				"name": "guardianwaf_set_paranoia_level",
				"arguments": map[string]any{
					"level": level,
				},
			})
			var out bytes.Buffer
			srv := NewServer(strings.NewReader(input), &out)
			srv.SetEngine(newMockEngine())
			srv.RegisterAllTools()
			_ = srv.Run()
			resp := readResponse(t, out.String())
			if resp.Error != nil {
				t.Fatalf("unexpected error for level %d: %v", level, resp.Error)
			}
		})
	}
}

func TestHandleSetParanoiaLevel_InvalidLevel(t *testing.T) {
	for _, level := range []int{0, 5, -1} {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			input := sendRequest(1, "tools/call", map[string]any{
				"name": "guardianwaf_set_paranoia_level",
				"arguments": map[string]any{
					"level": level,
				},
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
				t.Fatalf("expected error for level %d", level)
			}
		})
	}
}

func TestHandleAddCRSExclusion(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_crs_exclusion",
		"arguments": map[string]any{
			"rule_id": "942100", "path": "/api/webhook", "parameter": "q",
			"reason": "false positive on webhook",
		},
	})
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

func TestHandleAddCRSExclusion_MissingRuleID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_crs_exclusion",
		"arguments": map[string]any{
			"path": "/api",
		},
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
		t.Fatal("expected error for missing rule_id")
	}
}

// ============================================================================
// Virtual Patch handlers (4 handlers)
// ============================================================================

func TestHandleGetVirtualPatches(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_virtual_patches",
		"arguments": map[string]any{},
	})
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

func TestHandleGetVirtualPatches_WithFilters(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_get_virtual_patches",
		"arguments": map[string]any{
			"severity": "CRITICAL", "active_only": true,
		},
	})
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

func TestHandleEnableVirtualPatch(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_enable_virtual_patch",
		"arguments": map[string]any{
			"patch_id": "VP-LOG4SHELL-001", "enabled": true,
		},
	})
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

func TestHandleEnableVirtualPatch_MissingPatchID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_enable_virtual_patch",
		"arguments": map[string]any{
			"enabled": true,
		},
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
		t.Fatal("expected error for missing patch_id")
	}
}

func TestHandleAddCustomPatch(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_custom_patch",
		"arguments": map[string]any{
			"id": "VP-CUSTOM-001", "name": "Test Patch", "description": "Test",
			"cve_id": "CVE-2024-0001", "pattern": ".*exploit.*", "pattern_type": "regex",
			"target": "path", "action": "block", "severity": "HIGH", "score": 80,
		},
	})
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

func TestHandleAddCustomPatch_MissingRequired(t *testing.T) {
	requiredFields := []string{"id", "name", "pattern", "pattern_type", "target", "action"}
	for _, field := range requiredFields {
		t.Run("missing_"+field, func(t *testing.T) {
			args := map[string]any{
				"id": "VP-TEST", "name": "Test", "pattern": "test",
				"pattern_type": "contains", "target": "path", "action": "block",
			}
			delete(args, field)
			input := sendRequest(1, "tools/call", map[string]any{
				"name":      "guardianwaf_add_custom_patch",
				"arguments": args,
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
				t.Fatalf("expected error for missing %s", field)
			}
		})
	}
}

func TestHandleUpdateCVEDatabase(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_update_cve_database",
		"arguments": map[string]any{},
	})
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

func TestHandleUpdateCVEDatabase_EngineError(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_update_cve_database",
		"arguments": map[string]any{},
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

// ============================================================================
// API Validation handlers (5 handlers)
// ============================================================================

func TestHandleGetAPISchemas(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_api_schemas",
		"arguments": map[string]any{},
	})
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

func TestHandleUploadAPISchema(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_upload_api_schema",
		"arguments": map[string]any{
			"name": "test-schema", "content": `{"openapi":"3.0.0"}`,
			"format": "json", "strict_mode": true,
		},
	})
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

func TestHandleUploadAPISchema_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_upload_api_schema",
		"arguments": map[string]any{
			"content": "{}", "format": "json",
		},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleUploadAPISchema_MissingContent(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_upload_api_schema",
		"arguments": map[string]any{
			"name": "test", "format": "json",
		},
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
		t.Fatal("expected error for missing content")
	}
}

func TestHandleUploadAPISchema_DefaultFormat(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_upload_api_schema",
		"arguments": map[string]any{
			"name": "test", "content": `{"openapi":"3.0.0"}`,
		},
	})
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

func TestHandleRemoveAPISchema(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_api_schema",
		"arguments": map[string]any{"name": "test-schema"},
	})
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

func TestHandleRemoveAPISchema_MissingName(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_api_schema",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing name")
	}
}

func TestHandleSetAPIValidationMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_set_api_validation_mode",
		"arguments": map[string]any{
			"validate_request": true, "validate_response": false,
			"strict_mode": true, "block_on_violation": true,
		},
	})
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

func TestHandleSetAPIValidationMode_EmptyParams(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_api_validation_mode",
		"arguments": map[string]any{},
	})
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

func TestHandleTestAPISchema(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_api_schema",
		"arguments": map[string]any{
			"method": "POST", "path": "/api/users", "body": `{"name":"test"}`,
		},
	})
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

func TestHandleTestAPISchema_MissingMethod(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_api_schema",
		"arguments": map[string]any{
			"path": "/api/users",
		},
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
		t.Fatal("expected error for missing method")
	}
}

func TestHandleTestAPISchema_MissingPath(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_api_schema",
		"arguments": map[string]any{
			"method": "GET",
		},
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
		t.Fatal("expected error for missing path")
	}
}

// ============================================================================
// Client-Side Protection handlers (4 handlers)
// ============================================================================

func TestHandleGetClientSideStats(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_clientside_stats",
		"arguments": map[string]any{},
	})
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

func TestHandleSetClientSideMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_set_clientside_mode",
		"arguments": map[string]any{
			"mode": "block", "magecart_detection": true,
			"agent_injection": true, "csp_enabled": true,
		},
	})
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

func TestHandleSetClientSideMode_MissingMode(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_clientside_mode",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing mode")
	}
}

func TestHandleAddSkimmingDomain(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_skimming_domain",
		"arguments": map[string]any{"domain": "evil-skimmer.com"},
	})
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

func TestHandleAddSkimmingDomain_MissingDomain(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_add_skimming_domain",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing domain")
	}
}

func TestHandleGetCSPReports(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_csp_report",
		"arguments": map[string]any{"limit": 50},
	})
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

func TestHandleGetCSPReports_DefaultLimit(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_csp_report",
		"arguments": map[string]any{},
	})
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

// ============================================================================
// DLP handlers (4 handlers)
// ============================================================================

func TestHandleGetDLPAlerts(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_dlp_alerts",
		"arguments": map[string]any{},
	})
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

func TestHandleGetDLPAlerts_WithFilters(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_get_dlp_alerts",
		"arguments": map[string]any{
			"limit": 10, "pattern_type": "credit_card",
		},
	})
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

func TestHandleAddDLPPattern(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_add_dlp_pattern",
		"arguments": map[string]any{
			"id": "DLP-CUSTOM-001", "name": "Test Pattern",
			"pattern": `\d{4}-\d{4}`, "description": "Test",
			"action": "block", "score": 80,
		},
	})
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

func TestHandleAddDLPPattern_MissingRequired(t *testing.T) {
	requiredFields := []string{"id", "name", "pattern", "action"}
	for _, field := range requiredFields {
		t.Run("missing_"+field, func(t *testing.T) {
			args := map[string]any{
				"id": "DLP-TEST", "name": "Test", "pattern": `\d+`, "action": "block",
			}
			delete(args, field)
			input := sendRequest(1, "tools/call", map[string]any{
				"name":      "guardianwaf_add_dlp_pattern",
				"arguments": args,
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
				t.Fatalf("expected error for missing %s", field)
			}
		})
	}
}

func TestHandleRemoveDLPPattern(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_dlp_pattern",
		"arguments": map[string]any{"id": "DLP-CUSTOM-001"},
	})
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

func TestHandleRemoveDLPPattern_MissingID(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_remove_dlp_pattern",
		"arguments": map[string]any{},
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
		t.Fatal("expected error for missing id")
	}
}

func TestHandleTestDLPPattern(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_dlp_pattern",
		"arguments": map[string]any{
			"pattern": `\d{4}-\d{4}-\d{4}-\d{4}`, "test_data": "Card: 4111-1111-1111-1111",
		},
	})
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

func TestHandleTestDLPPattern_MissingPattern(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_dlp_pattern",
		"arguments": map[string]any{
			"test_data": "some data",
		},
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
		t.Fatal("expected error for missing pattern")
	}
}

func TestHandleTestDLPPattern_MissingTestData(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_test_dlp_pattern",
		"arguments": map[string]any{
			"pattern": `\d+`,
		},
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
		t.Fatal("expected error for missing test_data")
	}
}

// ============================================================================
// HTTP/3 handlers (2 handlers)
// ============================================================================

func TestHandleGetHTTP3Status(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_get_http3_status",
		"arguments": map[string]any{},
	})
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

func TestHandleSetHTTP3Config(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name": "guardianwaf_set_http3_config",
		"arguments": map[string]any{
			"enabled": true, "enable_0rtt": true, "advertise_alt_svc": true,
		},
	})
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

func TestHandleSetHTTP3Config_EmptyParams(t *testing.T) {
	input := sendRequest(1, "tools/call", map[string]any{
		"name":      "guardianwaf_set_http3_config",
		"arguments": map[string]any{},
	})
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

// ============================================================================
// Engine error paths for all new feature handlers via HandleRequestJSON
// ============================================================================

func TestAllNewFeatureHandlers_EngineErrors(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
	}{
		{"guardianwaf_get_crs_rules", map[string]any{}},
		{"guardianwaf_enable_crs_rule", map[string]any{"rule_id": "942100", "enabled": true}},
		{"guardianwaf_set_paranoia_level", map[string]any{"level": 2}},
		{"guardianwaf_add_crs_exclusion", map[string]any{"rule_id": "942100"}},
		{"guardianwaf_get_virtual_patches", map[string]any{}},
		{"guardianwaf_enable_virtual_patch", map[string]any{"patch_id": "VP-001", "enabled": true}},
		{"guardianwaf_add_custom_patch", map[string]any{
			"id": "VP-T", "name": "T", "pattern": "p", "pattern_type": "regex", "target": "path", "action": "block",
		}},
		{"guardianwaf_update_cve_database", map[string]any{}},
		{"guardianwaf_get_api_schemas", map[string]any{}},
		{"guardianwaf_upload_api_schema", map[string]any{"name": "s", "content": "{}", "format": "json"}},
		{"guardianwaf_remove_api_schema", map[string]any{"name": "s"}},
		{"guardianwaf_set_api_validation_mode", map[string]any{}},
		{"guardianwaf_test_api_schema", map[string]any{"method": "GET", "path": "/api"}},
		{"guardianwaf_get_clientside_stats", map[string]any{}},
		{"guardianwaf_set_clientside_mode", map[string]any{"mode": "monitor"}},
		{"guardianwaf_add_skimming_domain", map[string]any{"domain": "evil.com"}},
		{"guardianwaf_get_csp_report", map[string]any{}},
		{"guardianwaf_get_dlp_alerts", map[string]any{}},
		{"guardianwaf_add_dlp_pattern", map[string]any{"id": "D1", "name": "N", "pattern": "p", "action": "block"}},
		{"guardianwaf_remove_dlp_pattern", map[string]any{"id": "D1"}},
		{"guardianwaf_test_dlp_pattern", map[string]any{"pattern": "p", "test_data": "t"}},
		{"guardianwaf_get_http3_status", map[string]any{}},
		{"guardianwaf_set_http3_config", map[string]any{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name":      tt.name,
					"arguments": tt.args,
				},
			})
			srv := NewServer(nil, nil)
			srv.SetEngine(newFailEngine())
			srv.RegisterAllTools()

			respData, err := srv.HandleRequestJSON(reqData)
			if err != nil {
				t.Fatalf("HandleRequestJSON error: %v", err)
			}
			var resp JSONRPCResponse
			if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
				t.Fatalf("invalid response JSON: %v", jsonErr)
			}
			result, ok := resp.Result.(map[string]any)
			if !ok {
				t.Fatalf("result not a map, got: %v", resp)
			}
			isError, _ := result["isError"].(bool)
			if !isError {
				t.Fatalf("expected isError=true for %s with fail engine", tt.name)
			}
		})
	}
}

// ============================================================================
// SSE edge cases
// ============================================================================

func TestSSEAuthenticate_EmptyKeyConfigured(t *testing.T) {
	handler, _ := helperSSEServer("")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if handler.authenticate(req) {
		t.Fatal("expected rejection when apiKey is empty")
	}
}

func TestSSEAuthenticate_NoHeaderNoQuery(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if handler.authenticate(req) {
		t.Fatal("expected rejection with no header and no query param")
	}
}

func TestHandleSSE_MaxClients(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	handler.mu.Lock()
	for i := 0; i < maxMCPSSEClients; i++ {
		handler.clients[&sseClient{done: make(chan struct{})}] = true
	}
	handler.mu.Unlock()

	rec := httptest.NewRecorder()
	flushRec := &safeResponseRecorder{rec: rec}
	req := helperAuthReq(http.MethodGet, "/mcp/sse", nil)
	handler.handleSSE(flushRec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when max clients reached, got %d", rec.Code)
	}
}

// ============================================================================
// NewFeatureTools and RegisterNewFeatureHandlers
// ============================================================================

func TestNewFeatureTools(t *testing.T) {
	tools := NewFeatureTools()
	if len(tools) != 23 {
		t.Fatalf("expected 23 new feature tools, got %d", len(tools))
	}
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
	}
}

func TestRegisterNewFeatureHandlers(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.RegisterNewFeatureHandlers()
	if srv.ToolCount() != 23 {
		t.Fatalf("expected 23 new feature tools, got %d", srv.ToolCount())
	}
}

// ============================================================================
// Invalid JSON for new feature handlers via HandleRequestJSON
// ============================================================================

func TestNewFeatureHandlers_InvalidJSON(t *testing.T) {
	tests := []string{
		"guardianwaf_enable_crs_rule",
		"guardianwaf_set_paranoia_level",
		"guardianwaf_add_crs_exclusion",
		"guardianwaf_enable_virtual_patch",
		"guardianwaf_add_custom_patch",
		"guardianwaf_upload_api_schema",
		"guardianwaf_remove_api_schema",
		"guardianwaf_set_api_validation_mode",
		"guardianwaf_test_api_schema",
		"guardianwaf_set_clientside_mode",
		"guardianwaf_add_skimming_domain",
		"guardianwaf_add_dlp_pattern",
		"guardianwaf_remove_dlp_pattern",
		"guardianwaf_test_dlp_pattern",
		"guardianwaf_set_http3_config",
	}

	for _, toolName := range tests {
		t.Run(toolName, func(t *testing.T) {
			reqData, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name":      toolName,
					"arguments": "not-json-object",
				},
			})
			srv := NewServer(nil, nil)
			srv.SetEngine(newMockEngine())
			srv.RegisterAllTools()

			respData, err := srv.HandleRequestJSON(reqData)
			if err != nil {
				t.Fatalf("HandleRequestJSON error: %v", err)
			}
			var resp JSONRPCResponse
			if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
				t.Fatalf("invalid response JSON: %v", jsonErr)
			}
			result, ok := resp.Result.(map[string]any)
			if !ok {
				t.Fatalf("result not a map: %v", resp)
			}
			isError, _ := result["isError"].(bool)
			if !isError {
				t.Fatalf("expected isError=true for invalid JSON to %s", toolName)
			}
		})
	}
}

// ============================================================================
// No engine for new feature handlers via HandleRequestJSON
// ============================================================================

func TestNewFeatureHandlers_NoEngine(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
	}{
		{"guardianwaf_get_crs_rules", map[string]any{}},
		{"guardianwaf_enable_crs_rule", map[string]any{"rule_id": "942100", "enabled": true}},
		{"guardianwaf_set_paranoia_level", map[string]any{"level": 2}},
		{"guardianwaf_add_crs_exclusion", map[string]any{"rule_id": "942100"}},
		{"guardianwaf_get_virtual_patches", map[string]any{}},
		{"guardianwaf_enable_virtual_patch", map[string]any{"patch_id": "VP-001", "enabled": true}},
		{"guardianwaf_add_custom_patch", map[string]any{
			"id": "VP-T", "name": "T", "pattern": "p", "pattern_type": "regex", "target": "path", "action": "block",
		}},
		{"guardianwaf_update_cve_database", map[string]any{}},
		{"guardianwaf_get_api_schemas", map[string]any{}},
		{"guardianwaf_upload_api_schema", map[string]any{"name": "s", "content": "{}", "format": "json"}},
		{"guardianwaf_remove_api_schema", map[string]any{"name": "s"}},
		{"guardianwaf_set_api_validation_mode", map[string]any{}},
		{"guardianwaf_test_api_schema", map[string]any{"method": "GET", "path": "/api"}},
		{"guardianwaf_get_clientside_stats", map[string]any{}},
		{"guardianwaf_set_clientside_mode", map[string]any{"mode": "monitor"}},
		{"guardianwaf_add_skimming_domain", map[string]any{"domain": "evil.com"}},
		{"guardianwaf_get_csp_report", map[string]any{}},
		{"guardianwaf_get_dlp_alerts", map[string]any{}},
		{"guardianwaf_add_dlp_pattern", map[string]any{"id": "D1", "name": "N", "pattern": "p", "action": "block"}},
		{"guardianwaf_remove_dlp_pattern", map[string]any{"id": "D1"}},
		{"guardianwaf_test_dlp_pattern", map[string]any{"pattern": "p", "test_data": "t"}},
		{"guardianwaf_get_http3_status", map[string]any{}},
		{"guardianwaf_set_http3_config", map[string]any{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name":      tt.name,
					"arguments": tt.args,
				},
			})
			srv := NewServer(nil, nil)
			srv.RegisterAllTools()

			respData, err := srv.HandleRequestJSON(reqData)
			if err != nil {
				t.Fatalf("HandleRequestJSON error: %v", err)
			}
			var resp JSONRPCResponse
			if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
				t.Fatalf("invalid response JSON: %v", jsonErr)
			}
			result, ok := resp.Result.(map[string]any)
			if !ok {
				t.Fatalf("result not a map: %v", resp)
			}
			isError, _ := result["isError"].(bool)
			if !isError {
				t.Fatalf("expected isError=true for %s with no engine", tt.name)
			}
		})
	}
}

// ============================================================================
// Bulk tool call for all new feature + alerting handlers via stdio pipeline
// ============================================================================

func TestBulkNewFeatureToolCalls(t *testing.T) {
	toolCalls := []struct {
		name string
		args map[string]any
	}{
		{"guardianwaf_get_crs_rules", map[string]any{}},
		{"guardianwaf_enable_crs_rule", map[string]any{"rule_id": "942100", "enabled": true}},
		{"guardianwaf_set_paranoia_level", map[string]any{"level": 2}},
		{"guardianwaf_add_crs_exclusion", map[string]any{"rule_id": "942100"}},
		{"guardianwaf_get_virtual_patches", map[string]any{}},
		{"guardianwaf_enable_virtual_patch", map[string]any{"patch_id": "VP-001", "enabled": true}},
		{"guardianwaf_add_custom_patch", map[string]any{
			"id": "VP-BULK", "name": "Bulk", "pattern": "test", "pattern_type": "contains",
			"target": "path", "action": "block", "severity": "HIGH", "score": 80,
		}},
		{"guardianwaf_update_cve_database", map[string]any{}},
		{"guardianwaf_get_api_schemas", map[string]any{}},
		{"guardianwaf_upload_api_schema", map[string]any{"name": "s", "content": "{}", "format": "json"}},
		{"guardianwaf_remove_api_schema", map[string]any{"name": "s"}},
		{"guardianwaf_set_api_validation_mode", map[string]any{}},
		{"guardianwaf_test_api_schema", map[string]any{"method": "GET", "path": "/api"}},
		{"guardianwaf_get_clientside_stats", map[string]any{}},
		{"guardianwaf_set_clientside_mode", map[string]any{"mode": "monitor"}},
		{"guardianwaf_add_skimming_domain", map[string]any{"domain": "evil.com"}},
		{"guardianwaf_get_csp_report", map[string]any{}},
		{"guardianwaf_get_dlp_alerts", map[string]any{}},
		{"guardianwaf_add_dlp_pattern", map[string]any{
			"id": "D1", "name": "N", "pattern": "p", "action": "block", "score": 50,
		}},
		{"guardianwaf_remove_dlp_pattern", map[string]any{"id": "D1"}},
		{"guardianwaf_test_dlp_pattern", map[string]any{"pattern": "p", "test_data": "t"}},
		{"guardianwaf_get_http3_status", map[string]any{}},
		{"guardianwaf_set_http3_config", map[string]any{}},
		{"guardianwaf_get_alerting_status", map[string]any{}},
		{"guardianwaf_add_webhook", map[string]any{
			"name": "wh", "url": "https://example.com", "type": "slack",
		}},
		{"guardianwaf_remove_webhook", map[string]any{"name": "wh"}},
		{"guardianwaf_add_email_target", map[string]any{
			"name": "em", "smtp_host": "smtp.example.com", "from": "waf@ex.com", "to": []string{"a@ex.com"},
		}},
		{"guardianwaf_remove_email_target", map[string]any{"name": "em"}},
		{"guardianwaf_test_alert", map[string]any{"target": "wh"}},
	}

	var input strings.Builder
	for i, tc := range toolCalls {
		input.WriteString(sendRequest(i+1, "tools/call", map[string]any{
			"name":      tc.name,
			"arguments": tc.args,
		}))
	}

	output := &bytes.Buffer{}
	srv := NewServer(strings.NewReader(input.String()), output)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	_ = srv.Run()

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
			content, _ := result["content"].([]any)
			if len(content) > 0 {
				item, _ := content[0].(map[string]any)
				t.Errorf("tool %s (response %d) error: %v", toolCalls[i].name, i, item["text"])
			} else {
				t.Errorf("tool %s (response %d) returned tool error", toolCalls[i].name, i)
			}
		}
	}
}

// ============================================================================
// writeResponse with writer error
// ============================================================================

func TestWriteResponse_WriterError(t *testing.T) {
	srv := NewServer(nil, &failingWriter{})
	srv.writeResponse(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]any{"ok": true},
	})
	// Should not panic even when writer fails
}

type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write failure")
}

// ============================================================================
// processRequest direct tests
// ============================================================================

func TestProcessRequest_Initialize(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetServerInfo("test", "1.0")
	resp := srv.processRequest(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestProcessRequest_Notification(t *testing.T) {
	srv := NewServer(nil, nil)
	_ = srv.processRequest(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "notifications/initialized",
	})
}

func TestProcessRequest_ToolsList(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	resp := srv.processRequest(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestProcessRequest_ToolsCall(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	params, _ := json.Marshal(map[string]any{
		"name":      "guardianwaf_get_stats",
		"arguments": map[string]any{},
	})
	resp := srv.processRequest(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  params,
	})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestProcessRequest_UnknownMethod(t *testing.T) {
	srv := NewServer(nil, nil)
	resp := srv.processRequest(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown/method",
	})
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method not found, got %d", resp.Error.Code)
	}
}

// Ensure unused imports are consumed
var _ io.Reader = &errReader{}
var _ = fmt.Sprintf
