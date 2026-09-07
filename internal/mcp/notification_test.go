package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Regression: the JSON/SSE request path returned a response for JSON-RPC
// NOTIFICATIONS. processRequestWithAuditContext answered
// notifications/initialized with JSONRPCResponse{ID: nil}, which marshals to
// {"jsonrpc":"2.0"} — never nil — so the SSE transport enqueued a spurious
// response frame for every mandatory lifecycle notification. JSON-RPC 2.0
// (§4.1) and the MCP spec forbid responding to notifications; the stdio path
// already handled this correctly.

func TestNotificationProducesNoResponse(t *testing.T) {
	s := NewServer(nil, nil) // SSE-only mode: no stdio reader/writer

	respData, err := s.HandleRequestJSON([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("HandleRequestJSON: %v", err)
	}
	if len(respData) > 0 {
		t.Fatalf("notification produced a response %s — notifications must go unanswered", respData)
	}
}

func TestRequestWithIDStillGetsResponse(t *testing.T) {
	s := NewServer(nil, nil)

	respData, err := s.HandleRequestJSON([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("HandleRequestJSON: %v", err)
	}
	if !bytes.Contains(respData, []byte(`"id":7`)) {
		t.Fatalf("request with ID produced no correlatable response: %s", respData)
	}
}

func TestParseErrorStillReturned(t *testing.T) {
	s := NewServer(nil, nil)

	respData, err := s.HandleRequestJSON([]byte(`{not json`))
	if err != nil {
		t.Fatalf("HandleRequestJSON: %v", err)
	}
	var resp struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil || resp.Error == nil || resp.Error.Code != -32700 {
		t.Fatalf("malformed input did not produce a parse error (-32700): %s", respData)
	}
}

func TestUnauthenticatedToolsCallStillRejected(t *testing.T) {
	s := NewServer(nil, nil)
	s.SetAPIKey("secret-key-0123456789abcdef")

	respData, err := s.HandleRequestJSON([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats"}}`))
	if err != nil {
		t.Fatalf("HandleRequestJSON: %v", err)
	}
	if !bytes.Contains(respData, []byte("-32001")) {
		t.Fatalf("unauthenticated tools/call was not rejected: %s", respData)
	}
}
