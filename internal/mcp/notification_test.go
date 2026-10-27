package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
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

// Regression F205: every notification (request without an "id" member) — not
// only notifications/initialized — must go unanswered on both transports,
// while still being processed. MCP clients send notifications/cancelled
// routinely; the server answered it with a -32601 error lacking an id.
func TestAnyNotificationProducesNoResponse(t *testing.T) {
	notifs := []string{
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"probe","arguments":{}}}`,
	}
	for _, n := range notifs {
		calls := 0
		probe := func(json.RawMessage) (any, error) { calls++; return "ok", nil }

		var out bytes.Buffer
		stdio := NewServer(strings.NewReader(n+"\n"), &out)
		stdio.RegisterTool("probe", probe)
		if err := stdio.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out.Len() != 0 {
			t.Fatalf("stdio answered notification %s: %s", n, out.String())
		}

		sse := NewServer(nil, nil)
		sse.RegisterTool("probe", probe)
		resp, err := sse.HandleRequestJSON([]byte(n))
		if err != nil {
			t.Fatalf("HandleRequestJSON: %v", err)
		}
		if len(resp) != 0 {
			t.Fatalf("HTTP answered notification %s: %s", n, resp)
		}
		if strings.Contains(n, "probe") && calls != 2 {
			t.Fatalf("notification tool call not processed on both transports: calls=%d", calls)
		}
	}

	// "id": null is a request, not a notification: it is answered with id null.
	resp, _ := NewServer(nil, nil).HandleRequestJSON([]byte(`{"jsonrpc":"2.0","id":null,"method":"nope"}`))
	if !bytes.Contains(resp, []byte(`"id":null`)) {
		t.Fatalf("request with id null not answered with id null: %s", resp)
	}
}

// Regression F206: a final stdio request without a trailing newline was read
// together with io.EOF and silently dropped.
func TestRunDispatchesUnterminatedFinalLine(t *testing.T) {
	var out bytes.Buffer
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	if err := NewServer(strings.NewReader(in), &out).Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Count(out.String(), "\n"); got != 2 || !strings.Contains(out.String(), `"id":2`) {
		t.Fatalf("expected 2 responses incl. id 2, got %d: %.200s", got, out.String())
	}
}
