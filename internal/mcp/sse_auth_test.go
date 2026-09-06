package mcp

import (
	"encoding/json"
	"testing"
)

// Regression tests: tools/call arriving through the SSE transport must be
// authenticated by the transport's own per-request credential. The SSE layer
// authenticates every POST via the X-API-Key header (authenticateContext) and
// sets AuditContext.AuthType = "api_key" only after a successful
// constant-time key comparison — but processRequestWithAuditContext ignored
// that and consulted the server-wide `authenticated` flag, which nothing on
// the SSE path ever sets (the JSON-path initialize never authenticates).
// With an API key configured, every SSE tools/call was rejected with
// "authentication required" — the MCP SSE transport was unusable with auth
// enabled.

const sseToolsCallRequest = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats","arguments":{}}}`

func TestSSEAuthenticatedToolsCallIsAccepted(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("secret")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	// Exactly the AuditContext authenticateContext returns for a valid
	// X-API-Key header on the SSE transport.
	audit := &AuditContext{Transport: "sse", AuthType: "api_key", Principal: "dashboard_api_key"}

	respData, err := srv.HandleRequestJSONWithAuditContext([]byte(sseToolsCallRequest), audit)
	if err != nil {
		t.Fatalf("HandleRequestJSONWithAuditContext: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("FAIL: SSE tools/call with valid per-request credential rejected: %d %s", resp.Error.Code, resp.Error.Message)
	}
}

// Control: without a transport credential, tools/call with an API key
// configured must stay rejected on both sides of the fix.
func TestSSEUnauthenticatedToolsCallStillRejected(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("secret")
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	// nil audit context = no transport credential (the stdio-style path).
	respData, err := srv.HandleRequestJSONWithAuditContext([]byte(sseToolsCallRequest), nil)
	if err != nil {
		t.Fatalf("HandleRequestJSONWithAuditContext: %v", err)
	}
	var resp JSONRPCResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("FAIL: unauthenticated tools/call not rejected: %+v", resp)
	}
}
