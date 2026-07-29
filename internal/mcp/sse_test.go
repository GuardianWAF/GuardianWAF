package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// helperSSEServer creates a fully-wired SSEHandler with a real MCP server and mock engine.
func helperSSEServer(apiKey string) (*SSEHandler, *Server) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()
	handler := NewSSEHandler(srv, apiKey)
	return handler, srv
}

// helperAuthReq creates an authenticated request with the default test API key.
func helperAuthReq(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("X-API-Key", "test-api-key")
	return req
}

// --- NewSSEHandler ---

func TestNewSSEHandler_BasicFields(t *testing.T) {
	handler, _ := helperSSEServer("secret")
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.server == nil {
		t.Fatal("expected server to be set")
	}
	if handler.apiKey != "secret" {
		t.Fatalf("expected apiKey 'secret', got %q", handler.apiKey)
	}
	if handler.clients == nil {
		t.Fatal("expected clients map to be initialized")
	}
	if len(handler.clients) != 0 {
		t.Fatalf("expected empty clients map, got %d entries", len(handler.clients))
	}
}

// --- authenticate ---

func TestAuthenticate_NonEmptyKeyRequiresHeader(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if handler.authenticate(req) {
		t.Fatal("expected request without API key to be denied when apiKey is set")
	}
	// Correct key should pass
	req2 := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	req2.Header.Set("X-API-Key", "test-api-key")
	if !handler.authenticate(req2) {
		t.Fatal("expected correct API key to authenticate")
	}
}

func TestAuthenticate_CorrectHeaderKey(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	req.Header.Set("X-API-Key", "mykey")
	if !handler.authenticate(req) {
		t.Fatal("expected correct X-API-Key header to authenticate")
	}
}

func TestAuthenticate_CorrectQueryParam(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse?api_key=mykey", nil)
	// Query param API keys are rejected to prevent credential leakage via logs
	if handler.authenticate(req) {
		t.Fatal("expected api_key query param to be rejected (use X-API-Key header only)")
	}
}

func TestAuthenticate_WrongKeyDenies(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	req.Header.Set("X-API-Key", "wrong")
	if handler.authenticate(req) {
		t.Fatal("expected wrong key to deny request")
	}
}

func TestAuthenticate_LiveKeyProviderRotatesImmediately(t *testing.T) {
	srv := NewServer(nil, nil)
	currentKey := "old-key"
	handler := NewSSEHandlerWithAPIKeyProvider(srv, func() string { return currentKey })

	request := func(key string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
		req.Header.Set("X-API-Key", key)
		return req
	}
	if !handler.authenticate(request("old-key")) {
		t.Fatal("initial provider key did not authenticate")
	}
	currentKey = "new-key"
	if handler.authenticate(request("old-key")) {
		t.Fatal("old provider key still authenticated after rotation")
	}
	if !handler.authenticate(request("new-key")) {
		t.Fatal("new provider key did not authenticate immediately")
	}
}

func TestAuthenticate_NoKeyWhenRequiredDenies(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if handler.authenticate(req) {
		t.Fatal("expected missing key to deny request when apiKey is set")
	}
}

func TestSanitizeSSEEndpointHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "hostname", host: "example.com", want: "example.com"},
		{name: "port", host: "example.com:8443", want: "example.com:8443"},
		{name: "empty", host: "", want: ""},
		{name: "userinfo", host: "example.com@evil.test", want: ""},
		{name: "slash", host: "example.com/evil", want: ""},
		{name: "backslash", host: "example.com\\evil", want: ""},
		{name: "newline", host: "example.com\nevent: injected", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeSSEEndpointHost(tt.host); got != tt.want {
				t.Fatalf("sanitizeSSEEndpointHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// --- RegisterRoutes ---

func TestRegisterRoutes_Registered(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Verify POST /mcp/message route is reachable.
	req := helperAuthReq(http.MethodPost, "/mcp/message", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	// Empty body -> LimitReader returns 0 bytes -> empty JSON -> parse error handled
	// The handler calls HandleRequestJSON which returns an error response but not 500
	// because empty body is valid input to HandleRequestJSON.
	// It should return 202 (Accepted) since HandleRequestJSON succeeds with parse error response.
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /mcp/message: expected status 202, got %d", w.Code)
	}

	// Verify GET /mcp/sse route is reachable (it blocks on context, so use a cancellable context).
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sseReq := helperAuthReq(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)
	sseW := httptest.NewRecorder()
	mux.ServeHTTP(sseW, sseReq)
	// After context cancellation the handler unblocks; check that it wrote the SSE headers.
	if !strings.Contains(sseW.Body.String(), "endpoint") {
		t.Fatal("expected SSE endpoint event in response body")
	}
}

func TestHandleMessage_AuditsMutatingToolWithSSEAuthContext(t *testing.T) {
	handler, srv := helperSSEServer("test-api-key")
	var logs bytes.Buffer
	srv.log = slog.New(slog.NewJSONHandler(&logs, nil))

	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_add_webhook","arguments":{"name":"ops","url":"https://hooks.example.test/secret-token","type":"generic"}}}`)
	req := helperAuthReq(http.MethodPost, "/mcp/message", body)
	req.RemoteAddr = "203.0.113.10:4444"
	w := httptest.NewRecorder()

	handler.handleMessage(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d: %s", w.Code, w.Body.String())
	}

	out := logs.String()
	for _, want := range []string{
		"MCP mutating tool call",
		"guardianwaf_add_webhook",
		"success",
		`"transport":"sse"`,
		`"auth_type":"api_key"`,
		`"principal":"dashboard_api_key"`,
		`"remote_addr":"203.0.113.10:4444"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit log missing %q: %s", want, out)
		}
	}
	for _, forbidden := range []string{
		"test-api-key",
		"hooks.example.test",
		"secret-token",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("audit log leaked %q: %s", forbidden, out)
		}
	}
}

// --- ClientCount ---

func TestClientCount_InitiallyZero(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	if handler.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", handler.ClientCount())
	}
}

func TestClientCount_AfterSSEConnection(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect to SSE endpoint.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/mcp/sse", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("X-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	// Give server a moment to register the client.
	time.Sleep(50 * time.Millisecond)

	count := handler.ClientCount()
	if count != 1 {
		t.Fatalf("expected 1 client, got %d", count)
	}

	// Close the response body (client disconnects), which should trigger cleanup.
	// resp.Body.Close() will cancel the request context.
	// Already deferred above, but let's force it early.
	resp.Body.Close()

	// Wait for cleanup.
	time.Sleep(100 * time.Millisecond)

	count = handler.ClientCount()
	if count != 0 {
		t.Fatalf("expected 0 clients after disconnect, got %d", count)
	}
	handler.mu.Lock()
	sessionCount := len(handler.sessions)
	handler.mu.Unlock()
	if sessionCount != 0 {
		t.Fatalf("expected 0 session routes after disconnect, got %d", sessionCount)
	}
}

// --- handleSSE ---

func TestHandleSSE_Unauthorized(t *testing.T) {
	handler, _ := helperSSEServer("secretkey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	w := httptest.NewRecorder()
	handler.handleSSE(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleSSE_MethodNotAllowed(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/sse", nil)
	w := httptest.NewRecorder()
	handler.handleSSE(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for non-GET SSE request, got %d", w.Code)
	}
}

func TestHandleSSE_Headers(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	sseReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	sseReq.Header.Set("X-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Fatalf("expected Content-Type 'text/event-stream', got %q", ct)
	}
	cc := resp.Header.Get("Cache-Control")
	if cc != "no-cache" {
		t.Fatalf("expected Cache-Control 'no-cache', got %q", cc)
	}
	conn := resp.Header.Get("Connection")
	if conn != "keep-alive" {
		t.Fatalf("expected Connection 'keep-alive', got %q", conn)
	}
	// Access-Control-Allow-Origin should NOT be set (wildcard CORS removed for security)
	aco := resp.Header.Get("Access-Control-Allow-Origin")
	if aco != "" {
		t.Fatalf("expected no Access-Control-Allow-Origin header, got %q", aco)
	}
}

func TestHandleSSE_EndpointEvent(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	epReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	epReq.Header.Set("X-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(epReq)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	// Read the first SSE event (endpoint event).
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read event type: %v", err)
	}
	if !strings.HasPrefix(line, "event: endpoint") {
		t.Fatalf("expected 'event: endpoint', got %q", line)
	}
	dataLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read data line: %v", err)
	}
	if !strings.HasPrefix(dataLine, "data: ") {
		t.Fatalf("expected 'data: ...', got %q", dataLine)
	}
	// Extract the session-scoped URL from the data line.
	data := strings.TrimSpace(strings.TrimPrefix(dataLine, "data: "))
	endpoint, err := url.Parse(data)
	if err != nil {
		t.Fatalf("invalid endpoint URL %q: %v", data, err)
	}
	if endpoint.Path != "/mcp/message" || endpoint.Query().Get("session_id") == "" {
		t.Fatalf("expected session-scoped /mcp/message endpoint, got %q", data)
	}
}

// --- handleMessage ---

func TestHandleMessage_Unauthorized(t *testing.T) {
	handler, _ := helperSSEServer("secretkey")
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", nil)
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestHandleMessage_EmptyBody(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/message", strings.NewReader(""))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	// Empty body is valid input to HandleRequestJSON (will produce parse error response)
	// but handleMessage does not error on it; HandleRequestJSON returns the parse error
	// as JSON, so respData is non-nil, err is nil => 202.
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestHandleMessage_ValidJSONRPC(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	req := helperAuthReq(http.MethodPost, "/mcp/message", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestHandleMessage_InvalidJSON(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/message", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	// HandleRequestJSON returns parse error as JSON, so err is nil => 202
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestHandleMessage_WithAPIKeyHeader(t *testing.T) {
	handler, _ := helperSSEServer("testkey")
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", strings.NewReader(reqBody))
	req.Header.Set("X-API-Key", "testkey")
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 with correct API key, got %d", w.Code)
	}
}

func TestHandleMessage_WithAPIKeyQueryParam(t *testing.T) {
	handler, _ := helperSSEServer("testkey")
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/message?api_key=testkey", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	// Query param API keys are rejected to prevent credential leakage
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (query param rejected), got %d", w.Code)
	}
}

// --- HandleRequestJSON (server.go:295) ---

func TestHandleRequestJSON_InvalidJSON(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	respData, err := srv.HandleRequestJSON([]byte("not json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response is not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error in response for invalid JSON")
	}
	if resp.Error.Code != ErrCodeParseError {
		t.Fatalf("expected parse error code %d, got %d", ErrCodeParseError, resp.Error.Code)
	}
}

func TestHandleRequestJSON_InvalidVersion(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"1.0","id":1,"method":"initialize"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response is not valid JSON: %v", jsonErr)
	}
	if resp.Error == nil {
		t.Fatal("expected error for invalid JSON-RPC version")
	}
	if resp.Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("expected invalid request code %d, got %d", ErrCodeInvalidRequest, resp.Error.Code)
	}
}

func TestHandleRequestJSON_ValidInitialize(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response is not valid JSON: %v", jsonErr)
	}
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
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("expected protocol version '2024-11-05', got %v", result["protocolVersion"])
	}
}

func TestHandleRequestJSON_ToolsList(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	reqData := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	respData, err := srv.HandleRequestJSON(reqData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal(respData, &resp); jsonErr != nil {
		t.Fatalf("response is not valid JSON: %v", jsonErr)
	}
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

// --- writeResponse with nil writer ---

func TestWriteResponse_NilWriter(t *testing.T) {
	srv := NewServer(nil, nil)
	// writer is nil; writeResponse should not panic.
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]any{"ok": true},
	}
	// This should not panic.
	srv.writeResponse(resp)
}

// --- session-scoped response delivery ---

func TestSessionResponse_SendsToConnectedClient(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect SSE client.
	sseReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("creating SSE request: %v", err)
	}
	sseReq.Header.Set("X-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	// Read the initial endpoint event to ensure the client is fully registered.
	reader := bufio.NewReader(resp.Body)
	// Read the advertised, session-scoped POST endpoint.
	_, _ = reader.ReadString('\n')
	endpointLine, _ := reader.ReadString('\n')
	endpointURL := strings.TrimSpace(strings.TrimPrefix(endpointLine, "data: "))
	_, _ = reader.ReadString('\n')
	if !strings.Contains(endpointURL, "session_id=") {
		t.Fatalf("expected session-scoped endpoint, got %q", endpointURL)
	}

	// Give the server a moment.
	time.Sleep(50 * time.Millisecond)

	if handler.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", handler.ClientCount())
	}

	// Send a message through this client's advertised endpoint.
	initReq := `{"jsonrpc":"2.0","id":99,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	postReq, err := http.NewRequest(http.MethodPost, endpointURL, strings.NewReader(initReq)) //nolint:noctx
	if err != nil {
		t.Fatalf("creating POST request: %v", err)
	}
	postReq.Header.Set("X-API-Key", "test-api-key")
	postReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST message failed: %v", err)
	}
	postResp.Body.Close()

	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", postResp.StatusCode)
	}

	// Read the routed SSE response from the client connection.
	// The server should send: event: message\ndata: {...}\n\n
	// Use a goroutine with a timeout to avoid blocking forever.
	type sseResult struct {
		eventType string
		data      string
	}
	resultCh := make(chan sseResult, 1)
	go func() {
		// Read event line
		evLine, err := reader.ReadString('\n')
		if err != nil {
			resultCh <- sseResult{eventType: "error", data: err.Error()}
			return
		}
		evLine = strings.TrimSuffix(evLine, "\n")
		eventType := strings.TrimPrefix(evLine, "event: ")

		dataLine, err := reader.ReadString('\n')
		if err != nil {
			resultCh <- sseResult{eventType: eventType, data: err.Error()}
			return
		}
		dataLine = strings.TrimSuffix(dataLine, "\n")
		data := strings.TrimPrefix(dataLine, "data: ")

		// Read the trailing blank line.
		_, _ = reader.ReadString('\n')

		resultCh <- sseResult{eventType: eventType, data: data}
	}()

	select {
	case result := <-resultCh:
		if result.eventType == "error" {
			t.Fatalf("error reading SSE event: %s", result.data)
		}
		if result.eventType != "message" {
			t.Fatalf("expected event type 'message', got %q", result.eventType)
		}
		// Parse the data as JSON-RPC response.
		var rpcResp JSONRPCResponse
		if jsonErr := json.Unmarshal([]byte(result.data), &rpcResp); jsonErr != nil {
			t.Fatalf("failed to parse routed data as JSON: %v\n data: %s", jsonErr, result.data)
		}
		if rpcResp.ID != float64(99) {
			t.Fatalf("expected response id 99, got %v", rpcResp.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for broadcast event")
	}
}

// --- Multiple SSE clients receive only their own responses ---

func TestHandleMessage_IsolatesResponseBySession(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	clientA := &sseClient{id: "session-a", done: make(chan struct{}), ch: make(chan []byte, 1)}
	clientB := &sseClient{id: "session-b", done: make(chan struct{}), ch: make(chan []byte, 1)}
	handler.mu.Lock()
	handler.clients[clientA] = true
	handler.clients[clientB] = true
	handler.sessions[clientA.id] = clientA
	handler.sessions[clientB.id] = clientB
	handler.mu.Unlock()

	body := `{"jsonrpc":"2.0","id":42,"method":"initialize","params":{}}`
	req := helperAuthReq(http.MethodPost, "/mcp/message?session_id=session-a", strings.NewReader(body))
	resp := httptest.NewRecorder()
	handler.handleMessage(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", resp.Code, resp.Body.String())
	}

	select {
	case data := <-clientA.ch:
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal(data, &rpcResp); err != nil {
			t.Fatalf("target response is invalid JSON: %v", err)
		}
		if rpcResp.ID != float64(42) {
			t.Fatalf("target response ID = %v, want 42", rpcResp.ID)
		}
	default:
		t.Fatal("target SSE session did not receive its response")
	}
	select {
	case data := <-clientB.ch:
		t.Fatalf("non-target SSE session received another client's response: %s", data)
	default:
	}
}

func TestHandleMessage_RequiresSessionWhenSSEClientConnected(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	client := &sseClient{id: "session-a", done: make(chan struct{}), ch: make(chan []byte, 1)}
	handler.mu.Lock()
	handler.clients[client] = true
	handler.sessions[client.id] = client
	handler.mu.Unlock()

	req := helperAuthReq(http.MethodPost, "/mcp/message", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	resp := httptest.NewRecorder()
	handler.handleMessage(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without session_id, got %d", resp.Code)
	}
	select {
	case data := <-client.ch:
		t.Fatalf("session received response for unbound request: %s", data)
	default:
	}
}

func TestHandleMessage_RejectsUnknownSession(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/message?session_id=missing", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	resp := httptest.NewRecorder()
	handler.handleMessage(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown session, got %d", resp.Code)
	}
}

// --- handleMessage read error (body returns error) ---

func TestHandleMessage_BodyReadError(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/message", &errReader{err: fmt.Errorf("read failure")})
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for read error, got %d", w.Code)
	}
}

func TestHandleMessage_BodyTooLarge(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodPost, "/mcp/message", strings.NewReader(strings.Repeat("x", maxMCPMessageBody+1)))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", w.Code)
	}
}

func TestHandleMessage_MethodNotAllowed(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	req := helperAuthReq(http.MethodGet, "/mcp/message", nil)
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for non-POST message request, got %d", w.Code)
	}
}

// --- handleMessage with a session-scoped SSE client ---

func TestHandleMessage_RoutesToSSEClient(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect SSE client.
	sseReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("creating SSE request: %v", err)
	}
	sseReq.Header.Set("X-API-Key", "test-api-key")
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	// Consume endpoint event and retain this client's session-scoped POST URL.
	_, _ = reader.ReadString('\n')
	endpointLine, _ := reader.ReadString('\n')
	endpointURL := strings.TrimSpace(strings.TrimPrefix(endpointLine, "data: "))
	_, _ = reader.ReadString('\n')

	time.Sleep(50 * time.Millisecond)

	// Send a tools/list request via this connection's endpoint.
	toolsReq := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	msgReq, err := http.NewRequest(http.MethodPost, endpointURL, strings.NewReader(toolsReq)) //nolint:noctx
	if err != nil {
		t.Fatalf("creating POST request: %v", err)
	}
	msgReq.Header.Set("X-API-Key", "test-api-key")
	msgReq.Header.Set("Content-Type", "application/json")
	postResp, err := http.DefaultClient.Do(msgReq)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	postResp.Body.Close()

	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", postResp.StatusCode)
	}

	// Read this session's response event.
	type ev struct {
		eventType string
		data      string
	}
	ch := make(chan ev, 1)
	go func() {
		evLine, _ := reader.ReadString('\n')
		dataLine, _ := reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
		ch <- ev{
			eventType: strings.TrimSuffix(strings.TrimPrefix(evLine, "event: "), "\n"),
			data:      strings.TrimSuffix(strings.TrimPrefix(dataLine, "data: "), "\n"),
		}
	}()

	select {
	case e := <-ch:
		if e.eventType != "message" {
			t.Fatalf("expected event type 'message', got %q", e.eventType)
		}
		var rpcResp JSONRPCResponse
		if jsonErr := json.Unmarshal([]byte(e.data), &rpcResp); jsonErr != nil {
			t.Fatalf("failed to parse routed response: %v", jsonErr)
		}
		if rpcResp.ID != float64(7) {
			t.Fatalf("expected response id 7, got %v", rpcResp.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for routed response")
	}
}

// --- SSE with API key in query param ---

func TestHandleSSE_WithAPIKeyQueryParam(t *testing.T) {
	handler, _ := helperSSEServer("mysecret")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Query param API keys are rejected — must use X-API-Key header
	resp, err := http.Get(ts.URL + "/mcp/sse?api_key=mysecret")
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 (query param rejected), got %d", resp.StatusCode)
	}

	// Verify header-based auth still works (test via authenticate method — handleSSE blocks indefinitely)
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	req.Header.Set("X-API-Key", "mysecret")
	if !handler.authenticate(req) {
		t.Fatal("expected X-API-Key header to authenticate")
	}
}

// --- SSE endpoint URL uses https scheme when TLS is set ---

func TestHandleSSE_EndpointURLScheme(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	urlReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil) //nolint:noctx
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	urlReq.Header.Set("X-API-Key", "test-api-key")
	resp, err := http.DefaultClient.Do(urlReq)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	// event: endpoint
	_, _ = reader.ReadString('\n')
	dataLine, _ := reader.ReadString('\n')
	data := strings.TrimPrefix(dataLine, "data: ")
	data = strings.TrimSpace(data)

	// httptest.NewServer uses http scheme (no TLS).
	if !strings.HasPrefix(data, "http://") {
		t.Fatalf("expected http:// scheme, got %q", data)
	}
}

// --- Full integration: SSE connect + POST message + verify broadcast + disconnect ---

func TestSSE_FullIntegration(t *testing.T) {
	handler, _ := helperSSEServer("intkey")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. Connect SSE client with API key header.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/mcp/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", "intkey")

	sseResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	// Read endpoint event.
	evLine, _ := reader.ReadString('\n')
	if !strings.Contains(evLine, "endpoint") {
		t.Fatalf("expected endpoint event, got %q", evLine)
	}
	dataLine, _ := reader.ReadString('\n')
	data := strings.TrimSuffix(strings.TrimPrefix(dataLine, "data: "), "\n")
	_, _ = reader.ReadString('\n') // blank line

	// 2. Verify client count.
	time.Sleep(50 * time.Millisecond)
	if handler.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", handler.ClientCount())
	}

	// 3. POST a message to the endpoint URL with the correct API key.
	postReq := `{"jsonrpc":"2.0","id":55,"method":"tools/list"}`
	httpReq, _ := http.NewRequest(http.MethodPost, data, strings.NewReader(postReq))
	httpReq.Header.Set("X-API-Key", "intkey")
	postResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", postResp.StatusCode)
	}

	// 4. Read broadcast from SSE client.
	ch := make(chan string, 1)
	go func() {
		_, _ = reader.ReadString('\n')
		msgData, _ := reader.ReadString('\n')
		_, _ = reader.ReadString('\n')
		ch <- strings.TrimSuffix(strings.TrimPrefix(msgData, "data: "), "\n")
	}()

	select {
	case rawData := <-ch:
		var rpcResp JSONRPCResponse
		if jsonErr := json.Unmarshal([]byte(rawData), &rpcResp); jsonErr != nil {
			t.Fatalf("failed to parse: %v", jsonErr)
		}
		if rpcResp.Error != nil {
			t.Fatalf("unexpected error in response: %v", rpcResp.Error)
		}
		if rpcResp.ID != float64(55) {
			t.Fatalf("expected id 55, got %v", rpcResp.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}

	// 5. Disconnect and verify cleanup.
	sseResp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	if handler.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after disconnect, got %d", handler.ClientCount())
	}
}

// --- HandleRequestJSON restores original writer ---

func TestHandleRequestJSON_PreservesOriginalWriter(t *testing.T) {
	var buf bytes.Buffer
	srv := NewServer(nil, &buf)
	srv.SetEngine(newMockEngine())
	srv.RegisterAllTools()

	_, err := srv.HandleRequestJSON([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After HandleRequestJSON, the original writer should be restored.
	// Write something via sendResult to verify.
	srv.sendResult(2, map[string]any{"test": true})
	output := buf.String()
	if output == "" {
		t.Fatal("expected output on original writer after HandleRequestJSON")
	}
	var resp JSONRPCResponse
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &resp); jsonErr != nil {
		t.Fatalf("failed to parse: %v", jsonErr)
	}
	if resp.ID != float64(2) {
		t.Fatalf("expected id 2, got %v", resp.ID)
	}
}

// --- enqueueResponse with a disconnected client ---

func TestEnqueueResponse_DoneClient(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	doneCh := make(chan struct{})
	close(doneCh)
	client := &sseClient{id: "closed", done: doneCh, ch: make(chan []byte, 1)}

	handler.enqueueResponse(client, []byte(`{"jsonrpc":"2.0","id":1}`))
	select {
	case data := <-client.ch:
		t.Fatalf("disconnected client received data: %s", data)
	default:
	}
}

// flushRecorder is an http.ResponseWriter + http.Flusher for testing.
type flushRecorder struct {
	header  http.Header
	written int
	flushes int
}

func (f *flushRecorder) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}

func (f *flushRecorder) Write(b []byte) (int, error) {
	f.written += len(b)
	return len(b), nil
}

func (f *flushRecorder) WriteHeader(code int) {}

func (f *flushRecorder) Flush() {
	f.flushes++
}

// Ensure unused import for io is consumed.
var _ io.Reader = &errReader{}

// bytes import needed for HandleRequestJSON test.
// (already imported via bufio test usage above)
