package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func TestAuthenticate_EmptyAPIKeyAllowsAll(t *testing.T) {
	handler, _ := helperSSEServer("")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if !handler.authenticate(req) {
		t.Fatal("expected empty apiKey to allow all requests")
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
	if !handler.authenticate(req) {
		t.Fatal("expected correct api_key query param to authenticate")
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

func TestAuthenticate_NoKeyWhenRequiredDenies(t *testing.T) {
	handler, _ := helperSSEServer("mykey")
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	if handler.authenticate(req) {
		t.Fatal("expected missing key to deny request when apiKey is set")
	}
}

// --- RegisterRoutes ---

func TestRegisterRoutes_Registered(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Verify POST /mcp/message route is reachable.
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", nil)
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
	sseReq := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)
	sseW := httptest.NewRecorder()
	mux.ServeHTTP(sseW, sseReq)
	// After context cancellation the handler unblocks; check that it wrote the SSE headers.
	if !strings.Contains(sseW.Body.String(), "endpoint") {
		t.Fatal("expected SSE endpoint event in response body")
	}
}

// --- ClientCount ---

func TestClientCount_InitiallyZero(t *testing.T) {
	handler, _ := helperSSEServer("")
	if handler.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", handler.ClientCount())
	}
}

func TestClientCount_AfterSSEConnection(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect to SSE endpoint.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/mcp/sse", nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
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

func TestHandleSSE_Headers(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp/sse") //nolint:noctx
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
	aco := resp.Header.Get("Access-Control-Allow-Origin")
	if aco != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin '*', got %q", aco)
	}
}

func TestHandleSSE_EndpointEvent(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp/sse") //nolint:noctx
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
	// Extract the URL from data line.
	data := strings.TrimPrefix(dataLine, "data: ")
	data = strings.TrimSpace(data)
	if !strings.HasSuffix(data, "/mcp/message") {
		t.Fatalf("expected data to end with /mcp/message, got %q", data)
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
	handler, _ := helperSSEServer("")
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", strings.NewReader(""))
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
	handler, _ := helperSSEServer("")
	reqBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestHandleMessage_InvalidJSON(t *testing.T) {
	handler, _ := helperSSEServer("")
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", strings.NewReader("not-json"))
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

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 with correct API key in query, got %d", w.Code)
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

// --- broadcastResponse ---

func TestBroadcastResponse_SendsToClients(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect SSE client.
	resp, err := http.Get(ts.URL + "/mcp/sse") //nolint:noctx
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	// Read the initial endpoint event to ensure the client is fully registered.
	reader := bufio.NewReader(resp.Body)
	// Read event: endpoint
	_, _ = reader.ReadString('\n')
	// Read data: http://...
	_, _ = reader.ReadString('\n')
	// Read blank line separator
	_, _ = reader.ReadString('\n')

	// Give the server a moment.
	time.Sleep(50 * time.Millisecond)

	if handler.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", handler.ClientCount())
	}

	// Send a message via POST to trigger broadcastResponse.
	initReq := `{"jsonrpc":"2.0","id":99,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	postResp, err := http.Post(ts.URL+"/mcp/message", "application/json", strings.NewReader(initReq)) //nolint:noctx
	if err != nil {
		t.Fatalf("POST message failed: %v", err)
	}
	postResp.Body.Close()

	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", postResp.StatusCode)
	}

	// Read the broadcast SSE event from the client connection.
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
			t.Fatalf("failed to parse broadcast data as JSON: %v\n data: %s", jsonErr, result.data)
		}
		if rpcResp.ID != float64(99) {
			t.Fatalf("expected broadcast response id 99, got %v", rpcResp.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for broadcast event")
	}
}

// --- Integration: multiple SSE clients receive broadcast ---

func TestBroadcastResponse_MultipleClients(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const numClients = 3
	var wg sync.WaitGroup
	results := make(chan string, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(ts.URL + "/mcp/sse") //nolint:noctx
			if err != nil {
				results <- fmt.Sprintf("error: %v", err)
				return
			}
			defer resp.Body.Close()

			reader := bufio.NewReader(resp.Body)
			// Consume endpoint event.
			_, _ = reader.ReadString('\n')
			_, _ = reader.ReadString('\n')
			_, _ = reader.ReadString('\n')

			// Read the broadcast message.
			evLine, err := reader.ReadString('\n')
			if err != nil {
				results <- fmt.Sprintf("read event error: %v", err)
				return
			}
			results <- strings.TrimSuffix(evLine, "\n")
		}()
	}

	// Wait for all clients to connect and consume the initial event.
	// A small sleep to ensure goroutines have connected.
	time.Sleep(200 * time.Millisecond)

	if handler.ClientCount() != numClients {
		t.Fatalf("expected %d clients, got %d", numClients, handler.ClientCount())
	}

	// Send a message to trigger broadcast.
	initReq := `{"jsonrpc":"2.0","id":42,"method":"initialize","params":{}}`
	postResp, err := http.Post(ts.URL+"/mcp/message", "application/json", strings.NewReader(initReq)) //nolint:noctx
	if err != nil {
		t.Fatalf("POST message failed: %v", err)
	}
	postResp.Body.Close()

	// Collect results with timeout.
	timeout := time.After(5 * time.Second)
	received := 0
	for received < numClients {
		select {
		case r := <-results:
			if strings.HasPrefix(r, "error") || strings.HasPrefix(r, "read") {
				t.Errorf("client error: %s", r)
			} else if r != "event: message" {
				t.Errorf("expected 'event: message', got %q", r)
			}
			received++
		case <-timeout:
			t.Fatalf("timed out waiting for clients, got %d/%d", received, numClients)
		}
	}

	wg.Wait()
}

// --- broadcastResponse with no clients (should not panic) ---

func TestBroadcastResponse_NoClients(t *testing.T) {
	handler, _ := helperSSEServer("")
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]any{"ok": true},
	}
	// Should not panic with no clients.
	handler.broadcastResponse(resp)
}

// --- handleMessage read error (body returns error) ---

func TestHandleMessage_BodyReadError(t *testing.T) {
	handler, _ := helperSSEServer("")
	req := httptest.NewRequest(http.MethodPost, "/mcp/message", &errReader{err: fmt.Errorf("read failure")})
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for read error, got %d", w.Code)
	}
}

// --- handleMessage with SSE client connected (broadcast path) ---

func TestHandleMessage_BroadcastsToSSEClient(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect SSE client.
	sseResp, err := http.Get(ts.URL + "/mcp/sse")
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	// Consume endpoint event (3 lines: event, data, blank).
	_, _ = reader.ReadString('\n')
	_, _ = reader.ReadString('\n')
	_, _ = reader.ReadString('\n')

	time.Sleep(50 * time.Millisecond)

	// Send a tools/list request via POST.
	toolsReq := `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`
	postResp, err := http.Post(ts.URL+"/mcp/message", "application/json", strings.NewReader(toolsReq))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	postResp.Body.Close()

	if postResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", postResp.StatusCode)
	}

	// Read the broadcast event.
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
			t.Fatalf("failed to parse broadcast: %v", jsonErr)
		}
		if rpcResp.ID != float64(7) {
			t.Fatalf("expected broadcast id 7, got %v", rpcResp.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for broadcast")
	}
}

// --- SSE with API key in query param ---

func TestHandleSSE_WithAPIKeyQueryParam(t *testing.T) {
	handler, _ := helperSSEServer("mysecret")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp/sse?api_key=mysecret")
	if err != nil {
		t.Fatalf("SSE connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with correct api_key, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}
}

// --- SSE endpoint URL uses https scheme when TLS is set ---

func TestHandleSSE_EndpointURLScheme(t *testing.T) {
	handler, _ := helperSSEServer("")
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp/sse") //nolint:noctx
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

// --- broadcastResponse with client whose done channel is closed ---

func TestBroadcastResponse_DoneClient(t *testing.T) {
	handler, _ := helperSSEServer("")

	// Manually create a client with done already closed to simulate a disconnected client.
	doneCh := make(chan struct{})
	close(doneCh)

	// Use a recorder that supports Flush.
	flusher := &flushRecorder{}
	client := &sseClient{
		w:       flusher,
		flusher: flusher,
		done:    doneCh,
	}
	handler.mu.Lock()
	handler.clients[client] = true
	handler.mu.Unlock()

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  map[string]any{"ok": true},
	}
	// Should not panic, should skip the done client.
	handler.broadcastResponse(resp)

	// No data should have been written since client is done.
	if flusher.written > 0 {
		t.Fatalf("expected no data written to done client, got %d bytes", flusher.written)
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
