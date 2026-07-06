package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleWithParams_IgnoresUnknownRequiredField(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())

	type params struct {
		Name string `json:"name"`
	}

	got, err := handleWithParams[params, string](
		srv,
		json.RawMessage(`{"name":"ok"}`),
		[]string{"DoesNotExist", "Name"},
		func(eng EngineInterface, p params) (string, error) {
			if p.Name != "ok" {
				return "", fmt.Errorf("unexpected name %q", p.Name)
			}
			return "ok", nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("expected ok result, got %q", got)
	}
}

func TestHandleAddRateLimit_NegativeLimit(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())

	_, err := srv.handleAddRateLimit(json.RawMessage(`{"id":"rl-neg","limit":-1,"window":"60s"}`))
	if err == nil || !strings.Contains(err.Error(), "limit must be > 0") {
		t.Fatalf("expected limit validation error, got %v", err)
	}
}

func TestAlertingHandlers_EngineErrors(t *testing.T) {
	tests := []struct {
		name   string
		call   func(*Server) (any, error)
		field  string
	}{
		{
			name:  "add webhook",
			call:  func(s *Server) (any, error) { return s.handleAddWebhook(json.RawMessage(`{"name":"ops","url":"https://hooks.example.test","type":"generic"}`)) },
			field: "fail",
		},
		{
			name:  "remove webhook",
			call:  func(s *Server) (any, error) { return s.handleRemoveWebhook(json.RawMessage(`{"name":"ops"}`)) },
			field: "fail",
		},
		{
			name:  "add email target",
			call:  func(s *Server) (any, error) { return s.handleAddEmailTarget(json.RawMessage(`{"name":"ops","smtp_host":"smtp.example.test","from":"from@example.test","to":["to@example.test"]}`)) },
			field: "fail",
		},
		{
			name:  "remove email target",
			call:  func(s *Server) (any, error) { return s.handleRemoveEmailTarget(json.RawMessage(`{"name":"ops"}`)) },
			field: "fail",
		},
		{
			name:  "test alert",
			call:  func(s *Server) (any, error) { return s.handleTestAlert(json.RawMessage(`{"target":"ops"}`)) },
			field: "fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(nil, nil)
			srv.SetEngine(newFailEngine())
			if _, err := tt.call(srv); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected engine error containing %q, got %v", tt.field, err)
			}
		})
	}
}

func TestValidateTools_DetectsDrift(t *testing.T) {
	t.Run("missing handler", func(t *testing.T) {
		s := NewServer(nil, nil)
		s.RegisterTool("guardianwaf_only_extra", func(params json.RawMessage) (any, error) { return nil, nil })
		err := s.ValidateTools()
		if err == nil {
			t.Fatal("expected drift error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "defined-but-not-registered") || !strings.Contains(msg, "registered-but-not-defined") {
			t.Fatalf("unexpected drift error: %v", err)
		}
		if !strings.Contains(msg, "guardianwaf_only_extra") {
			t.Fatalf("expected extra tool listed in drift error: %v", err)
		}
	})

	t.Run("missing definition only", func(t *testing.T) {
		var first ToolDefinition
		for _, tool := range AllTools() {
			first = tool
			break
		}
		s := NewServer(nil, nil)
		s.RegisterAllTools()
		s.mu.Lock()
		delete(s.tools, first.Name)
		s.mu.Unlock()
		err := s.ValidateTools()
		if err == nil {
			t.Fatal("expected drift error")
		}
		if !strings.Contains(err.Error(), first.Name) {
			t.Fatalf("expected missing tool name %q in error: %v", first.Name, err)
		}
	})
}

func TestHandleSSE_InvalidHost(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	rec := httptest.NewRecorder()
	req := helperAuthReq(http.MethodGet, "http://example.test/mcp/sse", nil)
	req.Host = "bad/host"
	handler.handleSSE(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid host, got %d", rec.Code)
	}
}

type failAfterFirstWriteRecorder struct {
	header          http.Header
	writeCalls      int
	firstWriteDone  chan struct{}
	firstWriteFired bool
}

func (r *failAfterFirstWriteRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *failAfterFirstWriteRecorder) Write(p []byte) (int, error) {
	r.writeCalls++
	if r.writeCalls == 1 {
		if r.firstWriteDone != nil && !r.firstWriteFired {
			close(r.firstWriteDone)
			r.firstWriteFired = true
		}
		return len(p), nil
	}
	return 0, fmt.Errorf("forced write failure")
}

func (r *failAfterFirstWriteRecorder) WriteHeader(statusCode int) {}
func (r *failAfterFirstWriteRecorder) Flush()                        {}

func TestHandleSSE_MessageWriteFailure(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	rec := &failAfterFirstWriteRecorder{firstWriteDone: make(chan struct{})}
	req := helperAuthReq(http.MethodGet, "http://example.test/mcp/sse", nil)
	done := make(chan struct{})
	go func() {
		handler.handleSSE(rec, req)
		close(done)
	}()

	select {
	case <-rec.firstWriteDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial SSE endpoint write")
	}

	var client *sseClient
	handler.mu.Lock()
	for c := range handler.clients {
		client = c
		break
	}
	handler.mu.Unlock()
	if client == nil {
		t.Fatal("expected SSE client to register")
	}

	client.ch <- []byte(`{"ok":true}`)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE handler to exit after write failure")
	}
}

func TestHandleRequestJSONWithAuditContext_ParseErrorStillMarshals(t *testing.T) {
	srv := NewServer(nil, nil)
	respData, err := srv.HandleRequestJSONWithAuditContext([]byte("not-json"), &AuditContext{Transport: "sse"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var resp JSONRPCResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != ErrCodeParseError {
		t.Fatalf("expected parse error response, got %+v", resp)
	}
}

func TestHandleMessage_BroadcastUnmarshalFailureStillAccepted(t *testing.T) {
	handler, _ := helperSSEServer("test-api-key")
	client := &sseClient{done: make(chan struct{}), ch: make(chan []byte, 1)}
	handler.mu.Lock()
	handler.clients[client] = true
	handler.mu.Unlock()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guardianwaf_get_stats","arguments":{}}}`
	req := helperAuthReq(http.MethodPost, "/mcp/message", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.handleMessage(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}
