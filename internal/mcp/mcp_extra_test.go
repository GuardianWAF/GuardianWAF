package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandleGetTopIPs_InvalidJSON(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	_, err := srv.handleGetTopIPs(json.RawMessage("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestWriteResponse_MarshalError(t *testing.T) {
	var buf bytes.Buffer
	srv := NewServer(nil, &buf)
	srv.writeResponse(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  make(chan int),
	})
	if buf.Len() != 0 {
		t.Error("expected no output when marshal fails")
	}
}

func TestHandleSSE_NonFlusher(t *testing.T) {
	handler, _ := helperSSEServer("")
	rec := httptest.NewRecorder()
	nf := &struct {
		http.ResponseWriter
	}{ResponseWriter: rec}
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	handler.handleSSE(nf, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestHandleSSE_HTTPS(t *testing.T) {
	handler, _ := helperSSEServer("")

	// Use a thread-safe wrapper around ResponseRecorder
	rec := httptest.NewRecorder()
	safeRec := &safeResponseRecorder{rec: rec}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)
	req.TLS = &tls.ConnectionState{}

	done := make(chan struct{})
	go func() {
		handler.handleSSE(safeRec, req)
		close(done)
	}()

	// Wait for SSE data with timeout
	var body string
	for i := 0; i < 200; i++ {
		time.Sleep(10 * time.Millisecond)
		body = safeRec.bodyString()
		if len(body) > 0 {
			break
		}
	}
	if len(body) == 0 {
		t.Fatal("timed out waiting for SSE data")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleSSE to return")
	}

	if safeRec.code() != http.StatusOK {
		t.Fatalf("expected 200, got %d", safeRec.code())
	}
	if !strings.Contains(body, "https://") {
		t.Fatalf("expected https scheme in endpoint, got %s", body)
	}
}

// safeResponseRecorder wraps httptest.ResponseRecorder with mutex for thread safety
type safeResponseRecorder struct {
	rec *httptest.ResponseRecorder
	mu  sync.RWMutex
}

func (s *safeResponseRecorder) Header() http.Header {
	return s.rec.Header()
}

func (s *safeResponseRecorder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec.Write(p)
}

func (s *safeResponseRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec.WriteHeader(code)
}

func (s *safeResponseRecorder) Flush() {
	s.rec.Flush()
}

func (s *safeResponseRecorder) bodyString() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rec.Body.String()
}

func (s *safeResponseRecorder) code() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rec.Code
}

func TestBroadcastResponse_MarshalError(t *testing.T) {
	handler, _ := helperSSEServer("")
	handler.broadcastResponse(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  math.NaN(),
	})
}
