package mcp

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type heartbeatResponseWriter struct {
	header http.Header
	writes int
	fail   bool
}

func (w *heartbeatResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *heartbeatResponseWriter) WriteHeader(int) {}

func (w *heartbeatResponseWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.fail && w.writes > 1 {
		return 0, errors.New("heartbeat write failed")
	}
	return len(p), nil
}

func (w *heartbeatResponseWriter) Flush() {}

func TestSSEHeartbeatWritePaths(t *testing.T) {
	for _, fail := range []bool{false, true} {
		handler, _ := helperSSEServer("test-api-key")
		handler.heartbeatInterval = time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		req := helperAuthReq(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)
		writer := &heartbeatResponseWriter{fail: fail}

		handler.handleSSE(writer, req)
		cancel()
		if writer.writes < 2 {
			t.Fatalf("fail=%v: endpoint and heartbeat writes = %d, want at least 2", fail, writer.writes)
		}
	}
}
