package mcp

import (
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
)

// Regression (round 13/25): SetAPIKey's rotation contract means the key can
// change at ANY time while clients are being served, but the stdio dispatcher
// read s.apiKey unlocked in handleInitialize, handleToolsCall and
// isAuthenticated — a data race with SetAPIKey's locked write (Go strings are
// two-word headers, so a torn read made the constant-time auth comparison
// evaluate garbage). The reads must snapshot the key under the same lock
// SetAPIKey writes under. This test drives rotation and the request path
// concurrently and is only meaningful with -race enabled (the standard suite
// gate): with the fix reverted it fails with a DATA RACE report.
func TestSetAPIKeyConcurrentWithRequests_NoDataRace(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("initial-key")
	srv.RegisterTool("echo", func(params json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, nil
	})
	conv := startStdioServer(t, srv)

	// Drain responses; the race test does not assert on them. Without this
	// drainer the server eventually blocks writing into the out-pipe while
	// the feeder blocks writing into the in-pipe (classic two-pipe deadlock).
	go func() {
		_, _ = io.Copy(io.Discard, conv.outR)
	}()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	keys := []string{"key-a", "key-b", "key-c", ""}

	// Rotator: SetAPIKey's contract allows changing the credential at any
	// time while clients are served.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				srv.SetAPIKey(keys[i%len(keys)])
			}
		}
	}()

	// Request feeder through the real stdio dispatcher.
	wg.Add(1)
	go func() {
		defer wg.Done()
		lines := []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"api_key":"key-a"}}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
		}
		for {
			for _, line := range lines {
				select {
				case <-stop:
					return
				default:
					if _, err := io.WriteString(conv.inW, line+"\n"); err != nil {
						return
					}
				}
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	// Unblock the server loop; startStdioServer's cleanup drains runErr.
	_ = conv.inW.Close()
}
