package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type hijackChainWriter struct {
	http.ResponseWriter
	conn  net.Conn
	rw    *bufio.ReadWriter
	calls int
	err   error
}

func (w *hijackChainWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.calls++
	return w.conn, w.rw, w.err
}

func (w *hijackChainWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type hijackChainWrapper struct{ http.ResponseWriter }

func (w *hijackChainWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func wrapHijackChain(w http.ResponseWriter, depth int) http.ResponseWriter {
	for range depth {
		w = &hijackChainWrapper{ResponseWriter: w}
	}
	return w
}

type hijackChainAddr string

func (a hijackChainAddr) Network() string { return "memory" }
func (a hijackChainAddr) String() string  { return string(a) }

type hijackChainConn struct {
	mu                  sync.Mutex
	written             bytes.Buffer
	readDone, closeDone chan struct{}
	readOnce, closeOnce sync.Once
}

func (c *hijackChainConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readDone) })
	return 0, io.EOF
}
func (c *hijackChainConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(p)
}
func (c *hijackChainConn) Close() error                   { c.closeOnce.Do(func() { close(c.closeDone) }); return nil }
func (*hijackChainConn) LocalAddr() net.Addr              { return hijackChainAddr("local") }
func (*hijackChainConn) RemoteAddr() net.Addr             { return hijackChainAddr("remote") }
func (*hijackChainConn) SetDeadline(time.Time) error      { return nil }
func (*hijackChainConn) SetReadDeadline(time.Time) error  { return nil }
func (*hijackChainConn) SetWriteDeadline(time.Time) error { return nil }

type hijackChainDuplexBody struct {
	readDone, closeDone chan struct{}
	readOnce, closeOnce sync.Once
}

func (b *hijackChainDuplexBody) Read([]byte) (int, error) {
	b.readOnce.Do(func() { close(b.readDone) })
	return 0, io.EOF
}
func (*hijackChainDuplexBody) Write(p []byte) (int, error) { return len(p), nil }
func (b *hijackChainDuplexBody) Close() error {
	b.closeOnce.Do(func() { close(b.closeDone) })
	return nil
}

type hijackChainTransport func(*http.Request) (*http.Response, error)

func (f hijackChainTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Regression: proxy response wrapping must preserve supported controller
// operations through middleware and keep outer overrides authoritative.
func TestProxyErrorPreservesWrappedHijack(t *testing.T) {
	newWriter := func(t *testing.T) *hijackChainWriter {
		t.Helper()
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		return &hijackChainWriter{ResponseWriter: httptest.NewRecorder(), conn: server, rw: bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))}
	}
	for _, depth := range []int{0, 1, 3} {
		t.Run(fmt.Sprintf("depth_%d", depth), func(t *testing.T) {
			base := newWriter(t)
			pe := &proxyError{ResponseWriter: wrapHijackChain(base, depth)}
			for call := 1; call <= 3; call++ {
				conn, rw, err := http.NewResponseController(pe).Hijack()
				if err != nil || conn != base.conn || rw != base.rw || base.calls != call {
					t.Fatalf("EXPECTED: handles unchanged error=nil calls=%d | ACTUAL: conn_match=%v rw_match=%v error=%v calls=%d", call, conn == base.conn, rw == base.rw, err, base.calls)
				}
			}
		})
	}
	t.Run("underlying_error", func(t *testing.T) {
		base := newWriter(t)
		base.err = errors.New("injected hijack error")
		conn, rw, err := (&proxyError{ResponseWriter: wrapHijackChain(base, 2)}).Hijack()
		if !errors.Is(err, base.err) || conn != base.conn || rw != base.rw || base.calls != 1 {
			t.Fatal("underlying error or handles were replaced")
		}
	})
	t.Run("outer_override", func(t *testing.T) {
		inner, outer := newWriter(t), newWriter(t)
		outer.ResponseWriter = wrapHijackChain(inner, 2)
		outer.err = errors.New("outer wrapper refuses hijack")
		conn, rw, err := (&proxyError{ResponseWriter: outer}).Hijack()
		if !errors.Is(err, outer.err) || conn != outer.conn || rw != outer.rw || outer.calls != 1 || inner.calls != 0 {
			t.Fatal("outer hijack implementation was bypassed")
		}
	})
	for _, depth := range []int{0, 2} {
		t.Run(fmt.Sprintf("unsupported_%d", depth), func(t *testing.T) {
			conn, rw, err := http.NewResponseController(&proxyError{ResponseWriter: wrapHijackChain(httptest.NewRecorder(), depth)}).Hijack()
			if !errors.Is(err, http.ErrNotSupported) || conn != nil || rw != nil {
				t.Fatalf("unsupported result: conn=%v rw=%v error=%v", conn, rw, err)
			}
		})
	}
	t.Run("target_protocol_upgrade", func(t *testing.T) {
		client := &hijackChainConn{readDone: make(chan struct{}), closeDone: make(chan struct{})}
		backend := &hijackChainDuplexBody{readDone: make(chan struct{}), closeDone: make(chan struct{})}
		t.Cleanup(func() { _ = client.Close(); _ = backend.Close() })
		base := &hijackChainWriter{ResponseWriter: httptest.NewRecorder(), conn: client, rw: bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))}
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		target.proxy.Transport = hijackChainTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 101, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, Body: backend, Request: r}, nil
		})
		r := httptest.NewRequest("GET", "/stream", nil)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		if err := target.ServeHTTP(wrapHijackChain(base, 3), r, ""); err != nil {
			t.Fatal(err)
		}
		// Wait for both copy directions and the asynchronous backend cleanup.
		<-client.readDone
		<-backend.readDone
		<-client.closeDone
		<-backend.closeDone
		client.mu.Lock()
		handshake := client.written.String()
		client.mu.Unlock()
		if base.calls != 1 || !strings.HasPrefix(handshake, "HTTP/1.1 101 Switching Protocols\r\n") || !strings.Contains(handshake, "Upgrade: websocket\r\n") || target.ActiveConns() != 0 {
			t.Fatalf("EXPECTED: upgrade=101 hijack_calls=1 active_conns=0 | ACTUAL: handshake=%q hijack_calls=%d active_conns=%d", handshake, base.calls, target.ActiveConns())
		}
	})
}
