package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
)

type targetLateCleanupContext struct {
	context.Context
	entered, release  chan struct{}
	once, releaseOnce sync.Once
}

func (c *targetLateCleanupContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Context.Err()
}
func (c *targetLateCleanupContext) open() { c.releaseOnce.Do(func() { close(c.release) }) }
func targetLateCleanupGate(ctx context.Context) *targetLateCleanupContext {
	return &targetLateCleanupContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
}

type targetLateCleanupConn struct {
	net.Conn
	closed     atomic.Bool
	closedDone chan struct{}
	once       sync.Once
}

func (c *targetLateCleanupConn) Close() error {
	err := c.Conn.Close()
	c.closed.Store(true)
	c.once.Do(func() { close(c.closedDone) })
	return err
}

type targetLateCleanupExchange struct {
	conn     *targetLateCleanupConn
	path     string
	release  chan struct{}
	once     sync.Once
	response string
}

func (e *targetLateCleanupExchange) respond(code int, body string) {
	e.once.Do(func() {
		e.response = fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", code, http.StatusText(code), len(body), body)
		close(e.release)
	})
}

type targetLateCleanupPeer struct {
	mu        sync.Mutex
	conns     []*targetLateCleanupConn
	servers   []net.Conn
	done      []chan struct{}
	exchanges []*targetLateCleanupExchange
	requests  chan *targetLateCleanupExchange
}

func (p *targetLateCleanupPeer) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	conn := &targetLateCleanupConn{Conn: client, closedDone: make(chan struct{})}
	done := make(chan struct{})
	p.mu.Lock()
	p.conns = append(p.conns, conn)
	p.servers = append(p.servers, server)
	p.done = append(p.done, done)
	p.mu.Unlock()
	go func() {
		defer close(done)
		defer server.Close()
		reader := bufio.NewReader(server)
		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			e := &targetLateCleanupExchange{conn: conn, path: req.URL.Path, release: make(chan struct{})}
			p.mu.Lock()
			p.exchanges = append(p.exchanges, e)
			p.mu.Unlock()
			p.requests <- e
			<-e.release
			if _, err := io.WriteString(server, e.response); err != nil {
				return
			}
		}
	}()
	return conn, nil
}
func (p *targetLateCleanupPeer) cleanup() {
	p.mu.Lock()
	conns := append([]*targetLateCleanupConn(nil), p.conns...)
	servers := append([]net.Conn(nil), p.servers...)
	done := append([]chan struct{}(nil), p.done...)
	exchanges := append([]*targetLateCleanupExchange(nil), p.exchanges...)
	p.mu.Unlock()
	for _, e := range exchanges {
		e.respond(200, "ok")
	}
	for _, c := range conns {
		_ = c.Close()
	}
	for _, c := range servers {
		_ = c.Close()
	}
	for _, d := range done {
		<-d
	}
}
func (p *targetLateCleanupPeer) allClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		if !c.closed.Load() {
			return false
		}
	}
	return true
}
func (p *targetLateCleanupPeer) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.conns) }
func targetLateCleanupTarget(t *testing.T) (*Target, *targetLateCleanupPeer) {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	peer := &targetLateCleanupPeer{requests: make(chan *targetLateCleanupExchange, 16)}
	tr := target.proxy.Transport.(*http.Transport)
	tr.IdleConnTimeout = 0 // No timer may hide a missing lifecycle cleanup.
	tr.ResponseHeaderTimeout = 0
	tr.DialContext = peer.dial
	t.Cleanup(func() { target.Close(); peer.cleanup() })
	return target, peer
}

type targetLateCleanupIdle struct {
	err  error
	conn *targetLateCleanupConn
}
type targetLateCleanupResult struct {
	idle       chan targetLateCleanupIdle
	err        error
	panicValue any
	rec        *httptest.ResponseRecorder
}
type targetLateCleanupPanicWriter struct {
	*httptest.ResponseRecorder
	value any
}

func (w *targetLateCleanupPanicWriter) Write([]byte) (int, error) { panic(w.value) }
func targetLateCleanupStart(target *Target, ctx context.Context, path, prefix string, panicValue any) <-chan targetLateCleanupResult {
	done := make(chan targetLateCleanupResult, 1)
	go func() {
		result := targetLateCleanupResult{rec: httptest.NewRecorder(), idle: make(chan targetLateCleanupIdle, 4)}
		var assigned atomic.Pointer[targetLateCleanupConn]
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if conn, ok := info.Conn.(*targetLateCleanupConn); ok {
					assigned.Store(conn)
				}
			},
			PutIdleConn: func(err error) { result.idle <- targetLateCleanupIdle{err: err, conn: assigned.Load()} },
		})
		defer func() { result.panicValue = recover(); done <- result }()
		var w http.ResponseWriter = result.rec
		if panicValue != nil {
			w = &targetLateCleanupPanicWriter{ResponseRecorder: result.rec, value: panicValue}
		}
		result.err = target.ServeHTTP(w, httptest.NewRequest("GET", path, nil).WithContext(ctx), prefix)
	}()
	return done
}

// Failed idle admission is closed by the transport read loop after EOF wakes
// the handler. Await that owned cleanup; a successfully pooled orphan must
// already have been closed by Target's completion cleanup.
func targetLateCleanupAwaitReadLoop(r targetLateCleanupResult) {
	select {
	case event := <-r.idle:
		if event.err != nil && event.conn != nil {
			<-event.conn.closedDone
		}
	default:
	}
}
func targetLateCleanupCheck(t *testing.T, target *Target, peer *targetLateCleanupPeer, r targetLateCleanupResult, code int) {
	t.Helper()
	targetLateCleanupAwaitReadLoop(r)
	if r.err != nil || r.panicValue != nil || r.rec.Code != code || target.ActiveConns() != 0 || !target.Closed() || !peer.allClosed() {
		t.Errorf("completed retired target: err=%v panic=%v status=%d active=%d closed=%v allConnectionsClosed=%v", r.err, r.panicValue, r.rec.Code, target.ActiveConns(), target.Closed(), peer.allClosed())
	}
}
func TestTargetReleasesLateTransportConnectionsAfterClose(t *testing.T) {
	t.Run("live_reuse_then_close", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		for range 2 {
			done := targetLateCleanupStart(target, context.Background(), "/api/control", "/api", nil)
			e := <-peer.requests
			e.respond(200, "ok")
			r := <-done
			if r.err != nil || r.panicValue != nil || r.rec.Code != 200 || r.rec.Body.String() != "ok" || target.ActiveConns() != 0 || target.Closed() || e.conn.closed.Load() || e.path != "/control" {
				t.Error("live keep-alive control failed")
			}
		}
		if peer.count() != 1 {
			t.Errorf("control did not reuse connection: %d", peer.count())
		}
		target.Close()
		target.Close()
		if !peer.allClosed() {
			t.Error("idle control not closed")
		}
	})
	t.Run("close_before_entry", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		target.Close()
		r := <-targetLateCleanupStart(target, context.Background(), "/", "", nil)
		targetLateCleanupCheck(t, target, peer, r, 503)
		if peer.count() != 0 {
			t.Error("closed target reached transport")
		}
	})
	for _, phase := range []string{"before_transport", "after_transport"} {
		for _, outcome := range []string{"success", "server_error", "writer_panic"} {
			t.Run(phase+"/"+outcome, func(t *testing.T) {
				target, peer := targetLateCleanupTarget(t)
				gate := targetLateCleanupGate(context.Background())
				t.Cleanup(gate.open)
				ctx := context.Background()
				if phase == "before_transport" {
					ctx = gate
				}
				marker := errors.New("injected writer panic")
				var panicValue any
				if outcome == "writer_panic" {
					panicValue = marker
				}
				done := targetLateCleanupStart(target, ctx, "/api/data", "/api", panicValue)
				if phase == "before_transport" {
					<-gate.entered
					target.Close()
					gate.open()
				}
				e := <-peer.requests
				if phase == "after_transport" {
					target.Close()
				}
				code := 200
				if outcome == "server_error" {
					code = 503
				}
				e.respond(code, "ok")
				r := <-done
				targetLateCleanupAwaitReadLoop(r)
				if outcome == "writer_panic" {
					panicErr, _ := r.panicValue.(error)
					if !errors.Is(panicErr, marker) || target.ActiveConns() != 0 || !peer.allClosed() {
						t.Errorf("panic cleanup: panic=%v active=%d allClosed=%v", r.panicValue, target.ActiveConns(), peer.allClosed())
					}
				} else {
					targetLateCleanupCheck(t, target, peer, r, code)
					if r.rec.Body.String() != "ok" {
						t.Error("in-flight response changed")
					}
				}
				if e.path != "/data" {
					t.Errorf("prefix path changed: %s", e.path)
				}
				wantFailures := 0
				if outcome == "server_error" {
					wantFailures = 1
				}
				if target.circuit.Failures() != wantFailures {
					t.Errorf("circuit failures=%d want=%d", target.circuit.Failures(), wantFailures)
				}
			})
		}
	}
	t.Run("repeated_close_before_late_start", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		gate := targetLateCleanupGate(context.Background())
		t.Cleanup(gate.open)
		done := targetLateCleanupStart(target, gate, "/", "", nil)
		<-gate.entered
		for range 4 {
			target.Close()
		}
		gate.open()
		e := <-peer.requests
		e.respond(200, "")
		r := <-done
		targetLateCleanupCheck(t, target, peer, r, 200)
	})
	t.Run("cancel_in_flight_after_close", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		gate := targetLateCleanupGate(ctx)
		t.Cleanup(gate.open)
		done := targetLateCleanupStart(target, gate, "/", "", nil)
		<-gate.entered
		target.Close()
		gate.open()
		e := <-peer.requests
		cancel()
		r := <-done
		<-e.conn.closedDone
		e.respond(200, "ok")
		if !errors.Is(r.err, context.Canceled) || r.panicValue != nil || target.ActiveConns() != 0 || !peer.allClosed() || target.circuit.Failures() != 0 {
			t.Errorf("canceled cleanup: err=%v active=%d allClosed=%v failures=%d", r.err, target.ActiveConns(), peer.allClosed(), target.circuit.Failures())
		}
	})
	t.Run("two_already_entered_requests_finish_in_sequence", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		first, second := targetLateCleanupGate(context.Background()), targetLateCleanupGate(context.Background())
		t.Cleanup(first.open)
		t.Cleanup(second.open)
		doneFirst, doneSecond := targetLateCleanupStart(target, first, "/first", "", nil), targetLateCleanupStart(target, second, "/second", "", nil)
		<-first.entered
		<-second.entered
		target.Close()
		first.open()
		e := <-peer.requests
		e.respond(200, "ok")
		r := <-doneFirst
		targetLateCleanupCheck(t, target, peer, r, 200)
		second.open()
		e = <-peer.requests
		e.respond(200, "ok")
		r = <-doneSecond
		targetLateCleanupCheck(t, target, peer, r, 200)
		if peer.count() != 2 {
			t.Errorf("expected two separately created retired connections, got %d", peer.count())
		}
	})
	t.Run("cleanup_preserves_other_active_request", func(t *testing.T) {
		target, peer := targetLateCleanupTarget(t)
		first, second := targetLateCleanupGate(context.Background()), targetLateCleanupGate(context.Background())
		t.Cleanup(first.open)
		t.Cleanup(second.open)
		doneFirst, doneSecond := targetLateCleanupStart(target, first, "/first", "", nil), targetLateCleanupStart(target, second, "/second", "", nil)
		<-first.entered
		<-second.entered
		target.Close()
		first.open()
		second.open()
		one, two := <-peer.requests, <-peer.requests
		var firstExchange, secondExchange *targetLateCleanupExchange
		if one.path == "/first" {
			firstExchange, secondExchange = one, two
		} else {
			firstExchange, secondExchange = two, one
		}
		firstExchange.respond(200, "ok")
		r := <-doneFirst
		targetLateCleanupAwaitReadLoop(r)
		if r.err != nil || r.rec.Code != 200 || !firstExchange.conn.closed.Load() || secondExchange.conn.closed.Load() || target.ActiveConns() != 1 {
			t.Errorf("active sibling disturbed: err=%v firstClosed=%v secondClosed=%v active=%d", r.err, firstExchange.conn.closed.Load(), secondExchange.conn.closed.Load(), target.ActiveConns())
		}
		secondExchange.respond(200, "ok")
		r = <-doneSecond
		targetLateCleanupCheck(t, target, peer, r, 200)
	})
}
