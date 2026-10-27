package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type targetCanceledDrainTransport func(*http.Request) (*http.Response, error)

func (f targetCanceledDrainTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type targetCanceledDrainBody struct {
	reader               io.Reader
	block                bool
	entered, closed      chan struct{}
	readOnce, closeOnce  sync.Once
	reads, closes, bytes atomic.Int64
	closeErr             error
}

func (b *targetCanceledDrainBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.block {
		b.readOnce.Do(func() { close(b.entered) })
		<-b.closed
		return 0, io.ErrClosedPipe
	}
	n, err := b.reader.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}
func (b *targetCanceledDrainBody) Close() error {
	b.closes.Add(1)
	b.closeOnce.Do(func() { close(b.closed) })
	return b.closeErr
}

type targetCanceledDrainErrorReader struct{}

func (targetCanceledDrainErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func targetCanceledDrainNewBody(reader io.Reader, block bool) *targetCanceledDrainBody {
	return &targetCanceledDrainBody{reader: reader, block: block, entered: make(chan struct{}), closed: make(chan struct{})}
}
func targetCanceledDrainTarget(t *testing.T) *Target {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	target.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 2})
	return target
}
func TestTargetSkipsCanceledBodyDrain(t *testing.T) {
	for _, kind := range []string{"empty", "finite", "over_limit", "read_error", "dependency_canceled"} {
		t.Run("live/"+kind, func(t *testing.T) {
			target := targetCanceledDrainTarget(t)
			depErr := errors.New("backend failure")
			var reader io.Reader = strings.NewReader("")
			wantBytes := int64(0)
			switch kind {
			case "finite", "dependency_canceled":
				reader = strings.NewReader("payload")
				wantBytes = 7
			case "over_limit":
				reader = strings.NewReader(strings.Repeat("x", (1<<20)+16))
				wantBytes = 1 << 20
			case "read_error":
				reader = targetCanceledDrainErrorReader{}
			}
			if kind == "dependency_canceled" {
				depErr = context.Canceled
			}
			body := targetCanceledDrainNewBody(reader, false)
			target.proxy.Transport = targetCanceledDrainTransport(func(*http.Request) (*http.Response, error) { return nil, depErr })
			req := httptest.NewRequest("POST", "/", nil)
			req.Body = body
			req.ContentLength = -1
			err := target.ServeHTTP(httptest.NewRecorder(), req, "")
			// The HTTP server owns inbound-body closure after handler return.
			_ = req.Body.Close()
			if !errors.Is(err, depErr) || body.bytes.Load() != wantBytes || body.reads.Load() == 0 || body.closes.Load() == 0 || target.circuit.Failures() != 1 || target.ActiveConns() != 0 {
				t.Errorf("live cleanup: err=%v bytes=%d want=%d reads=%d closes=%d failures=%d active=%d", err, body.bytes.Load(), wantBytes, body.reads.Load(), body.closes.Load(), target.circuit.Failures(), target.ActiveConns())
			}
		})
	}
	for _, phase := range []string{"closed", "half_open"} {
		for _, kind := range []string{"nil", "finite", "blocked", "close_error"} {
			for _, prefix := range []string{"", "/api"} {
				t.Run("cancel/"+phase+"/"+kind+prefix, func(t *testing.T) {
					target := targetCanceledDrainTarget(t)
					if phase == "half_open" {
						target.circuit.RecordFailure()
						target.circuit.RecordFailure()
						target.circuit.lastFailure.Store(time.Time{})
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
					target.proxy.Transport = targetCanceledDrainTransport(func(r *http.Request) (*http.Response, error) {
						close(started)
						<-release
						return nil, r.Context().Err()
					})
					body := targetCanceledDrainNewBody(strings.NewReader("payload"), kind == "blocked")
					if kind == "close_error" {
						body.closeErr = io.ErrClosedPipe
					}
					defer body.Close()
					req := httptest.NewRequest("POST", "/api/data", nil).WithContext(ctx)
					req.ContentLength = -1
					if kind == "nil" {
						req.Body = nil
					} else {
						req.Body = body
					}
					go func() {
						err := target.ServeHTTP(httptest.NewRecorder(), req, prefix)
						// Model net/http server cleanup after the handler returns.
						if req.Body != nil {
							_ = req.Body.Close()
						}
						done <- err
					}()
					<-started
					activeBefore := target.ActiveConns()
					cancel()
					close(release)
					var err error
					stalled := false
					select {
					case <-body.entered:
						stalled = true
						body.Close()
						err = <-done
					case err = <-done:
					}
					wantState := CircuitClosed
					if phase == "half_open" {
						wantState = CircuitOpen
					}
					if activeBefore != 1 || stalled || !errors.Is(err, context.Canceled) || body.reads.Load() != 0 || target.ActiveConns() != 0 || target.CircuitState() != wantState || target.circuit.Failures() != 0 {
						t.Errorf("canceled cleanup: before=%d blocked=%v err=%v reads=%d active=%d state=%s failures=%d", activeBefore, stalled, err, body.reads.Load(), target.ActiveConns(), target.CircuitState(), target.circuit.Failures())
					}
					if kind != "nil" {
						select {
						case <-body.closed:
						default:
							t.Error("body not closed")
						}
					}
					if phase == "half_open" && (!target.circuit.canAttempt() || !target.circuit.lastFailure.Load().(time.Time).IsZero()) {
						t.Error("canceled probe cleanup extended cooldown")
					}
				})
			}
		}
	}
}
