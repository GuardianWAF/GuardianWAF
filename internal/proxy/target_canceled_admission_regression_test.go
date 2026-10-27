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

type targetCanceledAdmissionTransport func(*http.Request) (*http.Response, error)

func (f targetCanceledAdmissionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type targetCanceledAdmissionBody struct {
	io.Reader
	reads, closes    atomic.Int32
	entered, release chan struct{}
	once             sync.Once
}

func (b *targetCanceledAdmissionBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.entered != nil {
		b.once.Do(func() { close(b.entered); <-b.release })
	}
	return b.Reader.Read(p)
}
func (b *targetCanceledAdmissionBody) Close() error { b.closes.Add(1); return nil }
func targetCanceledAdmissionTarget(t *testing.T, calls *atomic.Int32) *Target {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	target.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 2})
	target.proxy.Transport = targetCanceledAdmissionTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	return target
}
func TestTargetRejectsCanceledAdmission(t *testing.T) {
	for _, phase := range []string{"closed", "prior_failure", "open", "expired_open", "busy_probe"} {
		for _, deadline := range []bool{false, true} {
			name := phase + "/cancel"
			if deadline {
				name = phase + "/deadline"
			}
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				target := targetCanceledAdmissionTarget(t, &calls)
				if phase != "closed" {
					target.circuit.RecordFailure()
				}
				if phase == "open" || phase == "expired_open" || phase == "busy_probe" {
					target.circuit.RecordFailure()
				}
				if phase == "expired_open" || phase == "busy_probe" {
					target.circuit.lastFailure.Store(time.Time{})
				}
				if phase == "busy_probe" {
					if !target.circuit.Allow() {
						t.Fatal("cannot reserve control probe")
					}
				}
				state, failures, generation := target.CircuitState(), target.circuit.Failures(), target.circuit.generation
				last := target.circuit.lastFailure.Load().(time.Time)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				wantErr := context.Canceled
				if deadline {
					ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
					defer cancel()
					wantErr = context.DeadlineExceeded
				}
				body := &targetCanceledAdmissionBody{Reader: strings.NewReader("payload")}
				req := httptest.NewRequest("POST", "/api/data", nil).WithContext(ctx)
				req.Body = body
				req.ContentLength = -1
				rec := httptest.NewRecorder()
				err := target.ServeHTTP(rec, req, "/api")
				if !errors.Is(err, wantErr) || calls.Load() != 0 || body.reads.Load() != 0 || body.closes.Load() != 0 || target.ActiveConns() != 0 {
					t.Errorf("error=%v calls=%d reads=%d closes=%d active=%d", err, calls.Load(), body.reads.Load(), body.closes.Load(), target.ActiveConns())
				}
				if target.CircuitState() != state || target.circuit.Failures() != failures || target.circuit.generation != generation || !target.circuit.lastFailure.Load().(time.Time).Equal(last) {
					t.Error("canceled admission changed circuit")
				}
				if rec.Body.Len() != 0 || len(rec.Header()) != 0 {
					t.Errorf("admission committed response: %q headers=%v", rec.Body.String(), rec.Header())
				}
			})
		}
	}
	t.Run("live_expired_probe_control", func(t *testing.T) {
		var calls atomic.Int32
		target := targetCanceledAdmissionTarget(t, &calls)
		target.circuit.RecordFailure()
		target.circuit.RecordFailure()
		target.circuit.lastFailure.Store(time.Time{})
		rec := httptest.NewRecorder()
		err := target.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil), "")
		if err != nil || calls.Load() != 1 || rec.Code != 200 || rec.Body.String() != "ok" || target.CircuitState() != CircuitClosed || target.circuit.Failures() != 0 || target.ActiveConns() != 0 {
			t.Errorf("live probe: error=%v calls=%d state=%s status=%d", err, calls.Load(), target.CircuitState(), rec.Code)
		}
	})
	t.Run("closed_target_precedence", func(t *testing.T) {
		var calls atomic.Int32
		target := targetCanceledAdmissionTarget(t, &calls)
		target.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rec := httptest.NewRecorder()
		err := target.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil).WithContext(ctx), "")
		if err != nil || rec.Code != 503 || calls.Load() != 0 {
			t.Errorf("closed target: err=%v status=%d calls=%d", err, rec.Code, calls.Load())
		}
	})
	t.Run("cancel_after_selection_before_admission", func(t *testing.T) {
		var calls atomic.Int32
		first, sibling := targetCanceledAdmissionTarget(t, &calls), targetCanceledAdmissionTarget(t, &calls)
		first.circuit.RecordFailure()
		first.circuit.RecordFailure()
		first.circuit.lastFailure.Store(time.Time{})
		generation := first.circuit.generation
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		body := &targetCanceledAdmissionBody{Reader: strings.NewReader("payload"), entered: make(chan struct{}), release: make(chan struct{})}
		req := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
		req.Body = body
		req.ContentLength = 7
		router := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{first, sibling}, StrategyRoundRobin)}})
		rec, done := httptest.NewRecorder(), make(chan struct{})
		go func() { router.ServeHTTP(rec, req); close(done) }()
		<-body.entered
		cancel()
		close(body.release)
		<-done
		if rec.Code != 502 || calls.Load() != 0 || first.circuit.Failures() != 2 || first.CircuitState() != CircuitOpen || first.circuit.generation != generation || first.ActiveConns() != 0 || sibling.ActiveConns() != 0 || body.closes.Load() != 1 {
			t.Errorf("buffered canceled admission: status=%d calls=%d state=%s failures=%d gen=%d bodyCloses=%d", rec.Code, calls.Load(), first.CircuitState(), first.circuit.Failures(), first.circuit.generation, body.closes.Load())
		}
	})
}
