package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type circuitCancellationTransport func(*http.Request) (*http.Response, error)

func (f circuitCancellationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func circuitCancellationTarget(t *testing.T) *Target {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	target.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 2})
	return target
}
func circuitCancellationCancel(t *testing.T, target *Target, expired bool) {
	t.Helper()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	if expired {
		cancel()
		ctx, cancel = context.WithDeadline(context.Background(), time.Time{})
	}
	defer cancel()
	target.proxy.Transport = circuitCancellationTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-release
		return nil, r.Context().Err()
	})
	var err error
	if expired {
		// Already-expired requests return before transport admission.
		close(release)
		err = target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx), "")
	} else {
		go func() {
			done <- target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx), "")
		}()
		<-started
		cancel()
		close(release)
		err = <-done
	}
	wantErr := context.Canceled
	if expired {
		wantErr = context.DeadlineExceeded
	}
	if !errors.Is(err, wantErr) || target.ActiveConns() != 0 {
		t.Fatalf("cancel error=%v active=%d", err, target.ActiveConns())
	}
}
func TestTargetCancellationPreservesCircuit(t *testing.T) {
	for _, depErr := range []error{errors.New("backend failure"), context.Canceled, context.DeadlineExceeded} {
		t.Run("live_context/"+depErr.Error(), func(t *testing.T) {
			target := circuitCancellationTarget(t)
			target.circuit.threshold = 1
			target.proxy.Transport = circuitCancellationTransport(func(*http.Request) (*http.Response, error) { return nil, depErr })
			err := target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), "")
			if !errors.Is(err, depErr) || target.CircuitState() != CircuitOpen || target.circuit.Failures() != 1 || target.ActiveConns() != 0 {
				t.Fatalf("live error=%v state=%s failures=%d active=%d", err, target.CircuitState(), target.circuit.Failures(), target.ActiveConns())
			}
		})
	}
	for _, prior := range []bool{false, true} {
		for _, expired := range []bool{false, true} {
			name := "closed"
			if prior {
				name += "/prior_failure"
			}
			if expired {
				name += "/deadline"
			}
			t.Run(name, func(t *testing.T) {
				target := circuitCancellationTarget(t)
				if prior {
					target.circuit.RecordFailure()
				}
				failures := target.circuit.Failures()
				last := target.circuit.lastFailure.Load().(time.Time)
				for range 4 {
					circuitCancellationCancel(t, target, expired)
				}
				if target.CircuitState() != CircuitClosed || target.circuit.Failures() != failures || !target.circuit.lastFailure.Load().(time.Time).Equal(last) {
					t.Fatalf("cancellation changed closed circuit: state=%s failures=%d", target.CircuitState(), target.circuit.Failures())
				}
			})
		}
	}
	for _, follow := range []string{"success", "server_error", "transport_error"} {
		t.Run("half_open/"+follow, func(t *testing.T) {
			target := circuitCancellationTarget(t)
			target.circuit.RecordFailure()
			target.circuit.RecordFailure()
			target.circuit.lastFailure.Store(time.Time{}) // expiry without sleeping
			circuitCancellationCancel(t, target, false)
			if target.CircuitState() != CircuitOpen || target.circuit.Failures() != 0 || !target.circuit.lastFailure.Load().(time.Time).IsZero() || !target.circuit.canAttempt() {
				t.Fatalf("canceled probe state=%s failures=%d expiry=%v", target.CircuitState(), target.circuit.Failures(), target.circuit.canAttempt())
			}
			target.proxy.Transport = circuitCancellationTransport(func(r *http.Request) (*http.Response, error) {
				if follow == "transport_error" {
					return nil, errors.New("probe failed")
				}
				code := 200
				if follow == "server_error" {
					code = 503
				}
				return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("probe")), Request: r}, nil
			})
			rec := httptest.NewRecorder()
			err := target.ServeHTTP(rec, httptest.NewRequest("GET", "/probe", nil), "")
			wantState, wantFailures := CircuitClosed, 0
			if follow != "success" {
				wantState, wantFailures = CircuitOpen, 2
			}
			if target.CircuitState() != wantState || target.circuit.Failures() != wantFailures || target.ActiveConns() != 0 || (follow == "transport_error") != (err != nil) {
				t.Fatalf("replacement probe: state=%s failures=%d active=%d err=%v", target.CircuitState(), target.circuit.Failures(), target.ActiveConns(), err)
			}
		})
	}
	t.Run("stale_cancel_during_new_probe", func(t *testing.T) {
		target := circuitCancellationTarget(t)
		oldStarted, oldRelease, oldDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		probeStarted, probeRelease, probeDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		target.proxy.Transport = circuitCancellationTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/old" {
				close(oldStarted)
				<-oldRelease
				return nil, r.Context().Err()
			}
			close(probeStarted)
			<-probeRelease
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		})
		go func() {
			oldDone <- target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/old", nil).WithContext(ctx), "")
		}()
		<-oldStarted
		target.circuit.Reset()
		target.circuit.RecordFailure()
		target.circuit.RecordFailure()
		target.circuit.lastFailure.Store(time.Time{})
		go func() {
			probeDone <- target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil), "")
		}()
		<-probeStarted
		cancel()
		close(oldRelease)
		oldErr := <-oldDone
		state, failures, active := target.CircuitState(), target.circuit.Failures(), target.ActiveConns()
		admitted := target.circuit.Allow()
		close(probeRelease)
		probeErr := <-probeDone
		if !errors.Is(oldErr, context.Canceled) || state != CircuitHalfOpen || failures != 0 || active != 1 || admitted {
			t.Fatalf("stale cancel changed probe: err=%v state=%s failures=%d active=%d admitted=%v", oldErr, state, failures, active, admitted)
		}
		if probeErr != nil || target.CircuitState() != CircuitClosed || target.ActiveConns() != 0 {
			t.Fatalf("new probe failed: err=%v state=%s active=%d", probeErr, target.CircuitState(), target.ActiveConns())
		}
	})
}
