package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type canceledHealthProbeTransport func(*http.Request) (*http.Response, error)

func (f canceledHealthProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHealthCheckerCanceledProbePreservesState(t *testing.T) {
	newTarget := func() *Target {
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		return target
	}
	for _, tc := range []struct {
		name             string
		initial, success bool
	}{
		{"canceled-error-preserves-healthy", true, false},
		{"late-success-preserves-unhealthy", false, true},
		{"late-success-preserves-healthy", true, true},
		{"canceled-error-preserves-unhealthy", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := newTarget(), newTarget()
			first.SetHealthy(tc.initial)
			hc := NewHealthChecker(NewBalancer([]*Target{first, second}, ""), HealthConfig{Interval: time.Hour})
			hc.client.Timeout = 0 // ordering is controlled by channels, not deadlines
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			hc.client.Transport = canceledHealthProbeTransport(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-r.Context().Done()
					close(canceled)
					<-release
				}
				if !tc.success {
					return nil, context.Canceled
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			hc.Start()
			<-entered
			stopped := make(chan error, 1)
			go func() { stopped <- hc.StopWithContext(context.Background()) }()
			<-canceled
			close(release)
			if err := <-stopped; err != nil {
				t.Fatal(err)
			}
			hc.Stop() // repeated stop remains harmless
			if first.IsHealthy() != tc.initial || !second.IsHealthy() || calls.Load() != 1 {
				t.Fatalf("EXPECTED: first=%v second=true calls=1 | ACTUAL: first=%v second=%v calls=%d", tc.initial, first.IsHealthy(), second.IsHealthy(), calls.Load())
			}
			for _, target := range []*Target{first, second} {
				if stamp := target.lastCheck.Load().(time.Time); !stamp.IsZero() {
					t.Fatalf("canceled checker published a timestamp: %v", stamp)
				}
			}
		})
	}
	t.Run("already-canceled", func(t *testing.T) {
		target := newTarget()
		hc := NewHealthChecker(NewBalancer([]*Target{target}, ""), HealthConfig{})
		var calls int
		hc.client.Transport = canceledHealthProbeTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, context.Canceled })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		hc.checkAll(ctx)
		if calls != 0 || !target.IsHealthy() {
			t.Fatalf("EXPECTED: calls=0 healthy=true | ACTUAL: calls=%d healthy=%v", calls, target.IsHealthy())
		}
	})
	for _, status := range []int{200, 500} {
		t.Run(fmt.Sprintf("live-status-%d", status), func(t *testing.T) {
			target := newTarget()
			hc := NewHealthChecker(NewBalancer([]*Target{target}, ""), HealthConfig{})
			hc.client.Transport = canceledHealthProbeTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			hc.checkAll(context.Background())
			if target.IsHealthy() != (status == 200) {
				t.Fatalf("live status %d did not update health", status)
			}
		})
	}
}
