package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type busyProbeSelectionTransport func(*http.Request) (*http.Response, error)

func (f busyProbeSelectionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Regression: availability filtering must keep requests on an eligible sibling.
func TestRouterSkipsBusyHalfOpenTarget(t *testing.T) {
	newTarget := func() *Target {
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		return target
	}
	busy, healthy := newTarget(), newTarget()
	busy.Weight = 100
	busy.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 1})
	busy.circuit.RecordFailure()
	// Make every possible elapsed duration eligible without waiting for a clock.
	busy.circuit.resetTimeout = time.Duration(-1 << 63)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var busyCalls, healthyCalls atomic.Int32
	var probeErr error
	busy.proxy.Transport = busyProbeSelectionTransport(func(r *http.Request) (*http.Response, error) {
		if busyCalls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("probe")), Request: r}, nil
	})
	healthy.proxy.Transport = busyProbeSelectionTransport(func(r *http.Request) (*http.Response, error) {
		healthyCalls.Add(1)
		var body []byte
		var err error
		if r.Body != nil {
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("healthy:" + string(body))), Request: r}, nil
	})
	go func() {
		probeErr = busy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil), "")
		close(done)
	}()
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); <-done })
	<-entered
	request := httptest.NewRequest("GET", "/data", nil)
	busy.SetHealthy(false)
	if got := NewBalancer([]*Target{busy, healthy}, StrategyRoundRobin).Next(request); got != healthy {
		t.Fatal("unaffected control failed")
	}
	busy.SetHealthy(true)
	get := httptest.NewRecorder()
	NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{busy, healthy}, StrategyRoundRobin)}}).ServeHTTP(get, request)
	if get.Code != 200 || get.Body.String() != "healthy:" {
		t.Fatalf("EXPECTED: busy-probe GET status=200 | ACTUAL: status=%d", get.Code)
	}
	for _, strategy := range []string{StrategyRoundRobin, StrategyWeighted, StrategyLeastConn, StrategyIPHash} {
		t.Run(strategy, func(t *testing.T) {
			balancer := NewBalancer([]*Target{busy, healthy}, strategy)
			if got := balancer.NextExcluding(request, map[*Target]bool{healthy: true}); got != nil {
				t.Fatal("busy probe remained eligible after sibling exclusion")
			}
			router := NewRouter([]Route{{PathPrefix: "/", Balancer: balancer}})
			for _, unknownLength := range []bool{false, true} {
				r := httptest.NewRequest("POST", "/data", strings.NewReader("payload"))
				if unknownLength {
					r.ContentLength = -1
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, r)
				if rec.Code != 200 || rec.Body.String() != "healthy:payload" {
					t.Fatalf("EXPECTED: 200 healthy:payload | ACTUAL: %d %q", rec.Code, rec.Body.String())
				}
			}
		})
	}
	if busyCalls.Load() != 1 || healthyCalls.Load() != 9 {
		t.Fatalf("EXPECTED: busy_calls=1 healthy_calls=9 | ACTUAL: busy_calls=%d healthy_calls=%d", busyCalls.Load(), healthyCalls.Load())
	}
	rec := httptest.NewRecorder()
	NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{busy}, "")}}).ServeHTTP(rec, request)
	if rec.Code != 503 || busyCalls.Load() != 1 {
		t.Fatal("single busy target must reject without a second probe")
	}
	releaseOnce.Do(func() { close(release) })
	<-done
	if probeErr != nil || busy.circuit.State() != CircuitClosed {
		t.Fatalf("probe did not recover: err=%v state=%v", probeErr, busy.circuit.State())
	}
	if NewBalancer([]*Target{busy}, "").Next(request) != busy {
		t.Fatal("recovered target was not eligible")
	}
	// Selection must inspect, rather than reserve, an armed probe token.
	armed := newTarget()
	armed.circuit.state.Store(int32(CircuitHalfOpen))
	armed.circuit.halfOpenProbe.Store(true)
	balancer := NewBalancer([]*Target{armed}, "")
	first, second := balancer.Next(request), balancer.Next(request)
	if first != armed || second != armed || !armed.circuit.halfOpenProbe.Load() {
		t.Fatal("selection consumed the available probe token")
	}
	if !armed.circuit.Allow() || armed.circuit.Allow() || balancer.Next(request) != nil {
		t.Fatal("armed probe admission was not exclusive")
	}
}
