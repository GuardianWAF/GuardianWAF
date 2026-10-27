package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type circuitGenerationTransport func(*http.Request) (*http.Response, error)

func (f circuitGenerationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type circuitGenerationResult struct {
	status int
	err    error
}
type circuitGenerationGate struct {
	started, release chan struct{}
	done             chan circuitGenerationResult
	once             sync.Once
}

func newCircuitGenerationGate(t *testing.T) *circuitGenerationGate {
	t.Helper()
	g := &circuitGenerationGate{started: make(chan struct{}), release: make(chan struct{}), done: make(chan circuitGenerationResult, 1)}
	t.Cleanup(g.open)
	return g
}
func (g *circuitGenerationGate) open() { g.once.Do(func() { close(g.release) }) }
func (g *circuitGenerationGate) start(target *Target, path string) {
	go func() {
		rec := httptest.NewRecorder()
		err := target.ServeHTTP(rec, httptest.NewRequest("GET", path, nil), "")
		g.done <- circuitGenerationResult{rec.Code, err}
	}()
	<-g.started
}

func newCircuitGenerationTarget(t *testing.T) *Target {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	target.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 1})
	// Force elapsed admission regardless of the clock, without sleeping.
	target.circuit.resetTimeout = time.Duration(-1 << 63)
	return target
}

func circuitGenerationResponse(r *http.Request, status int) (*http.Response, error) {
	if status == -1 {
		return nil, errors.New("injected transport failure")
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
}

func circuitGenerationFinish(t *testing.T, g *circuitGenerationGate, status int) {
	t.Helper()
	g.open()
	result := <-g.done
	if (result.err != nil) != (status == -1) {
		t.Fatalf("status %d returned unexpected error: %v", status, result.err)
	}
}

func circuitGenerationFail(t *testing.T, target *Target) {
	t.Helper()
	if err := target.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/failure", nil), ""); err != nil {
		t.Fatal(err)
	}
	if target.CircuitState() != CircuitOpen {
		t.Fatal("fresh failure did not open the circuit")
	}
}

func TestTargetCircuitGenerationDiscardsStaleResults(t *testing.T) {
	for _, oldStatus := range []int{200, 500, -1} {
		for _, probeStatus := range []int{200, 500} {
			t.Run(fmt.Sprintf("stale-%d-probe-%d", oldStatus, probeStatus), func(t *testing.T) {
				target := newCircuitGenerationTarget(t)
				old, probe := newCircuitGenerationGate(t), newCircuitGenerationGate(t)
				target.proxy.Transport = circuitGenerationTransport(func(r *http.Request) (*http.Response, error) {
					switch r.URL.Path {
					case "/old":
						close(old.started)
						<-old.release
						return circuitGenerationResponse(r, oldStatus)
					case "/probe":
						close(probe.started)
						<-probe.release
						return circuitGenerationResponse(r, probeStatus)
					default:
						return circuitGenerationResponse(r, 500)
					}
				})
				old.start(target, "/old")
				circuitGenerationFail(t, target)
				probe.start(target, "/probe")
				lastFailure := target.circuit.lastFailure.Load().(time.Time)
				circuitGenerationFinish(t, old, oldStatus)
				state, failures := target.CircuitState(), target.circuit.Failures()
				allowed := target.circuit.Allow()
				if state != CircuitHalfOpen || failures != 0 || allowed || target.circuit.lastFailure.Load().(time.Time) != lastFailure {
					t.Fatalf("EXPECTED: half-open failures=0 allowed=false unchanged_failure_time | ACTUAL: state=%s failures=%d allowed=%v", state, failures, allowed)
				}
				circuitGenerationFinish(t, probe, probeStatus)
				want := CircuitClosed
				if probeStatus == 500 {
					want = CircuitOpen
				}
				if got := target.CircuitState(); got != want {
					t.Fatalf("current probe state = %s, want %s", got, want)
				}
				if target.ActiveConns() != 0 {
					t.Fatal("active connection count did not return to zero")
				}
			})
		}
	}
	for _, status := range []int{200, 500, -1} {
		for _, wasProbe := range []bool{false, true} {
			t.Run(fmt.Sprintf("reset-status-%d-probe-%v", status, wasProbe), func(t *testing.T) {
				target := newCircuitGenerationTarget(t)
				pending := newCircuitGenerationGate(t)
				target.proxy.Transport = circuitGenerationTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/pending" {
						close(pending.started)
						<-pending.release
						return circuitGenerationResponse(r, status)
					}
					return circuitGenerationResponse(r, 500)
				})
				if wasProbe {
					circuitGenerationFail(t, target)
				}
				pending.start(target, "/pending")
				target.circuit.Reset()
				circuitGenerationFinish(t, pending, status)
				if got := target.CircuitState(); got != CircuitClosed || target.circuit.Failures() != 0 {
					t.Fatalf("EXPECTED: reset remains closed failures=0 | ACTUAL: state=%s failures=%d", got, target.circuit.Failures())
				}
				circuitGenerationFail(t, target) // control: new-generation failures still apply
			})
		}
	}
	t.Run("concurrent-single-probe", func(t *testing.T) {
		target := newCircuitGenerationTarget(t)
		target.circuit.RecordFailure()
		barrier := make(chan struct{})
		var admitted atomic.Int32
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-barrier
				if target.circuit.Allow() {
					admitted.Add(1)
				}
			}()
		}
		close(barrier)
		wg.Wait()
		if admitted.Load() != 1 || target.CircuitState() != CircuitHalfOpen {
			t.Fatalf("EXPECTED: one probe half-open | ACTUAL: admitted=%d state=%s", admitted.Load(), target.CircuitState())
		}
		target.circuit.RecordSuccess()
		if target.CircuitState() != CircuitClosed || !target.circuit.Allow() {
			t.Fatal("successful current probe did not restore admission")
		}
	})
}
