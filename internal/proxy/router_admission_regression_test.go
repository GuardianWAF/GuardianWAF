package proxy

import (
	"errors"
	"hash/fnv"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type routerAdmissionTransport func(*http.Request) (*http.Response, error)

func (f routerAdmissionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type routerAdmissionBody struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
	reads, closes    atomic.Int32
}

func (b *routerAdmissionBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}

func (b *routerAdmissionBody) Close() error { b.closes.Add(1); return nil }

func newRouterAdmissionTarget(t *testing.T, transport routerAdmissionTransport) *Target {
	t.Helper()
	target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(target.Close)
	target.proxy.Transport = transport
	return target
}

func routerAdmissionResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

// Regression: state changes after selection must not strand a request while a
// healthy sibling can accept it. Body and probe completion order are gated.
func TestRouterReselectsTargetAfterAdmissionChange(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyWeighted, StrategyLeastConn, StrategyIPHash} {
		for _, change := range []string{"control", "closed", "busy_probe", "all_closed", "transport_failure"} {
			t.Run(strategy+"/"+change, func(t *testing.T) {
				probeEntered, probeRelease, probeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var releaseProbe sync.Once
				var firstCalls, siblingCalls, probeCalls atomic.Int32
				var probeErr error
				first := newRouterAdmissionTarget(t, routerAdmissionTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/probe" {
						probeCalls.Add(1)
						close(probeEntered)
						<-probeRelease
						return routerAdmissionResponse(r, "probe"), nil
					}
					firstCalls.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					return routerAdmissionResponse(r, "first:"+string(body)), nil
				}))
				sibling := newRouterAdmissionTarget(t, routerAdmissionTransport(func(r *http.Request) (*http.Response, error) {
					siblingCalls.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					if change == "transport_failure" {
						return nil, errors.New("injected transport failure")
					}
					return routerAdmissionResponse(r, "sibling:"+string(body)), nil
				}))
				first.Weight = 100
				first.circuit = NewCircuitBreaker(CircuitConfig{Threshold: 1})
				targets := []*Target{first, sibling}
				if strategy == StrategyIPHash {
					h := fnv.New32a()
					_, _ = h.Write([]byte("192.0.2.1"))
					if h.Sum32()%2 != 0 {
						targets = []*Target{sibling, first}
					}
				}
				body := &routerAdmissionBody{Reader: strings.NewReader("payload"), entered: make(chan struct{}), release: make(chan struct{})}
				r := httptest.NewRequest("POST", "/data", nil)
				r.Body, r.ContentLength = body, 7
				rec, done := httptest.NewRecorder(), make(chan struct{})
				balancer := NewBalancer(targets, strategy)
				router := NewRouter([]Route{{PathPrefix: "/", Balancer: balancer}})
				go func() { router.ServeHTTP(rec, r); close(done) }()
				var releaseBody sync.Once
				t.Cleanup(func() { releaseBody.Do(func() { close(body.release) }); <-done })
				<-body.entered // Selection must precede the state change below.
				switch change {
				case "closed", "transport_failure":
					first.Close()
				case "all_closed":
					first.Close()
					sibling.Close()
				case "busy_probe":
					first.circuit.RecordFailure()
					// Expiry is unconditional for every representable elapsed duration.
					first.circuit.resetTimeout = time.Duration(-1 << 63)
					go func() {
						probeErr = first.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil), "")
						close(probeDone)
					}()
					t.Cleanup(func() { releaseProbe.Do(func() { close(probeRelease) }); <-probeDone })
					<-probeEntered
				}
				releaseBody.Do(func() { close(body.release) })
				<-done
				wantCode, wantBody, wantFirst, wantSibling := 200, "sibling:payload", int32(0), int32(1)
				switch change {
				case "control":
					wantBody, wantFirst, wantSibling = "first:payload", 1, 0
				case "all_closed":
					wantCode, wantBody, wantSibling = 503, "503 Service Unavailable - No healthy backends\n", 0
				case "transport_failure":
					wantCode, wantBody = 502, "502 Bad Gateway\n"
				}
				if rec.Code != wantCode || rec.Body.String() != wantBody || firstCalls.Load() != wantFirst || siblingCalls.Load() != wantSibling {
					t.Fatalf("EXPECTED: status=%d body=%q first_calls=%d sibling_calls=%d | ACTUAL: status=%d body=%q first_calls=%d sibling_calls=%d", wantCode, wantBody, wantFirst, wantSibling, rec.Code, rec.Body.String(), firstCalls.Load(), siblingCalls.Load())
				}
				if body.closes.Load() != 1 {
					t.Fatalf("buffered body closes=%d, want 1", body.closes.Load())
				}
				if change == "busy_probe" {
					if first.CircuitState() != CircuitHalfOpen || probeCalls.Load() != 1 {
						t.Fatal("router disrupted the in-flight probe")
					}
					releaseProbe.Do(func() { close(probeRelease) })
					<-probeDone
					if probeErr != nil || first.CircuitState() != CircuitClosed || NewBalancer([]*Target{first}, "").Next(r) != first {
						t.Fatal("probe completion did not restore target eligibility")
					}
				}
			})
		}
	}
}
