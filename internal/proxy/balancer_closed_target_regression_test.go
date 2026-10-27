package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type closedTargetSelectionTransport func(*http.Request) (*http.Response, error)

func (f closedTargetSelectionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Regression: availability filtering must keep requests on an eligible sibling.
func TestRouterSkipsClosedTarget(t *testing.T) {
	newTarget := func() *Target {
		target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(target.Close)
		return target
	}
	first, sibling := newTarget(), newTarget()
	first.Weight = 100
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var firstCalls, siblingCalls atomic.Int32
	var oldErr error
	first.proxy.Transport = closedTargetSelectionTransport(func(r *http.Request) (*http.Response, error) {
		firstCalls.Add(1)
		if r.URL.Path == "/probe" {
			close(entered)
			<-release
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("first")), Request: r}, nil
	})
	sibling.proxy.Transport = closedTargetSelectionTransport(func(r *http.Request) (*http.Response, error) {
		siblingCalls.Add(1)
		var body []byte
		var err error
		if r.Body != nil {
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("sibling:" + string(body))), Request: r}, nil
	})
	request := httptest.NewRequest("GET", "/data", nil)
	control := httptest.NewRecorder()
	NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{first, sibling}, "")}}).ServeHTTP(control, request)
	if control.Code != 200 || control.Body.String() != "first" || firstCalls.Load() != 1 {
		t.Fatal("unaffected control failed")
	}
	go func() {
		oldErr = first.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil), "")
		close(done)
	}()
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); <-done })
	<-entered
	first.Close()
	first.Close()
	get := httptest.NewRecorder()
	NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{first, sibling}, StrategyRoundRobin)}}).ServeHTTP(get, request)
	if get.Code != 200 || get.Body.String() != "sibling:" {
		t.Fatalf("EXPECTED: closed-target GET status=200 | ACTUAL: status=%d", get.Code)
	}
	for _, strategy := range []string{StrategyRoundRobin, StrategyWeighted, StrategyLeastConn, StrategyIPHash} {
		t.Run(strategy, func(t *testing.T) {
			balancer := NewBalancer([]*Target{first, sibling}, strategy)
			if balancer.NextExcluding(request, map[*Target]bool{sibling: true}) != nil {
				t.Fatal("closed target remained eligible after sibling exclusion")
			}
			router := NewRouter([]Route{{PathPrefix: "/", Balancer: balancer}})
			for _, unknownLength := range []bool{false, true} {
				r := httptest.NewRequest("POST", "/data", strings.NewReader("payload"))
				if unknownLength {
					r.ContentLength = -1
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, r)
				if rec.Code != 200 || rec.Body.String() != "sibling:payload" {
					t.Fatalf("EXPECTED: 200 sibling:payload | ACTUAL: %d %q", rec.Code, rec.Body.String())
				}
			}
		})
	}
	releaseOnce.Do(func() { close(release) })
	<-done
	if oldErr != nil || !first.Closed() || firstCalls.Load() != 2 || siblingCalls.Load() != 9 {
		t.Fatalf("EXPECTED: closed=true first_calls=2 sibling_calls=9 | ACTUAL: closed=%v first_calls=%d sibling_calls=%d old_err=%v", first.Closed(), firstCalls.Load(), siblingCalls.Load(), oldErr)
	}
	if NewBalancer([]*Target{first, sibling}, "").Next(request) != sibling {
		t.Fatal("late request completion made the closed target eligible")
	}
	sibling.Close()
	for _, targets := range [][]*Target{nil, {first}, {first, sibling}} {
		rec := httptest.NewRecorder()
		NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer(targets, "")}}).ServeHTTP(rec, request)
		if rec.Code != 503 {
			t.Fatalf("EXPECTED: unavailable status=503 | ACTUAL: status=%d", rec.Code)
		}
	}
	if firstCalls.Load() != 2 || siblingCalls.Load() != 9 {
		t.Fatal("closed or empty pool reached a transport")
	}
}
