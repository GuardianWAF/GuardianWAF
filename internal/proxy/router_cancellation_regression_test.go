package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type routerCancellationTransport func(*http.Request) (*http.Response, error)

func (f routerCancellationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRouterStopsRetriesAfterCancellation(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyWeighted, StrategyLeastConn, StrategyIPHash} {
		for _, payload := range []string{"", "payload"} {
			for _, scenario := range []string{"control", "cancel_first", "cancel_retry"} {
				bodyName := "empty"
				if payload != "" {
					bodyName = "body"
				}
				t.Run(strategy+"/"+bodyName+"/"+scenario, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
					var attempts atomic.Int32
					var calls [3]atomic.Int32
					var targets []*Target
					gateAt := int32(1)
					if scenario == "cancel_retry" {
						gateAt = 2
					}
					for i := range 3 {
						target, err := NewTargetWithPolicy("http://192.0.2.1", 1, TargetPolicy{AllowPrivateTargets: true})
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(target.Close)
						targets = append(targets, target)
						target.proxy.Transport = routerCancellationTransport(func(r *http.Request) (*http.Response, error) {
							calls[i].Add(1)
							attempt := attempts.Add(1)
							var body []byte
							if r.Body != nil {
								var err error
								body, err = io.ReadAll(r.Body)
								if err != nil {
									return nil, err
								}
							}
							if string(body) != payload {
								t.Errorf("attempt %d body=%q want=%q", attempt, body, payload)
							}
							if attempt == gateAt {
								close(started)
								<-release
							}
							if r.Context().Err() != nil {
								return nil, r.Context().Err()
							}
							if attempt < 3 {
								return nil, errors.New("backend failure")
							}
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
						})
					}
					router := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer(targets, strategy)}})
					req := httptest.NewRequest("GET", "/", nil)
					if payload != "" {
						req = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(payload))
					}
					req = req.WithContext(ctx)
					rec := httptest.NewRecorder()
					go func() { router.ServeHTTP(rec, req); close(done) }()
					<-started
					if scenario != "control" {
						cancel()
					}
					close(release)
					<-done
					wantAttempts, wantCode, wantFailures := int32(3), 200, 2
					if scenario != "control" {
						wantAttempts, wantCode, wantFailures = gateAt, 502, int(gateAt)-1
					}
					if attempts.Load() != wantAttempts || rec.Code != wantCode {
						t.Errorf("attempts=%d want=%d status=%d want=%d", attempts.Load(), wantAttempts, rec.Code, wantCode)
					}
					failures := 0
					for i, target := range targets {
						failures += target.circuit.Failures()
						if calls[i].Load() > 1 || target.ActiveConns() != 0 {
							t.Errorf("target %d calls=%d active=%d", i, calls[i].Load(), target.ActiveConns())
						}
					}
					if failures != wantFailures {
						t.Errorf("total failures=%d want=%d", failures, wantFailures)
					}
					if scenario == "control" && rec.Body.String() != "ok" {
						t.Errorf("control response=%q", rec.Body.String())
					}
				})
			}
		}
	}
}
