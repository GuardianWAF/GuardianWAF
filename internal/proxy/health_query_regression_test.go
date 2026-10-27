package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type regressionF4Transport func(*http.Request) (*http.Response, error)

func (f regressionF4Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHealthCheckQueryParameters(t *testing.T) {
	for _, tc := range []struct {
		name, base, path, want string
		status                 int
		fail                   bool
	}{
		{"query", "/api", "/healthz?ready=1", "/api/healthz?ready=1", 200, false},
		{"plain", "/api", "/healthz", "/api/healthz", 200, false},
		{"target-and-probe-query", "/api?token=a%26b", "/healthz?ready=1&ready=2", "/api/healthz?token=a%26b&ready=1&ready=2", 200, false},
		{"target-query-only", "/api?token=abc", "/healthz", "/api/healthz?token=abc", 200, false},
		{"escaped-delimiter", "/api", "/health%3Fz?ready=1", "/api/health%3Fz?ready=1", 200, false},
		{"escaped-base", "/a%2Fb/", "/healthz?ready=1", "/a%2Fb/healthz?ready=1", 200, false},
		{"empty-default", "", "", "/", 200, false},
		{"relative", "/api", "healthz?ready=1", "/api/healthz?ready=1", 200, false},
		{"unhealthy", "/api", "/healthz?ready=1", "/api/healthz?ready=1", 500, false},
		{"transport-failure", "/api", "/healthz?ready=1", "/api/healthz?ready=1", 0, true},
		{"invalid-escape", "/api", "/health%zz", "", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := NewTargetWithPolicy("http://192.0.2.1"+tc.base, 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			hc := NewHealthChecker(NewBalancer([]*Target{target}, ""), HealthConfig{Path: tc.path})
			var got string
			hc.client.Transport = regressionF4Transport(func(r *http.Request) (*http.Response, error) {
				got = r.URL.RequestURI()
				if r.URL.Host != "192.0.2.1" {
					t.Errorf("probe changed target host: %s", r.URL.Host)
				}
				if tc.fail {
					return nil, errors.New("injected transport failure")
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			for range 2 {
				hc.checkAll(context.Background())
				wantHealthy := tc.status >= 200 && tc.status < 400 && !tc.fail
				if got != tc.want || target.IsHealthy() != wantHealthy {
					t.Fatalf("EXPECTED: uri=%q healthy=%v | ACTUAL: uri=%q healthy=%v", tc.want, wantHealthy, got, target.IsHealthy())
				}
			}
		})
	}

}
