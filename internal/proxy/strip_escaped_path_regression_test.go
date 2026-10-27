package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type regressionF5Transport func(*http.Request) (*http.Response, error)

func (f regressionF5Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRouterStripPrefixPreservesEscaping(t *testing.T) {
	for _, tc := range []struct{ name, base, prefix, uri, want string }{
		{"escaped-slash", "", "/api", "/api/files/a%2Fb?download=1", "/files/a%2Fb?download=1"},
		{"plain", "", "/api", "/api/files/plain", "/files/plain"},
		{"escaped-prefix", "", "/api", "/%61pi/files/a%2fb", "/files/a%2fb"},
		{"escaped-base", "/root%2Fbase", "/api", "/api/a%2Fb", "/root%2Fbase/a%2Fb"},
		{"exact-prefix", "", "/api", "/api", "/"},
		{"trailing-prefix-slash", "", "/api/", "/api/a%2Fb", "/a%2Fb"},
		{"encoded-unreserved", "", "/api", "/api/%61%62%63", "/%61%62%63"},
		{"percent", "", "/api", "/api/a%25b", "/a%25b"},
		{"unicode-prefix", "", "/café", "/caf%C3%A9/a%2Fb", "/a%2Fb"},
		{"no-stripping", "", "", "/api/a%2Fb", "/api/a%2Fb"},
		{"escaped-leading-separator", "", "/api", "/api%2Ffiles/a%2Fb", "/files/a%2Fb"},
		{"escaped-leading-separator-lower", "", "/api", "/api%2ffiles/a%2fb", "/files/a%2fb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := NewTargetWithPolicy("http://192.0.2.1"+tc.base, 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var got string
			target.proxy.Transport = regressionF5Transport(func(r *http.Request) (*http.Response, error) {
				got = r.URL.RequestURI()
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			router := NewRouter([]Route{{PathPrefix: tc.prefix, StripPrefix: true, Balancer: NewBalancer([]*Target{target}, "")}})
			for range 2 {
				req := httptest.NewRequest("GET", tc.uri, nil)
				before := *req.URL
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if got != tc.want || rec.Code != http.StatusOK {
					t.Fatalf("EXPECTED: uri=%q status=200 | ACTUAL: uri=%q status=%d", tc.want, got, rec.Code)
				}
				if *req.URL != before {
					t.Fatalf("caller URL mutated: before=%+v after=%+v", before, *req.URL)
				}
				if target.ActiveConns() != 0 {
					t.Fatal("active connection count did not return to zero")
				}
			}
		})
	}

}
