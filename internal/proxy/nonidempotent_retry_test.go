package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResponseFailureNeverReplaysNonIdempotentRequest(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			var effects atomic.Int32
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				effects.Add(1)
				panic(http.ErrAbortHandler)
			}))
			defer first.Close()
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); w.WriteHeader(201) }))
			defer second.Close()
			a, err := NewTargetWithPolicy(first.URL, 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := NewTargetWithPolicy(second.URL, 1, TargetPolicy{AllowPrivateTargets: true})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			rt := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{a, b}, StrategyLeastConn)}})
			for _, body := range []string{"", `{"amount":100}`} {
				effects.Store(0)
				r := httptest.NewRequest(method, "/payment", strings.NewReader(body))
				rr := httptest.NewRecorder()
				rt.ServeHTTP(rr, r)
				wantEffects, wantStatus := int32(1), 502
				if method == http.MethodGet || method == http.MethodPut {
					wantEffects, wantStatus = 2, 201
				}
				if effects.Load() != wantEffects || rr.Code != wantStatus {
					t.Fatalf("body=%q effects=%d status=%d, want %d/%d", body, effects.Load(), rr.Code, wantEffects, wantStatus)
				}
			}
		})
	}
}
