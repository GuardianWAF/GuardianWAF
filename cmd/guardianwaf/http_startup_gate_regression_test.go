package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestHTTPStartupGateProtectsAllApplicationTraffic(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		cfg := config.DefaultConfig()
		cfg.TLS.Enabled, cfg.TLS.HTTPRedirect = redirect, redirect
		mux := http.NewServeMux()
		applicationCalls := 0
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			applicationCalls++
			w.WriteHeader(http.StatusNoContent)
		})
		ready := false
		handler := buildStartupHTTPHandler(cfg, mux, mux, func() bool { return ready })
		request := func(path string) int {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil))
			return rec.Code
		}
		for _, path := range []string{"/", "/readyz", "/.well-known/acme-challenge/unregistered"} {
			if status := request(path); status != http.StatusServiceUnavailable {
				t.Errorf("EXPECTED startup503 redirect=%v path=%s ACTUAL=%d; PROBLEM CONFIRMED", redirect, path, status)
			}
		}
		if applicationCalls != 0 {
			t.Error("application was reached before runtime initialization completed")
		}
		mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		if status := request("/.well-known/acme-challenge/registered"); status != http.StatusOK {
			t.Fatal("control: registered HTTP-01 challenge not served during startup")
		}
		ready = true
		expected := http.StatusNoContent
		if redirect {
			expected = http.StatusMovedPermanently
		}
		if status := request("/"); status != expected {
			t.Fatalf("ready control status=%d want%d", status, expected)
		}
	}
}
