package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestBuildHTTPHandler_ReturnsFallbackWhenRedirectDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = false
	cfg.TLS.HTTPRedirect = true
	serveMux := http.NewServeMux()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	buildHTTPHandler(cfg, serveMux, fallback).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected fallback status %d, got %d", http.StatusNoContent, rr.Code)
	}
}

func TestBuildHTTPHandler_RedirectsToHTTPS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.HTTPRedirect = true
	serveMux := http.NewServeMux()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com:8080/app?q=1", nil)
	buildHTTPHandler(cfg, serveMux, http.NotFoundHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("expected redirect status %d, got %d", http.StatusMovedPermanently, rr.Code)
	}
	if got, want := rr.Header().Get("Location"), "https://example.com/app?q=1"; got != want {
		t.Fatalf("expected Location %q, got %q", want, got)
	}
}

func TestBuildHTTPHandler_ServesACMEChallengeDuringRedirect(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.HTTPRedirect = true
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "challenge")
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/token", nil)
	buildHTTPHandler(cfg, serveMux, http.NotFoundHandler()).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected ACME status %d, got %d", http.StatusOK, rr.Code)
	}
	if got := rr.Body.String(); got != "challenge" {
		t.Fatalf("expected ACME response body %q, got %q", "challenge", got)
	}
}

func TestBuildHTTPHandler_RejectsUnsafeHost(t *testing.T) {
	for _, host := range []string{
		"example.com@evil.test",
		"example.com/evil",
		"example.com\\evil",
		"example.com\nLocation: https://evil.test",
	} {
		t.Run(host, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.TLS.Enabled = true
			cfg.TLS.HTTPRedirect = true
			serveMux := http.NewServeMux()

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
			req.Host = host
			buildHTTPHandler(cfg, serveMux, http.NotFoundHandler()).ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected bad request status %d, got %d", http.StatusBadRequest, rr.Code)
			}
		})
	}
}

func TestBuildHTTPHandler_NormalizesProtocolRelativeURI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.HTTPRedirect = true
	serveMux := http.NewServeMux()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com//evil.test/path", nil)
	buildHTTPHandler(cfg, serveMux, http.NotFoundHandler()).ServeHTTP(rr, req)

	if got, want := rr.Header().Get("Location"), "https://example.com/evil.test/path"; got != want {
		t.Fatalf("expected Location %q, got %q", want, got)
	}
}

func TestSanitizeHTTPRedirectHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "hostname", host: "example.com", want: "example.com"},
		{name: "hostname port", host: "example.com:8080", want: "example.com"},
		{name: "ipv6 port", host: "[2001:db8::1]:8080", want: "[2001:db8::1]"},
		{name: "empty", host: "", want: ""},
		{name: "userinfo", host: "example.com@evil.test", want: ""},
		{name: "slash", host: "example.com/evil", want: ""},
		{name: "backslash", host: "example.com\\evil", want: ""},
		{name: "space", host: "example.com evil", want: ""},
		{name: "control", host: "example.com\nLocation: https://evil.test", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeHTTPRedirectHost(tt.host); got != tt.want {
				t.Fatalf("sanitizeHTTPRedirectHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
