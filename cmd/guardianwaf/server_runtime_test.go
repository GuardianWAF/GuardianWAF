package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRuntimeHTTPServer_UsesProductionTimeouts(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	srv := newRuntimeHTTPServer("127.0.0.1:0", handler)

	if srv.Addr != "127.0.0.1:0" {
		t.Fatalf("expected addr %q, got %q", "127.0.0.1:0", srv.Addr)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Fatalf("expected read timeout %s, got %s", 30*time.Second, srv.ReadTimeout)
	}
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("expected read header timeout %s, got %s", 10*time.Second, srv.ReadHeaderTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Fatalf("expected write timeout %s, got %s", 30*time.Second, srv.WriteTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("expected idle timeout %s, got %s", 120*time.Second, srv.IdleTimeout)
	}

	rr := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rr.Body.String(); got != "ok" {
		t.Fatalf("expected handler response %q, got %q", "ok", got)
	}
}
