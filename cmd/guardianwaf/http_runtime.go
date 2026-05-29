package main

import (
	"net/http"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func buildHTTPHandler(cfg *config.Config, serveMux *http.ServeMux, handler http.Handler) http.Handler {
	if !cfg.TLS.Enabled || !cfg.TLS.HTTPRedirect {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve ACME challenges even when redirecting.
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			serveMux.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if idx := strings.LastIndex(host, ":"); idx > 0 {
			host = host[:idx]
		}
		if strings.ContainsAny(host, "@/") {
			host = ""
		}
		uri := r.URL.RequestURI()
		if strings.HasPrefix(uri, "//") {
			uri = "/" + strings.TrimLeft(uri, "/")
		}
		if host == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+host+uri, http.StatusMovedPermanently)
	})
}
