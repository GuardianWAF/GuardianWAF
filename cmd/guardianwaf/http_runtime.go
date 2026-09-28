package main

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/netutil"
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
		host := sanitizeHTTPRedirectHost(r.Host)
		uri := r.URL.RequestURI()
		if strings.HasPrefix(uri, "//") {
			uri = "/" + strings.TrimLeft(uri, "/")
		}
		if host == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		target := (&url.URL{Scheme: "https", Host: host, Path: "/", RawQuery: ""}).String()
		target = strings.TrimSuffix(target, "/") + uri
		http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- host is sanitized and target always uses the fixed https scheme.
	})
}

func sanitizeHTTPRedirectHost(host string) string {
	// netutil.StripPort is bracket-aware: a bare bracketed IPv6 Host (clients
	// omit the default port) survives whole — a LastIndex cut would mangle
	// "[::1]" into "[::" and produce a malformed redirect Location.
	host = netutil.StripPort(host)
	if host == "" || strings.ContainsAny(host, "@/\\") {
		return ""
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return ""
		}
	}
	return host
}
