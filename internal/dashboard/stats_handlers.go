package dashboard

import (
	"net/http"
)

// registerStats registers stats and events routes.
func (d *Dashboard) registerStats(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/stats", d.authWrap(d.handleGetStats))
	mux.HandleFunc("GET /api/v1/events", d.authWrap(d.handleGetEvents))
	mux.HandleFunc("GET /api/v1/events/export", d.authWrap(d.handleExportEvents))
	mux.HandleFunc("GET /api/v1/events/{id}", d.authWrap(d.handleGetEvent))
	mux.HandleFunc("GET /api/v1/ssl", d.authWrap(d.handleGetCerts))
	mux.HandleFunc("GET /api/v1/upstreams", d.authWrap(d.handleGetUpstreams))
	mux.HandleFunc("GET /api/v1/logs", d.authWrap(d.handleGetLogs))
	mux.HandleFunc("GET /api/v1/sse", d.authWrap(d.handleSSE))
}
