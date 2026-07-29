package dashboard

import (
	"fmt"
	"net/http"
)

// registerStats registers stats and events routes.
func (d *Dashboard) registerStats(mux *http.ServeMux) {
	mux.HandleFunc("GET /metrics", d.handleMetrics)
	mux.HandleFunc("GET /api/v1/stats", d.authWrap(d.handleGetStats))
	mux.HandleFunc("OPTIONS /api/v1/stats", handleCORS)
	mux.HandleFunc("GET /api/v1/events", d.authWrap(d.handleGetEvents))
	mux.HandleFunc("OPTIONS /api/v1/events", handleCORS)
	mux.HandleFunc("GET /api/v1/events/export", d.authWrap(d.handleExportEvents))
	mux.HandleFunc("GET /api/v1/events/{id}", d.authWrap(d.handleGetEvent))
	mux.HandleFunc("GET /api/v1/ssl", d.authWrap(d.handleGetCerts))
	mux.HandleFunc("POST /api/v1/ssl/certificates", d.authAuditWrap(d.handleUploadCertificateCompat))
	mux.HandleFunc("DELETE /api/v1/ssl/certificates/{name}", d.authAuditWrap(d.handleDeleteCertificateCompat))
	mux.HandleFunc("GET /api/v1/upstreams", d.authWrap(d.handleGetUpstreams))
	mux.HandleFunc("GET /api/v1/logs", d.authWrap(d.handleGetLogs))
	mux.HandleFunc("GET /api/v1/sse", d.authWrap(d.handleSSE))
	mux.HandleFunc("GET /api/v1/events/stream", d.authWrap(d.handleSSE))
}

func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s := d.engine.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP guardianwaf_requests_total Total number of requests processed.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_requests_total counter\n")
	fmt.Fprintf(w, "guardianwaf_requests_total %d\n", s.TotalRequests)
	fmt.Fprintf(w, "# HELP guardianwaf_requests_blocked_total Total number of blocked requests.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_requests_blocked_total counter\n")
	fmt.Fprintf(w, "guardianwaf_requests_blocked_total %d\n", s.BlockedRequests)
	fmt.Fprintf(w, "# HELP guardianwaf_requests_challenged_total Total number of challenged requests.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_requests_challenged_total counter\n")
	fmt.Fprintf(w, "guardianwaf_requests_challenged_total %d\n", s.ChallengedRequests)
	fmt.Fprintf(w, "# HELP guardianwaf_requests_logged_total Total number of logged (suspicious) requests.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_requests_logged_total counter\n")
	fmt.Fprintf(w, "guardianwaf_requests_logged_total %d\n", s.LoggedRequests)
	fmt.Fprintf(w, "# HELP guardianwaf_requests_passed_total Total number of passed requests.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_requests_passed_total counter\n")
	fmt.Fprintf(w, "guardianwaf_requests_passed_total %d\n", s.PassedRequests)
	fmt.Fprintf(w, "# HELP guardianwaf_latency_avg_microseconds Average request latency in microseconds.\n")
	fmt.Fprintf(w, "# TYPE guardianwaf_latency_avg_microseconds gauge\n")
	fmt.Fprintf(w, "guardianwaf_latency_avg_microseconds %d\n", s.AvgLatencyUs)
}
