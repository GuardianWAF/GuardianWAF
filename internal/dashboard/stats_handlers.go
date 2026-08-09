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

	// Cluster metrics — emitted only when cluster mode is active.
	if cs := d.clusterStatus; cs != nil {
		isLeader := 0
		if cs.Role() == "leader" {
			isLeader = 1
		}
		memberCount := len(cs.Peers()) + 1 // peers + self
		storeStats := cs.StoreStats()

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_member_count Number of nodes in the cluster (peers + self).\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_member_count gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_member_count %d\n", memberCount)

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_is_leader 1 if this node is the Raft leader, 0 otherwise.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_is_leader gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_is_leader %d\n", isLeader)

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_raft_term Current Raft term.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_raft_term gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_raft_term %d\n", cs.CurrentTerm())

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_raft_commit_index Index of the highest log entry known to be committed.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_raft_commit_index gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_raft_commit_index %d\n", cs.CommitIndex())

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_raft_last_applied Index of the highest log entry applied to the state machine.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_raft_last_applied gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_raft_last_applied %d\n", cs.LastApplied())

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_raft_log_length Number of entries in the Raft log.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_raft_log_length gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_raft_log_length %d\n", cs.LogLength())

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_store_bans Number of active bans in the replicated store.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_store_bans gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_store_bans %d\n", storeStats.Bans)

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_store_rules Number of rules in the replicated store.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_store_rules gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_store_rules %d\n", storeStats.Rules)

		fmt.Fprintf(w, "# HELP guardianwaf_cluster_store_counters Number of rate-limit counters in the replicated store.\n")
		fmt.Fprintf(w, "# TYPE guardianwaf_cluster_store_counters gauge\n")
		fmt.Fprintf(w, "guardianwaf_cluster_store_counters %d\n", storeStats.Counters)
	}
}
