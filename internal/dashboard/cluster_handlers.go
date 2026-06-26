package dashboard

import "net/http"

func (d *Dashboard) registerCluster(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/clusters", d.authWrap(d.handleClusterList))
	mux.HandleFunc("POST /api/clusters", d.authWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("GET /api/clusters/", d.authWrap(d.handleClusterNotFound))
	mux.HandleFunc("DELETE /api/clusters/", d.authWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("POST /api/clusters/", d.authWrap(d.handleClusterMutationDisabled))
	mux.HandleFunc("GET /api/nodes", d.authWrap(d.handleClusterNodesLegacy))
	mux.HandleFunc("GET /api/sync/stats", d.authWrap(d.handleSyncStats))
	mux.HandleFunc("GET /api/sync/status", d.authWrap(d.handleSyncStatus))

	mux.HandleFunc("GET /api/v1/cluster/status", d.authWrap(d.handleClusterStatus))
	mux.HandleFunc("GET /api/v1/cluster/nodes", d.authWrap(d.handleClusterNodes))
	mux.HandleFunc("GET /api/v1/cluster/health", d.authWrap(d.handleClusterHealth))
	mux.HandleFunc("GET /api/v1/cluster/node/stats", d.authWrap(d.handleClusterNodeStats))
	mux.HandleFunc("GET /api/v1/cluster/config", d.authWrap(d.handleClusterConfig))
}

func (d *Dashboard) handleClusterList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []any{})
}

func (d *Dashboard) handleClusterNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "cluster not found")
}

func (d *Dashboard) handleClusterMutationDisabled(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusServiceUnavailable, "cluster sync is not enabled")
}

func (d *Dashboard) handleClusterNodesLegacy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []any{})
}

func (d *Dashboard) handleSyncStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"total_events_sent":     0,
		"total_events_received": 0,
		"total_conflicts":       0,
		"total_resolved":        0,
		"active_connections":    0,
	})
}

func (d *Dashboard) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"local_node": "local",
		"nodes":      []any{},
	})
}

func (d *Dashboard) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": false,
		"cluster": map[string]any{
			"enabled": false,
			"status":  "disabled",
		},
		"nodes": []any{},
	})
}

func (d *Dashboard) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"nodes": []any{}})
}

func (d *Dashboard) handleClusterHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"healthy": true,
		"status":  "disabled",
	})
}

func (d *Dashboard) handleClusterNodeStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"requests": 0,
		"cpu":      0,
	})
}

func (d *Dashboard) handleClusterConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       false,
		"sync_interval": "0s",
	})
}
