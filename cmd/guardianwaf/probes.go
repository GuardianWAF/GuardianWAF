package main

import (
	"encoding/json"
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

func registerProbeHandlers(mux *http.ServeMux, cfg *config.Config, eng *engine.Engine, router func() *proxy.Router) {
	writeLive := func(w http.ResponseWriter, status string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		s := eng.Stats()
		_ = json.NewEncoder(w).Encode(map[string]any{ // nolint:errcheck // probe response; write error unreachable after WriteHeader
			"status":           status,
			"mode":             cfg.Mode,
			"total_requests":   s.TotalRequests,
			"blocked_requests": s.BlockedRequests,
		})
	}

	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		writeLive(w, "ok")
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		statuses := []proxy.UpstreamStatus(nil)
		if router != nil {
			if rt := router(); rt != nil {
				statuses = rt.AllUpstreamStatus()
			}
		}

		unhealthy := make([]string, 0)
		for _, st := range statuses {
			if st.TotalCount > 0 && st.HealthyCount == 0 {
				unhealthy = append(unhealthy, st.Name)
			}
		}

		httpStatus := http.StatusOK
		status := "ready"
		if len(unhealthy) > 0 {
			httpStatus = http.StatusServiceUnavailable
			status = "not_ready"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		s := eng.Stats()
		_ = json.NewEncoder(w).Encode(map[string]any{ // nolint:errcheck // probe response; write error unreachable after WriteHeader
			"status":              status,
			"mode":                cfg.Mode,
			"total_requests":      s.TotalRequests,
			"blocked_requests":    s.BlockedRequests,
			"upstreams_total":     len(statuses),
			"upstreams_unhealthy": unhealthy,
		})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeLive(w, "ok")
	})
}
