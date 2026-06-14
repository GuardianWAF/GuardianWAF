package main

import (
	"encoding/json"
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

type probeDependencies struct {
	Router         func() *proxy.Router
	DashboardReady func() bool
}

func registerProbeHandlers(mux *http.ServeMux, cfg *config.Config, eng *engine.Engine, router func() *proxy.Router) {
	registerProbeHandlersWithDeps(mux, cfg, eng, probeDependencies{Router: router})
}

func registerProbeHandlersWithDeps(mux *http.ServeMux, cfg *config.Config, eng *engine.Engine, deps probeDependencies) {
	writeLive := func(w http.ResponseWriter, status string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var s engine.Stats
		if eng != nil {
			s = eng.Stats()
		}
		mode := ""
		if cfg != nil {
			mode = cfg.Mode
		}
		_ = json.NewEncoder(w).Encode(map[string]any{ // nolint:errcheck // probe response; write error unreachable after WriteHeader
			"status":           status,
			"mode":             mode,
			"total_requests":   s.TotalRequests,
			"blocked_requests": s.BlockedRequests,
		})
	}

	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		writeLive(w, "ok")
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		statuses := []proxy.UpstreamStatus(nil)
		routerConfigured := proxyRoutingConfigured(cfg)
		routerReady := !routerConfigured
		if deps.Router != nil {
			if rt := deps.Router(); rt != nil {
				statuses = rt.AllUpstreamStatus()
				routerReady = true
			}
		}
		var s engine.Stats
		if eng != nil {
			s = eng.Stats()
		}

		reasons := make([]string, 0)
		if cfg == nil {
			reasons = append(reasons, "config_not_loaded")
		}
		if eng == nil {
			reasons = append(reasons, "engine_not_ready")
		} else if eng.EventStore() == nil {
			reasons = append(reasons, "event_store_not_ready")
		}
		if !routerReady {
			reasons = append(reasons, "router_not_ready")
		} else if routerConfigured && len(statuses) == 0 {
			reasons = append(reasons, "no_active_upstreams")
		}
		dashboardReady := true
		if cfg != nil && cfg.Dashboard.Enabled && cfg.Dashboard.Listen != "" && deps.DashboardReady != nil {
			dashboardReady = deps.DashboardReady()
			if !dashboardReady {
				reasons = append(reasons, "dashboard_not_ready")
			}
		}

		unhealthy := make([]string, 0)
		for _, st := range statuses {
			if st.TotalCount > 0 && st.HealthyCount == 0 {
				unhealthy = append(unhealthy, st.Name)
			}
		}
		if len(unhealthy) > 0 {
			reasons = append(reasons, "upstreams_unhealthy")
		}
		if cfg != nil && cfg.WAF.GeoIP.RequireReady && !s.GeoIPReady {
			reasons = append(reasons, "geoip_not_ready")
		}

		httpStatus := http.StatusOK
		status := "ready"
		if len(reasons) > 0 {
			httpStatus = http.StatusServiceUnavailable
			status = "not_ready"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
		mode := ""
		if cfg != nil {
			mode = cfg.Mode
		}
		_ = json.NewEncoder(w).Encode(map[string]any{ // nolint:errcheck // probe response; write error unreachable after WriteHeader
			"status":              status,
			"mode":                mode,
			"reasons":             reasons,
			"total_requests":      s.TotalRequests,
			"blocked_requests":    s.BlockedRequests,
			"dashboard_ready":     dashboardReady,
			"event_store_ready":   eng != nil && eng.EventStore() != nil,
			"geoip_ready":         s.GeoIPReady,
			"geoip_ranges":        s.GeoIPRanges,
			"router_ready":        routerReady,
			"upstreams_total":     len(statuses),
			"upstreams_unhealthy": unhealthy,
		})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeLive(w, "ok")
	})
}
