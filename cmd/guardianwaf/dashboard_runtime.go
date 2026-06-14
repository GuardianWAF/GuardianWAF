package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/compliance"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// startDashboard starts the full dashboard HTTP server in the background.
// It provides a real-time web UI with SSE event streaming, REST API,
// and security analytics. Returns the server and the SSE broadcaster
// so the engine can publish events to connected dashboard clients.
func startDashboard(cfg *config.Config, eng *engine.Engine) (*http.Server, *dashboard.SSEBroadcaster, *dashboard.Dashboard) {
	eventStore, ok := eng.EventStore().(events.EventStore)
	if !ok {
		slog.Warn("event store does not support queries; dashboard events disabled")
		eventStore = events.NewMemoryStore(1000)
	}

	if cfg.Dashboard.TLS {
		fmt.Fprintln(os.Stderr, "Dashboard server error: dashboard.tls is not supported by the built-in dashboard; terminate TLS at an ingress or reverse proxy")
		slog.Error("dashboard TLS termination is not implemented; refusing to start plain HTTP dashboard with dashboard.tls=true")
		return nil, nil, nil
	}

	// Require API key for dashboard - generate random if not set.
	if cfg.Dashboard.APIKey == "" {
		apiKey, err := generateDashboardPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
			slog.Error("dashboard API key auto-generation failed", "error", err)
			return nil, nil, nil
		}
		cfg.Dashboard.APIKey = apiKey
		fmt.Printf("[WARN] Dashboard API key not set - a new one has been generated.\n")
		fmt.Printf("[WARN] The generated key is NOT shown here for security reasons.\n")
		fmt.Printf("[WARN] To set a known key, set 'dashboard.api_key' in your config file.\n")
		fmt.Printf("[WARN] Access dashboard at http://%s and use the generated API key, or place it behind TLS.\n", cfg.Dashboard.Listen)
		slog.Warn("dashboard API key was auto-generated; set dashboard.api_key in config to use a known key")
	}

	dash := dashboard.New(eng, eventStore, cfg.Dashboard.APIKey)
	dash.SetTrustedProxies(cfg.TrustedProxies)
	dash.SetBuildInfo(version, commit, date)

	if cfg.Compliance.Enabled {
		compEngine, err := compliance.NewEngineWithError(cfg.Compliance)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard compliance error: %v\n", err)
			return nil, nil, nil
		}
		dash.SetComplianceEngine(compEngine)
	}

	if cfg.Dashboard.AdminKey != "" {
		dash.SetAdminKey(cfg.Dashboard.AdminKey)
	} else {
		slog.Warn("dashboard.admin_key not set; tenant admin API endpoints are disabled")
	}

	srv := &http.Server{
		Addr:              cfg.Dashboard.Listen,
		Handler:           dash.Handler(),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", cfg.Dashboard.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dashboard server error: listen %s: %v\n", cfg.Dashboard.Listen, err)
		return nil, nil, nil
	}

	go func() {
		fmt.Printf("Dashboard listening on %s\n", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
		}
	}()

	return srv, dash.SSE(), dash
}
