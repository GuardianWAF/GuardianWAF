package main

import (
	"fmt"
	"log/slog"
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

	// Require API key for dashboard - generate random if not set.
	if cfg.Dashboard.APIKey == "" {
		cfg.Dashboard.APIKey = generateDashboardPassword()
		fmt.Printf("[WARN] Dashboard API key not set - a new one has been generated.\n")
		fmt.Printf("[WARN] The generated key is NOT shown here for security reasons.\n")
		fmt.Printf("[WARN] To set a known key, set 'dashboard.api_key' in your config file.\n")
		fmt.Printf("[WARN] Access dashboard at https://%s and use the generated API key.\n", cfg.Dashboard.Listen)
		slog.Warn("dashboard API key was auto-generated; set dashboard.api_key in config to use a known key")
	}

	dash := dashboard.New(eng, eventStore, cfg.Dashboard.APIKey)

	if cfg.Compliance.Enabled {
		compEngine := compliance.NewEngine(cfg.Compliance)
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

	go func() {
		fmt.Printf("Dashboard listening on %s\n", cfg.Dashboard.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Dashboard server error: %v\n", err)
		}
	}()

	return srv, dash.SSE(), dash
}
