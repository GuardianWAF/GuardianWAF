package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/alerting"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tls"
)

type serveShutdownResources struct {
	server              *http.Server
	tlsServer           *http.Server
	dashboardServer     *http.Server
	certStore           *tls.CertStore
	engine              *engine.Engine
	proxyRuntimeMu      *sync.RWMutex
	proxyHealthCheckers *[]*proxy.HealthChecker
	cleanupStop         chan struct{}
	cleanupWG           *sync.WaitGroup
	dockerWatcher       *dkr.Watcher
	aiAnalyzer          *ai.Analyzer
	alertManager        *alerting.Manager
	dashboard           *dashboard.Dashboard
	eventConsumerWG     *sync.WaitGroup
}

func startServeHTTPServer(cfg *config.Config, eng *engine.Engine, srv *http.Server) {
	go func() {
		msg := fmt.Sprintf("GuardianWAF %s starting in %s mode on %s", version, cfg.Mode, cfg.Listen)
		fmt.Println(msg)
		eng.Logs.Info(msg)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			eng.Logs.Errorf("HTTP server error: %v", err)
			fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			osExit(1)
		}
	}()
}

func startServeTLSServer(cfg *config.Config, eng *engine.Engine, tlsSrv *http.Server) {
	if tlsSrv == nil {
		return
	}
	go func() {
		msg := fmt.Sprintf("TLS server listening on %s", cfg.TLS.Listen)
		fmt.Println(msg)
		eng.Logs.Info(msg)
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			eng.Logs.Errorf("TLS server error: %v", err)
			fmt.Fprintf(os.Stderr, "TLS server error: %v\n", err)
		}
	}()
}

func logServeRuntimeStatus(cfg *config.Config, eng *engine.Engine) {
	if cfg.Dashboard.Enabled {
		eng.Logs.Infof("Dashboard listening on %s", cfg.Dashboard.Listen)
	}
	if cfg.WAF.Challenge.Enabled {
		eng.Logs.Infof("JS Challenge enabled (difficulty: %d bits)", cfg.WAF.Challenge.Difficulty)
	}
	if cfg.WAF.BotDetection.Enabled {
		eng.Logs.Infof("Bot detection enabled in %s mode", cfg.WAF.BotDetection.Mode)
	}
	eng.Logs.Infof("Upstreams: %d configured", len(cfg.Upstreams))
	if len(cfg.VirtualHosts) > 0 {
		eng.Logs.Infof("Virtual hosts: %d configured", len(cfg.VirtualHosts))
	}
}

func shutdownServeRuntime(ctx context.Context, resources serveShutdownResources) {
	eng := resources.engine
	eng.Logs.Info("Shutting down...")
	fmt.Println("\nShutting down...")

	if resources.server != nil {
		_ = resources.server.Shutdown(ctx) // nolint:errcheck // best-effort; error logged upstream
	}
	if resources.tlsServer != nil {
		_ = resources.tlsServer.Shutdown(ctx) // nolint:errcheck // best-effort; error logged upstream
	}
	if resources.certStore != nil {
		resources.certStore.StopReload()
	}
	if resources.dashboardServer != nil {
		_ = resources.dashboardServer.Shutdown(ctx) // nolint:errcheck // best-effort; error logged upstream
	}

	stopThreatIntel(eng)
	stopProxyHealthCheckers(resources.proxyRuntimeMu, resources.proxyHealthCheckers)
	stopCleanupLoop(ctx, eng, resources.cleanupStop, resources.cleanupWG)

	if resources.dockerWatcher != nil {
		resources.dockerWatcher.Stop()
	}
	if resources.aiAnalyzer != nil {
		resources.aiAnalyzer.Stop()
	}
	if resources.alertManager != nil {
		if err := resources.alertManager.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Alert manager shutdown timed out: %v", err)
		}
	}
	if resources.dashboard != nil {
		resources.dashboard.Close()
	}

	eng.Close()
	if err := waitForWaitGroup(ctx, resources.eventConsumerWG); err != nil {
		eng.Logs.Warnf("Event consumer shutdown timed out: %v", err)
	}
	fmt.Println("GuardianWAF stopped.")
}

func stopThreatIntel(eng *engine.Engine) {
	if eng == nil {
		return
	}
	if tiLayer := eng.FindLayer("threat_intel"); tiLayer != nil {
		type stopper interface{ Stop() }
		if s, ok := tiLayer.(stopper); ok {
			s.Stop()
		}
	}
}

func stopProxyHealthCheckers(mu *sync.RWMutex, checkers *[]*proxy.HealthChecker) {
	if checkers == nil {
		return
	}
	var stoppingHealthCheckers []*proxy.HealthChecker
	if mu != nil {
		mu.Lock()
		stoppingHealthCheckers = *checkers
		*checkers = nil
		mu.Unlock()
	} else {
		stoppingHealthCheckers = *checkers
		*checkers = nil
	}
	stopHealthCheckers(stoppingHealthCheckers)
}

func stopCleanupLoop(ctx context.Context, eng *engine.Engine, cleanupStop chan struct{}, cleanupWG *sync.WaitGroup) {
	closeStopChannel(cleanupStop)
	if err := waitForWaitGroup(ctx, cleanupWG); err != nil {
		eng.Logs.Warnf("Periodic cleanup shutdown timed out: %v", err)
	}
}

func closeStopChannel(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
	}
}
