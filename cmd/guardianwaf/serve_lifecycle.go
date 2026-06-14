package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
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
	acmeRenewal         interface{ StopRenewal() }
	engine              *engine.Engine
	proxyRuntimeMu      *sync.RWMutex
	proxyRouter         **proxy.Router
	proxyHealthCheckers *[]*proxy.HealthChecker
	cleanupStop         chan struct{}
	cleanupWG           *sync.WaitGroup
	dockerWatcher       *dkr.Watcher
	aiAnalyzer          *ai.Analyzer
	alertManager        *alerting.Manager
	dashboard           *dashboard.Dashboard
	tenantManager       interface{ CloseWithContext(context.Context) error }
	eventConsumerWG     *sync.WaitGroup
	layerResources      *layerRuntimeResources
}

type sidecarShutdownResources struct {
	server              *http.Server
	engine              *engine.Engine
	proxyRouter         **proxy.Router
	proxyHealthCheckers *[]*proxy.HealthChecker
	cleanupStop         chan struct{}
	cleanupWG           *sync.WaitGroup
	layerResources      *layerRuntimeResources
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
		if err := resources.certStore.StopReloadWithContext(ctx); err != nil {
			eng.Logs.Warnf("TLS certificate reload shutdown timed out: %v", err)
		}
	}
	stopACMERenewal(ctx, eng, resources.acmeRenewal)
	if resources.dashboardServer != nil {
		_ = resources.dashboardServer.Shutdown(ctx) // nolint:errcheck // best-effort; error logged upstream
	}

	stopEngineLayer(ctx, eng, "threat_intel", "Threat intel")
	stopEngineLayer(ctx, eng, "virtualpatch", "Virtual patch")
	stopEngineLayer(ctx, eng, "ipacl", "IP ACL")
	stopProxyRuntime(ctx, eng, resources.proxyRuntimeMu, resources.proxyRouter, resources.proxyHealthCheckers)
	stopCleanupLoop(ctx, eng, resources.cleanupStop, resources.cleanupWG)

	if resources.dockerWatcher != nil {
		if err := resources.dockerWatcher.StopWithContext(ctx); err != nil {
			eng.Logs.Warnf("Docker watcher shutdown timed out: %v", err)
		}
	}
	if resources.aiAnalyzer != nil {
		if err := resources.aiAnalyzer.StopWithContext(ctx); err != nil {
			eng.Logs.Warnf("AI analyzer shutdown timed out: %v", err)
		}
	}
	if resources.alertManager != nil {
		if err := resources.alertManager.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Alert manager shutdown timed out: %v", err)
		}
	}
	if resources.dashboard != nil {
		if err := resources.dashboard.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Dashboard shutdown timed out: %v", err)
		}
	}
	if resources.tenantManager != nil && !isNilInterface(resources.tenantManager) {
		if err := resources.tenantManager.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Tenant manager shutdown timed out: %v", err)
		}
	}
	if err := resources.layerResources.stopGeoIPRefresh(ctx); err != nil {
		eng.Logs.Warnf("GeoIP auto-refresh shutdown timed out: %v", err)
	}

	eng.Close()
	if err := waitForWaitGroup(ctx, resources.eventConsumerWG); err != nil {
		eng.Logs.Warnf("Event consumer shutdown timed out: %v", err)
	}
	fmt.Println("GuardianWAF stopped.")
}

func shutdownSidecarRuntime(ctx context.Context, resources sidecarShutdownResources) {
	eng := resources.engine
	eng.Logs.Info("Shutting down sidecar...")
	fmt.Println("\nShutting down sidecar...")

	if resources.server != nil {
		_ = resources.server.Shutdown(ctx) // nolint:errcheck // best-effort; error logged upstream
	}
	stopEngineLayer(ctx, eng, "ipacl", "IP ACL")
	stopProxyRuntime(ctx, eng, nil, resources.proxyRouter, resources.proxyHealthCheckers)
	stopCleanupLoop(ctx, eng, resources.cleanupStop, resources.cleanupWG)
	if err := resources.layerResources.stopGeoIPRefresh(ctx); err != nil {
		eng.Logs.Warnf("GeoIP auto-refresh shutdown timed out: %v", err)
	}
	eng.Close()

	fmt.Println("GuardianWAF sidecar stopped.")
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func stopACMERenewal(ctx context.Context, eng *engine.Engine, renewal interface{ StopRenewal() }) {
	if renewal == nil || isNilInterface(renewal) {
		return
	}
	type contextRenewalStopper interface {
		StopRenewalWithContext(context.Context) error
	}
	if s, ok := renewal.(contextRenewalStopper); ok {
		if err := s.StopRenewalWithContext(ctx); err != nil {
			eng.Logs.Warnf("ACME renewal shutdown timed out: %v", err)
		}
		return
	}
	renewal.StopRenewal()
}

func stopEngineLayer(ctx context.Context, eng *engine.Engine, layerName, logName string) {
	if eng == nil {
		return
	}
	if layer := eng.FindLayer(layerName); layer != nil {
		type contextStopper interface{ StopWithContext(context.Context) error }
		if s, ok := layer.(contextStopper); ok {
			if err := s.StopWithContext(ctx); err != nil {
				eng.Logs.Warnf("%s shutdown timed out: %v", logName, err)
			}
			return
		}
		type stopper interface{ Stop() }
		if s, ok := layer.(stopper); ok {
			s.Stop()
		}
	}
}

func stopProxyHealthCheckers(ctx context.Context, eng *engine.Engine, mu *sync.RWMutex, checkers *[]*proxy.HealthChecker) {
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
	if err := stopHealthCheckersWithContext(ctx, stoppingHealthCheckers); err != nil && eng != nil {
		eng.Logs.Warnf("Proxy health checker shutdown timed out: %v", err)
	}
}

func stopProxyRuntime(ctx context.Context, eng *engine.Engine, mu *sync.RWMutex, router **proxy.Router, checkers *[]*proxy.HealthChecker) {
	if router == nil {
		stopProxyHealthCheckers(ctx, eng, mu, checkers)
		return
	}

	var stoppingRouter *proxy.Router
	var stoppingHealthCheckers []*proxy.HealthChecker
	if mu != nil {
		mu.Lock()
		stoppingRouter = *router
		*router = nil
		if checkers != nil {
			stoppingHealthCheckers = *checkers
			*checkers = nil
		}
		mu.Unlock()
	} else {
		stoppingRouter = *router
		*router = nil
		if checkers != nil {
			stoppingHealthCheckers = *checkers
			*checkers = nil
		}
	}

	if err := stopHealthCheckersWithContext(ctx, stoppingHealthCheckers); err != nil && eng != nil {
		eng.Logs.Warnf("Proxy health checker shutdown timed out: %v", err)
	}
	closeProxyRouter(stoppingRouter)
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
