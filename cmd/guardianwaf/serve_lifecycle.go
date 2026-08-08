package main

import (
	"context"
	"errors"
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
	siemExporter        interface{ Close() error }
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
	if cfg.AllowPrivateUpstreams != nil && *cfg.AllowPrivateUpstreams && cfg.Mode == "enforce" {
		eng.Logs.Warn("allow_private_upstreams is true in enforce mode — the WAF can proxy requests to private IP ranges. Set to false in production unless required.")
	}
}

func shutdownServeRuntime(ctx context.Context, resources serveShutdownResources) error {
	eng := resources.engine
	var shutdownErrs []error
	eng.Logs.Info("Shutting down...")
	fmt.Println("\nShutting down...")

	if resources.server != nil {
		if err := resources.server.Shutdown(ctx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("HTTP server shutdown: %w", err))
		}
	}
	if resources.tlsServer != nil {
		if err := resources.tlsServer.Shutdown(ctx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("TLS server shutdown: %w", err))
		}
	}
	if resources.certStore != nil {
		if err := resources.certStore.StopReloadWithContext(ctx); err != nil {
			eng.Logs.Warnf("TLS certificate reload shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("TLS certificate reload shutdown: %w", err))
		}
	}
	if err := stopACMERenewal(ctx, eng, resources.acmeRenewal); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("ACME renewal shutdown: %w", err))
	}
	if resources.dashboardServer != nil {
		if err := resources.dashboardServer.Shutdown(ctx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("dashboard server shutdown: %w", err))
		}
	}

	for _, layer := range []struct {
		name    string
		logName string
	}{
		{name: "threat_intel", logName: "Threat intel"},
		{name: "virtualpatch", logName: "Virtual patch"},
		{name: "ipacl", logName: "IP ACL"},
	} {
		if err := stopEngineLayer(ctx, eng, layer.name, layer.logName); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("%s shutdown: %w", layer.logName, err))
		}
	}
	if err := stopProxyRuntime(ctx, eng, resources.proxyRuntimeMu, resources.proxyRouter, resources.proxyHealthCheckers); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("proxy runtime shutdown: %w", err))
	}
	if err := stopCleanupLoop(ctx, eng, resources.cleanupStop, resources.cleanupWG); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("periodic cleanup shutdown: %w", err))
	}

	if resources.dockerWatcher != nil {
		if err := resources.dockerWatcher.StopWithContext(ctx); err != nil {
			eng.Logs.Warnf("Docker watcher shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("docker watcher shutdown: %w", err))
		}
	}
	if resources.aiAnalyzer != nil {
		if err := resources.aiAnalyzer.StopWithContext(ctx); err != nil {
			eng.Logs.Warnf("AI analyzer shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("AI analyzer shutdown: %w", err))
		}
	}
	if resources.alertManager != nil {
		if err := resources.alertManager.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Alert manager shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("alert manager shutdown: %w", err))
		}
	}
	if resources.dashboard != nil {
		if err := resources.dashboard.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Dashboard shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("dashboard shutdown: %w", err))
		}
	}
	if resources.siemExporter != nil {
		if err := resources.siemExporter.Close(); err != nil {
			eng.Logs.Warnf("SIEM exporter shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("SIEM exporter shutdown: %w", err))
		}
	}
	if resources.tenantManager != nil && !isNilInterface(resources.tenantManager) {
		if err := resources.tenantManager.CloseWithContext(ctx); err != nil {
			eng.Logs.Warnf("Tenant manager shutdown timed out: %v", err)
			shutdownErrs = append(shutdownErrs, fmt.Errorf("tenant manager shutdown: %w", err))
		}
	}
	if err := resources.layerResources.stopGeoIPRefresh(ctx); err != nil {
		eng.Logs.Warnf("GeoIP auto-refresh shutdown timed out: %v", err)
		shutdownErrs = append(shutdownErrs, fmt.Errorf("GeoIP auto-refresh shutdown: %w", err))
	}

	if err := eng.Close(); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("engine event store shutdown: %w", err))
	}
	if err := waitForWaitGroup(ctx, resources.eventConsumerWG); err != nil {
		eng.Logs.Warnf("Event consumer shutdown timed out: %v", err)
		shutdownErrs = append(shutdownErrs, fmt.Errorf("event consumer shutdown: %w", err))
	}
	fmt.Println("GuardianWAF stopped.")
	return errors.Join(shutdownErrs...)
}

func shutdownSidecarRuntime(ctx context.Context, resources sidecarShutdownResources) error {
	eng := resources.engine
	var shutdownErrs []error
	eng.Logs.Info("Shutting down sidecar...")
	fmt.Println("\nShutting down sidecar...")

	if resources.server != nil {
		if err := resources.server.Shutdown(ctx); err != nil {
			shutdownErrs = append(shutdownErrs, fmt.Errorf("HTTP server shutdown: %w", err))
		}
	}
	if err := stopEngineLayer(ctx, eng, "ipacl", "IP ACL"); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("IP ACL shutdown: %w", err))
	}
	if err := stopProxyRuntime(ctx, eng, nil, resources.proxyRouter, resources.proxyHealthCheckers); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("proxy runtime shutdown: %w", err))
	}
	if err := stopCleanupLoop(ctx, eng, resources.cleanupStop, resources.cleanupWG); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("periodic cleanup shutdown: %w", err))
	}
	if err := resources.layerResources.stopGeoIPRefresh(ctx); err != nil {
		eng.Logs.Warnf("GeoIP auto-refresh shutdown timed out: %v", err)
		shutdownErrs = append(shutdownErrs, fmt.Errorf("GeoIP auto-refresh shutdown: %w", err))
	}
	if err := eng.Close(); err != nil {
		shutdownErrs = append(shutdownErrs, fmt.Errorf("engine event store shutdown: %w", err))
	}

	fmt.Println("GuardianWAF sidecar stopped.")
	return errors.Join(shutdownErrs...)
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

func stopACMERenewal(ctx context.Context, eng *engine.Engine, renewal interface{ StopRenewal() }) error {
	if renewal == nil || isNilInterface(renewal) {
		return nil
	}
	type contextRenewalStopper interface {
		StopRenewalWithContext(context.Context) error
	}
	if s, ok := renewal.(contextRenewalStopper); ok {
		if err := s.StopRenewalWithContext(ctx); err != nil {
			eng.Logs.Warnf("ACME renewal shutdown timed out: %v", err)
			return err
		}
		return nil
	}
	renewal.StopRenewal()
	return nil
}

func stopEngineLayer(ctx context.Context, eng *engine.Engine, layerName, logName string) error {
	if eng == nil {
		return nil
	}
	if layer := eng.FindLayer(layerName); layer != nil {
		type contextStopper interface{ StopWithContext(context.Context) error }
		if s, ok := layer.(contextStopper); ok {
			if err := s.StopWithContext(ctx); err != nil {
				eng.Logs.Warnf("%s shutdown timed out: %v", logName, err)
				return err
			}
			return nil
		}
		type stopper interface{ Stop() }
		if s, ok := layer.(stopper); ok {
			s.Stop()
		}
	}
	return nil
}

func stopProxyHealthCheckers(ctx context.Context, eng *engine.Engine, mu *sync.RWMutex, checkers *[]*proxy.HealthChecker) error {
	if checkers == nil {
		return nil
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
	if err := stopHealthCheckersWithContext(ctx, stoppingHealthCheckers); err != nil {
		if eng != nil {
			eng.Logs.Warnf("Proxy health checker shutdown timed out: %v", err)
		}
		return err
	}
	return nil
}

func stopProxyRuntime(ctx context.Context, eng *engine.Engine, mu *sync.RWMutex, router **proxy.Router, checkers *[]*proxy.HealthChecker) error {
	if router == nil {
		return stopProxyHealthCheckers(ctx, eng, mu, checkers)
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

	var stopErr error
	if err := stopHealthCheckersWithContext(ctx, stoppingHealthCheckers); err != nil {
		if eng != nil {
			eng.Logs.Warnf("Proxy health checker shutdown timed out: %v", err)
		}
		stopErr = err
	}
	closeProxyRouter(stoppingRouter)
	return stopErr
}

func stopCleanupLoop(ctx context.Context, eng *engine.Engine, cleanupStop chan struct{}, cleanupWG *sync.WaitGroup) error {
	closeStopChannel(cleanupStop)
	if err := waitForWaitGroup(ctx, cleanupWG); err != nil {
		eng.Logs.Warnf("Periodic cleanup shutdown timed out: %v", err)
		return err
	}
	return nil
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
