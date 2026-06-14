package main

import (
	"sync"
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	dkr "github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
	"github.com/guardianwaf/guardianwaf/internal/tenant"
)

func setupDockerRuntime(
	cfg *config.Config,
	eng *engine.Engine,
	dash *dashboard.Dashboard,
	proxyRouter **proxy.Router,
	proxyHealthCheckers *[]*proxy.HealthChecker,
	proxyRuntimeMu *sync.RWMutex,
	upstreamHandler *atomic.Value,
	tenantMiddleware *tenant.Middleware,
) *dkr.Watcher {
	if cfg == nil || eng == nil || !cfg.Docker.Enabled {
		return nil
	}

	dockerClient := dkr.NewClientWithOptions(dkr.ClientOptions{
		SocketPath: cfg.Docker.SocketPath,
		TLSVerify:  cfg.Docker.TLSVerify,
		TLSCACert:  cfg.Docker.TLSCACert,
		TLSCert:    cfg.Docker.TLSCert,
		TLSKey:     cfg.Docker.TLSKey,
	})
	if err := dockerClient.Ping(); err != nil {
		eng.Logs.Warnf("Docker: connection failed: %v (auto-discovery disabled)", err)
		return nil
	}

	dockerWatcher := dkr.NewWatcher(dockerClient, cfg.Docker.LabelPrefix, cfg.Docker.Network, cfg.Docker.PollInterval)
	dockerWatcher.SetLogger(eng.Logs.Add)
	dockerWatcher.SetOnChange(func() {
		rebuildDockerProxyRuntime(
			cfg,
			eng,
			dash,
			dockerWatcher.Services(),
			proxyRouter,
			proxyHealthCheckers,
			proxyRuntimeMu,
			upstreamHandler,
			tenantMiddleware,
		)
	})
	dockerWatcher.Start()
	eng.Logs.Infof("Docker auto-discovery enabled (socket: %s, prefix: %s)", cfg.Docker.SocketPath, cfg.Docker.LabelPrefix)

	if dash != nil {
		dash.SetDockerWatcher(dockerWatcher)
	}
	return dockerWatcher
}

func rebuildDockerProxyRuntime(
	cfg *config.Config,
	eng *engine.Engine,
	dash *dashboard.Dashboard,
	services []dkr.DiscoveredService,
	proxyRouter **proxy.Router,
	proxyHealthCheckers *[]*proxy.HealthChecker,
	proxyRuntimeMu *sync.RWMutex,
	upstreamHandler *atomic.Value,
	tenantMiddleware *tenant.Middleware,
) {
	mergedCfg := dkr.BuildConfig(services, cfg)
	newHandler, newHealthCheckers := buildReverseProxy(mergedCfg)
	newRouter, _ := newHandler.(*proxy.Router)

	var oldRouter *proxy.Router
	var oldHealthCheckers []*proxy.HealthChecker
	proxyRuntimeMu.Lock()
	oldRouter = *proxyRouter
	oldHealthCheckers = *proxyHealthCheckers
	*proxyRouter = newRouter
	*proxyHealthCheckers = newHealthCheckers
	proxyRuntimeMu.Unlock()

	wireDashboardUpstreamStatus(dash, newRouter)

	wrappedHandler := eng.Middleware(newHandler)
	if tenantMiddleware != nil {
		wrappedHandler = tenantMiddleware.Handler(wrappedHandler)
	}
	upstreamHandler.Store(wrappedHandler)
	stopHealthCheckers(oldHealthCheckers)
	closeProxyRouter(oldRouter)
	eng.Logs.Infof("Docker: proxy rebuilt (%d services discovered)", len(services))
}
