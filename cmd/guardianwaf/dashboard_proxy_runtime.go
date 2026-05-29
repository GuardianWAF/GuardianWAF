package main

import (
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

type certStatusProvider interface {
	CertStatus() map[string]any
}

func wireDashboardProxyControls(
	dash *dashboard.Dashboard,
	cfg *config.Config,
	eng *engine.Engine,
	cfgPath string,
	proxyRouter **proxy.Router,
	proxyHealthCheckers *[]*proxy.HealthChecker,
	proxyRuntimeMu *sync.RWMutex,
	upstreamHandler *atomic.Value,
	diskStore certStatusProvider,
) {
	if dash == nil {
		return
	}

	wireDashboardUpstreamStatus(dash, *proxyRouter)
	if diskStore != nil {
		dash.SetCertFn(func() any {
			return diskStore.CertStatus()
		})
	}

	dash.SetRoutingController(dashboard.RoutingControllerFuncs{
		RebuildFn: func() error {
			newHandler, newHealthCheckers := buildReverseProxy(cfg)
			newRouter, _ := newHandler.(*proxy.Router)
			var oldHealthCheckers []*proxy.HealthChecker

			proxyRuntimeMu.Lock()
			oldHealthCheckers = *proxyHealthCheckers
			*proxyRouter = newRouter
			*proxyHealthCheckers = newHealthCheckers
			proxyRuntimeMu.Unlock()

			wireDashboardUpstreamStatus(dash, newRouter)
			upstreamHandler.Store(eng.Middleware(newHandler))
			stopHealthCheckers(oldHealthCheckers)
			return nil
		},
		SaveFn: func() error {
			c := eng.Config()
			syncCustomRulesToConfig(eng, c)
			return config.SaveFile(cfgPath, c)
		},
	})
}

func wireDashboardUpstreamStatus(dash *dashboard.Dashboard, router *proxy.Router) {
	if dash == nil || router == nil {
		return
	}
	dash.SetUpstreamsFn(func() any {
		return router.AllUpstreamStatus()
	})
}

func syncCustomRulesToConfig(eng *engine.Engine, cfg *config.Config) {
	rl := eng.FindLayer("rules")
	if rl == nil {
		return
	}
	type rulesGetter interface{ Rules() []rules.Rule }
	rg, ok := rl.(rulesGetter)
	if !ok {
		return
	}

	liveRules := rg.Rules()
	cfgRules := make([]config.CustomRule, len(liveRules))
	for i, r := range liveRules {
		conds := make([]config.RuleCondition, len(r.Conditions))
		for j, cond := range r.Conditions {
			conds[j] = config.RuleCondition{Field: cond.Field, Op: cond.Op, Value: cond.Value}
		}
		cfgRules[i] = config.CustomRule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Enabled,
			Priority:   r.Priority,
			Conditions: conds,
			Action:     r.Action,
			Score:      r.Score,
		}
	}
	cfg.WAF.CustomRules.Enabled = len(cfgRules) > 0
	cfg.WAF.CustomRules.Rules = cfgRules
}

func loadHTTPHandler(value *atomic.Value) http.Handler {
	if value == nil {
		return nil
	}
	handler, _ := value.Load().(http.Handler)
	return handler
}
