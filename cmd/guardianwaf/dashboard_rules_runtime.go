package main

import (
	"fmt"
	"net"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
)

func wireDashboardRules(dash *dashboard.Dashboard, cfg *config.Config, eng *engine.Engine) {
	if dash == nil {
		return
	}

	rLayer := dashboardRulesLayer(eng)
	gDB := dashboardGeoIPDB(cfg, eng)

	dash.SetRulesFns(
		func() any { return rLayer.Rules() },
		func(raw map[string]any) error {
			r := mapToRule(raw)
			if r.ID == "" {
				return fmt.Errorf("rule id is required")
			}
			rLayer.AddRule(r)
			return nil
		},
		func(id string, raw map[string]any) error {
			r := mapToRule(raw)
			r.ID = id
			if !rLayer.UpdateRule(r) {
				return fmt.Errorf("rule %s not found", id)
			}
			return nil
		},
		func(id string) bool { return rLayer.RemoveRule(id) },
		func(id string, enabled bool) bool { return rLayer.ToggleRule(id, enabled) },
		func(ip string) (string, string) {
			return lookupDashboardGeoIP(gDB, ip)
		},
	)
}

func dashboardRulesLayer(eng *engine.Engine) *rules.Layer {
	if rl := eng.FindLayer("rules"); rl != nil {
		if rLayer, ok := rl.(*rules.Layer); ok {
			return rLayer
		}
	}
	rLayer := rules.NewLayer(&rules.Config{Enabled: true}, nil)
	eng.AddLayer(engine.OrderedLayer{Layer: rLayer, Order: engine.OrderRules})
	return rLayer
}

func dashboardGeoIPDB(cfg *config.Config, eng *engine.Engine) *geoip.DB {
	if !cfg.WAF.GeoIP.Enabled {
		return nil
	}
	gDB, _ := loadGeoIP(cfg, eng)
	if gDB == nil {
		return nil
	}
	engine.SetGeoIPLookup(func(ip string) (string, string) {
		return lookupDashboardGeoIP(gDB, ip)
	})
	return gDB
}

func lookupDashboardGeoIP(gDB *geoip.DB, ip string) (string, string) {
	if gDB == nil {
		return "", "GeoIP not loaded"
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "invalid IP"
	}
	code := gDB.Lookup(parsed)
	return code, geoip.CountryName(code)
}
