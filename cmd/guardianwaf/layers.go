package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// addLayers wires all WAF layers to the engine based on config.
//
// Fail-closed policy: if an *enabled* security layer fails to build (e.g. an
// invalid CIDR in the IP ACL, a bad custom-rule regex, or an unloadable CRS
// ruleset), addLayers returns an error so the caller can refuse to start.
// A WAF that boots with a silently-missing protection layer is worse than one
// that refuses to boot. Operators who knowingly accept a degraded pipeline can
// set GWAF_ALLOW_DEGRADED_START=1 to downgrade the failure to a loud warning.
func addLayers(eng *engine.Engine, cfg *config.Config) error {
	eng.Logs.Add("info", fmt.Sprintf("Effective WAF pipeline: %v", layerregistry.PipelineSummary(cfg)))
	buildCtx := &layerregistry.BuildContext{}
	var buildErrs []error

	// add builds a layer by registry name and wires it into the engine. Build
	// errors are collected (not swallowed) so startup can fail closed.
	add := func(name string, withCtx bool, onSuccess func()) {
		var (
			layer engine.OrderedLayer
			ok    bool
			err   error
		)
		if withCtx {
			layer, ok, err = layerregistry.BuildLayerWithContext(name, cfg, buildCtx)
		} else {
			layer, ok, err = layerregistry.BuildLayer(name, cfg)
		}
		if err != nil {
			slog.Error("failed to create WAF layer", "layer", name, "error", err)
			buildErrs = append(buildErrs, fmt.Errorf("%s: %w", name, err))
			return
		}
		if ok {
			eng.AddLayer(layer)
			if onSuccess != nil {
				onSuccess()
			}
		}
	}

	add("ip_acl", true, nil)                                                                                                    // Order 100
	add("threat_intelligence", true, func() { eng.Logs.Info("Threat intelligence layer enabled") })                             // Order 125
	add("cors", false, func() { eng.Logs.Infof("CORS security enabled (%d allowed origins)", len(cfg.WAF.CORS.AllowOrigins)) }) // Order 150

	// Custom Rules layer (Order 150) — optionally GeoIP-aware.
	if cfg.WAF.CustomRules.Enabled && cfg.WAF.GeoIP.Enabled {
		buildCtx.GeoIPDB, _ = loadGeoIP(cfg, eng) // nolint:errcheck // GeoIPDB non-fatal; layer logs warning and proceeds
	}
	add("custom_rules", true, func() { eng.Logs.Infof("Custom rules: %d rules loaded", len(cfg.WAF.CustomRules.Rules)) })

	add("rate_limit", true, nil) // Order 200
	add("ato_protection", false, func() {
		eng.Logs.Infof("ATO protection enabled (%d login paths)", len(cfg.WAF.ATOProtection.LoginPaths))
	}) // Order 250
	add("api_security", false, func() { eng.Logs.Info("API security layer enabled") })          // Order 275
	add("api_validation", false, func() { eng.Logs.Info("API validation layer enabled") })      // Order 280
	add("sanitizer", false, nil)                                                                // Order 300
	add("crs", false, func() { eng.Logs.Info("CRS layer enabled") })                            // Order 350
	add("detection", false, nil)                                                                // Order 400
	add("virtual_patch", false, func() { eng.Logs.Info("Virtual patch layer enabled") })        // Order 450
	add("dlp", false, func() { eng.Logs.Info("DLP layer enabled") })                            // Order 475
	add("bot_detection", false, nil)                                                            // Order 500
	add("client_side", false, func() { eng.Logs.Info("Client-side protection layer enabled") }) // Order 590
	add("response", false, nil)                                                                 // Order 600

	buildCtx.RunStartHooks()
	eng.Logs.Add("info", fmt.Sprintf("Active WAF pipeline: %v", eng.PipelineLayers()))

	if len(buildErrs) > 0 {
		joined := errors.Join(buildErrs...)
		if allowDegradedStart() {
			slog.Warn("starting in DEGRADED mode: enabled security layers failed to build",
				"failed_count", len(buildErrs), "override", "GWAF_ALLOW_DEGRADED_START", "errors", joined)
			eng.Logs.Add("error", fmt.Sprintf("DEGRADED START: %d security layer(s) missing: %v", len(buildErrs), joined))
			return nil
		}
		return fmt.Errorf("refusing to start: %d enabled security layer(s) failed to build "+
			"(set GWAF_ALLOW_DEGRADED_START=1 to override and run with reduced protection): %w", len(buildErrs), joined)
	}
	return nil
}

// allowDegradedStart reports whether the operator has explicitly opted in to
// booting with one or more security layers missing.
func allowDegradedStart() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GWAF_ALLOW_DEGRADED_START"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
