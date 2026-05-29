package main

import (
	"fmt"
	"log/slog"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// addLayers wires all WAF layers to the engine based on config.
func addLayers(eng *engine.Engine, cfg *config.Config) {
	eng.Logs.Add("info", fmt.Sprintf("Effective WAF pipeline: %v", layerregistry.PipelineSummary(cfg)))
	buildCtx := &layerregistry.BuildContext{}

	// 1. IP ACL layer (Order 100)
	if layer, ok, err := layerregistry.BuildLayerWithContext("ip_acl", cfg, buildCtx); err != nil {
		slog.Warn("failed to create IP ACL layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}

	// 1b. Threat Intelligence layer (Order 125)
	if layer, ok, err := layerregistry.BuildLayerWithContext("threat_intelligence", cfg, buildCtx); err != nil {
		slog.Warn("failed to create threat intel layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("Threat intelligence layer enabled")
	}

	// 1c. CORS Security layer (Order 150)
	if layer, ok, err := layerregistry.BuildLayer("cors", cfg); err != nil {
		slog.Warn("failed to create CORS layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Infof("CORS security enabled (%d allowed origins)", len(cfg.WAF.CORS.AllowOrigins))
	}

	// 1d. Custom Rules layer (Order 150)
	if cfg.WAF.CustomRules.Enabled && cfg.WAF.GeoIP.Enabled {
		buildCtx.GeoIPDB, _ = loadGeoIP(cfg, eng) // nolint:errcheck // GeoIPDB non-fatal; layer logs warning and proceeds
	}
	if layer, ok, err := layerregistry.BuildLayerWithContext("custom_rules", cfg, buildCtx); err != nil {
		slog.Warn("failed to create custom rules layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Infof("Custom rules: %d rules loaded", len(cfg.WAF.CustomRules.Rules))
	}

	// 2. Rate Limit layer (Order 200)
	if layer, ok, err := layerregistry.BuildLayerWithContext("rate_limit", cfg, buildCtx); err != nil {
		slog.Warn("failed to create rate limit layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}

	// 2b. ATO Protection layer (Order 250)
	if layer, ok, err := layerregistry.BuildLayer("ato_protection", cfg); err != nil {
		slog.Warn("failed to create ATO protection layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Infof("ATO protection enabled (%d login paths)", len(cfg.WAF.ATOProtection.LoginPaths))
	}

	// 2c. API Security layer (Order 275)
	if layer, ok, err := layerregistry.BuildLayer("api_security", cfg); err != nil {
		slog.Warn("failed to create API security layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("API security layer enabled")
	}

	// 2.5. API Validation layer (Order 280) - OpenAPI schema validation
	if layer, ok, err := layerregistry.BuildLayer("api_validation", cfg); err != nil {
		slog.Warn("failed to create API validation layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("API validation layer enabled")
	}

	// 3. Sanitizer layer (Order 300)
	if layer, ok, err := layerregistry.BuildLayer("sanitizer", cfg); err != nil {
		slog.Warn("failed to create sanitizer layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}

	// 3.5. CRS Layer (Order 350) - OWASP Core Rule Set
	if layer, ok, err := layerregistry.BuildLayer("crs", cfg); err != nil {
		slog.Warn("failed to create CRS layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("CRS layer enabled")
	}

	// 4. Detection layer (Order 400)
	if layer, ok, err := layerregistry.BuildLayer("detection", cfg); err != nil {
		slog.Warn("failed to create detection layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}

	// 4.5. Virtual Patch layer (Order 450) - CVE-based virtual patching
	if layer, ok, err := layerregistry.BuildLayer("virtual_patch", cfg); err != nil {
		slog.Warn("failed to create virtual patch layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("Virtual patch layer enabled")
	}

	// 4.75. DLP Layer (Order 475) - Data Loss Prevention
	if layer, ok, err := layerregistry.BuildLayer("dlp", cfg); err != nil {
		slog.Warn("failed to create DLP layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("DLP layer enabled")
	}

	// 5. Bot Detection layer (Order 500)
	if layer, ok, err := layerregistry.BuildLayer("bot_detection", cfg); err != nil {
		slog.Warn("failed to create bot detection layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}

	// 5.5. Client-side protection layer (Order 590) - Magecart detection and CSP
	if layer, ok, err := layerregistry.BuildLayer("client_side", cfg); err != nil {
		slog.Warn("failed to create client-side protection layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
		eng.Logs.Info("Client-side protection layer enabled")
	}

	// 6. Response layer (Order 600)
	if layer, ok, err := layerregistry.BuildLayer("response", cfg); err != nil {
		slog.Warn("failed to create response layer", "error", err)
	} else if ok {
		eng.AddLayer(layer)
	}
	buildCtx.RunStartHooks()
	eng.Logs.Add("info", fmt.Sprintf("Active WAF pipeline: %v", eng.PipelineLayers()))
}
