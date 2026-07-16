package dashboard

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// registerConfig registers config routes.
func (d *Dashboard) registerConfig(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/config", d.authWrap(d.handleGetConfig))
	mux.HandleFunc("PUT /api/v1/config", d.authWrap(d.handleUpdateConfig))
	mux.HandleFunc("GET /api/v1/config/ratelimit", d.authWrap(d.handleGetRateLimitConfig))
	mux.HandleFunc("PUT /api/v1/config/ratelimit", d.authWrap(d.handleUpdateRateLimitConfig))
	mux.HandleFunc("GET /api/v1/config/bot", d.authWrap(d.handleGetBotConfig))
	mux.HandleFunc("PUT /api/v1/config/bot", d.authWrap(d.handleUpdateBotConfig))
	mux.HandleFunc("POST /api/v1/config/reload", d.authWrap(d.handleReloadConfig))
	mux.HandleFunc("OPTIONS /api/v1/config", handleCORS)
	mux.HandleFunc("POST /api/v1/cwv", d.handleCWVReport)
	mux.HandleFunc("GET /api/v1/cwv", d.authWrap(d.handleGetCWV))
}

// --- Config Handlers ---

func (d *Dashboard) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := d.engine.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode": cfg.Mode,
		"tls": map[string]any{
			"enabled":         cfg.TLS.Enabled,
			"listen":          cfg.TLS.Listen,
			"cert_configured": cfg.TLS.CertFile != "",
			"key_configured":  cfg.TLS.KeyFile != "",
			"http_redirect":   cfg.TLS.HTTPRedirect,
			"acme": map[string]any{
				"enabled": cfg.TLS.ACME.Enabled,
				"domains": cfg.TLS.ACME.Domains,
			},
		},
		"waf": map[string]any{
			"ip_acl": map[string]any{
				"enabled":   cfg.WAF.IPACL.Enabled,
				"whitelist": cfg.WAF.IPACL.Whitelist,
				"blacklist": cfg.WAF.IPACL.Blacklist,
				"auto_ban": map[string]any{
					"enabled":     cfg.WAF.IPACL.AutoBan.Enabled,
					"default_ttl": cfg.WAF.IPACL.AutoBan.DefaultTTL.String(),
					"max_ttl":     cfg.WAF.IPACL.AutoBan.MaxTTL.String(),
				},
			},
			"rate_limit": map[string]any{
				"enabled": cfg.WAF.RateLimit.Enabled,
				"rules":   cfg.WAF.RateLimit.Rules,
			},
			"sanitizer": map[string]any{
				"enabled":            cfg.WAF.Sanitizer.Enabled,
				"max_url_length":     cfg.WAF.Sanitizer.MaxURLLength,
				"max_header_size":    cfg.WAF.Sanitizer.MaxHeaderSize,
				"max_header_count":   cfg.WAF.Sanitizer.MaxHeaderCount,
				"max_body_size":      cfg.WAF.Sanitizer.MaxBodySize,
				"max_cookie_size":    cfg.WAF.Sanitizer.MaxCookieSize,
				"block_null_bytes":   cfg.WAF.Sanitizer.BlockNullBytes,
				"normalize_encoding": cfg.WAF.Sanitizer.NormalizeEncoding,
			},
			"detection": map[string]any{
				"enabled": cfg.WAF.Detection.Enabled,
				"threshold": map[string]any{
					"block": cfg.WAF.Detection.Threshold.Block,
					"log":   cfg.WAF.Detection.Threshold.Log,
				},
				"detectors": cfg.WAF.Detection.Detectors,
			},
			"bot_detection": map[string]any{
				"enabled": cfg.WAF.BotDetection.Enabled,
				"mode":    cfg.WAF.BotDetection.Mode,
				"tls_fingerprint": map[string]any{
					"enabled": cfg.WAF.BotDetection.TLSFingerprint.Enabled,
				},
				"user_agent": map[string]any{
					"enabled":              cfg.WAF.BotDetection.UserAgent.Enabled,
					"block_empty":          cfg.WAF.BotDetection.UserAgent.BlockEmpty,
					"block_known_scanners": cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
				},
				"behavior": map[string]any{
					"enabled":              cfg.WAF.BotDetection.Behavior.Enabled,
					"window":               cfg.WAF.BotDetection.Behavior.Window.String(),
					"rps_threshold":        cfg.WAF.BotDetection.Behavior.RPSThreshold,
					"error_rate_threshold": cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
				},
			},
			"challenge": map[string]any{
				"enabled":     cfg.WAF.Challenge.Enabled,
				"difficulty":  cfg.WAF.Challenge.Difficulty,
				"cookie_ttl":  cfg.WAF.Challenge.CookieTTL.String(),
				"cookie_name": cfg.WAF.Challenge.CookieName,
			},
			"response": map[string]any{
				"security_headers": map[string]any{
					"enabled":                cfg.WAF.Response.SecurityHeaders.Enabled,
					"x_frame_options":        cfg.WAF.Response.SecurityHeaders.XFrameOptions,
					"referrer_policy":        cfg.WAF.Response.SecurityHeaders.ReferrerPolicy,
					"x_content_type_options": cfg.WAF.Response.SecurityHeaders.XContentTypeOptions,
					"hsts": map[string]any{
						"enabled":            cfg.WAF.Response.SecurityHeaders.HSTS.Enabled,
						"max_age":            cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge,
						"include_subdomains": cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains,
					},
				},
				"data_masking": map[string]any{
					"enabled":            cfg.WAF.Response.DataMasking.Enabled,
					"mask_credit_cards":  cfg.WAF.Response.DataMasking.MaskCreditCards,
					"mask_ssn":           cfg.WAF.Response.DataMasking.MaskSSN,
					"mask_api_keys":      cfg.WAF.Response.DataMasking.MaskAPIKeys,
					"strip_stack_traces": cfg.WAF.Response.DataMasking.StripStackTraces,
				},
			},
			"cors": map[string]any{
				"enabled":           cfg.WAF.CORS.Enabled,
				"allow_origins":     cfg.WAF.CORS.AllowOrigins,
				"allow_methods":     cfg.WAF.CORS.AllowMethods,
				"allow_headers":     cfg.WAF.CORS.AllowHeaders,
				"allow_credentials": cfg.WAF.CORS.AllowCredentials,
				"strict_mode":       cfg.WAF.CORS.StrictMode,
			},
			"threat_intel": map[string]any{
				"enabled":    cfg.WAF.ThreatIntel.Enabled,
				"cache_size": cfg.WAF.ThreatIntel.CacheSize,
				"ip_reputation": map[string]any{
					"enabled":         cfg.WAF.ThreatIntel.IPReputation.Enabled,
					"block_malicious": cfg.WAF.ThreatIntel.IPReputation.BlockMalicious,
					"score_threshold": cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold,
				},
				"domain_reputation": map[string]any{
					"enabled":         cfg.WAF.ThreatIntel.DomainRep.Enabled,
					"block_malicious": cfg.WAF.ThreatIntel.DomainRep.BlockMalicious,
				},
			},
			"ato_protection": map[string]any{
				"enabled":     cfg.WAF.ATOProtection.Enabled,
				"login_paths": cfg.WAF.ATOProtection.LoginPaths,
				"brute_force": map[string]any{
					"enabled":                cfg.WAF.ATOProtection.BruteForce.Enabled,
					"max_attempts_per_ip":    cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP,
					"max_attempts_per_email": cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail,
				},
				"credential_stuffing": map[string]any{
					"enabled":               cfg.WAF.ATOProtection.CredStuffing.Enabled,
					"distributed_threshold": cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold,
				},
				"impossible_travel": map[string]any{
					"enabled":         cfg.WAF.ATOProtection.Travel.Enabled,
					"max_distance_km": cfg.WAF.ATOProtection.Travel.MaxDistanceKm,
				},
			},
			"api_security": map[string]any{
				"enabled": cfg.WAF.APISecurity.Enabled,
				"jwt": map[string]any{
					"enabled":    cfg.WAF.APISecurity.JWT.Enabled,
					"issuer":     cfg.WAF.APISecurity.JWT.Issuer,
					"audience":   cfg.WAF.APISecurity.JWT.Audience,
					"algorithms": cfg.WAF.APISecurity.JWT.Algorithms,
					"jwks_url":   cfg.WAF.APISecurity.JWT.JWKSURL,
				},
				"api_keys": map[string]any{
					"enabled":     cfg.WAF.APISecurity.APIKeys.Enabled,
					"header_name": cfg.WAF.APISecurity.APIKeys.HeaderName,
					"key_count":   len(cfg.WAF.APISecurity.APIKeys.Keys),
				},
			},
		},
		"docker": map[string]any{
			"enabled":       cfg.Docker.Enabled,
			"socket_path":   cfg.Docker.SocketPath,
			"label_prefix":  cfg.Docker.LabelPrefix,
			"poll_interval": cfg.Docker.PollInterval.String(),
			"network":       cfg.Docker.Network,
		},
		"ai_analysis": map[string]any{
			"enabled":    cfg.WAF.AIAnalysis.Enabled,
			"batch_size": cfg.WAF.AIAnalysis.BatchSize,
			"min_score":  cfg.WAF.AIAnalysis.MinScore,
			"auto_block": cfg.WAF.AIAnalysis.AutoBlock,
		},
		"alerting": map[string]any{
			"enabled":       cfg.Alerting.Enabled,
			"webhook_count": len(cfg.Alerting.Webhooks),
		},
	})
}

func (d *Dashboard) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if !limitedDecodeJSON(w, r, &patch) {
		return
	}

	// Copy config to avoid mutating shared state without a lock and retain a
	// rollback snapshot if durable persistence fails.
	oldCfg := d.engine.Config()
	cfg := deepCopyConfig(oldCfg)

	// Apply top-level mode
	if v, ok := patch["mode"].(string); ok {
		cfg.Mode = v
	}

	// Apply TLS section patches
	if tls, ok := patch["tls"].(map[string]any); ok {
		if v, ok := tls["enabled"].(bool); ok {
			cfg.TLS.Enabled = v
		}
		if v, ok := tls["listen"].(string); ok {
			cfg.TLS.Listen = v
		}
		if v, ok := tls["cert_file"].(string); ok {
			cfg.TLS.CertFile = v
		}
		if v, ok := tls["key_file"].(string); ok {
			cfg.TLS.KeyFile = v
		}
		if v, ok := tls["http_redirect"].(bool); ok {
			cfg.TLS.HTTPRedirect = v
		}
		if acme, ok := tls["acme"].(map[string]any); ok {
			if v, ok := acme["enabled"].(bool); ok {
				cfg.TLS.ACME.Enabled = v
			}
			if v, ok := acme["email"].(string); ok {
				cfg.TLS.ACME.Email = v
			}
			if v, ok := acme["cache_dir"].(string); ok {
				cfg.TLS.ACME.CacheDir = v
			}
		}
	}

	// Apply WAF section patches
	if waf, ok := patch["waf"].(map[string]any); ok {
		applyWAFPatch(cfg, waf)
	}

	// Apply Docker section patches
	if docker, ok := patch["docker"].(map[string]any); ok {
		if v, ok := docker["enabled"].(bool); ok {
			cfg.Docker.Enabled = v
		}
		if v, ok := docker["socket_path"].(string); ok {
			cfg.Docker.SocketPath = v
		}
		if v, ok := docker["label_prefix"].(string); ok {
			cfg.Docker.LabelPrefix = v
		}
		if v, ok := docker["network"].(string); ok {
			cfg.Docker.Network = v
		}
	}

	// Apply AI Analysis section patches
	if ai, ok := patch["ai_analysis"].(map[string]any); ok {
		if v, ok := ai["enabled"].(bool); ok {
			cfg.WAF.AIAnalysis.Enabled = v
		}
		if v, ok := ai["batch_size"].(float64); ok {
			cfg.WAF.AIAnalysis.BatchSize = int(v)
		}
		if v, ok := ai["min_score"].(float64); ok {
			cfg.WAF.AIAnalysis.MinScore = int(v)
		}
		if v, ok := ai["auto_block"].(bool); ok {
			cfg.WAF.AIAnalysis.AutoBlock = v
		}
	}

	// Apply Alerting section patches
	if alerting, ok := patch["alerting"].(map[string]any); ok {
		if v, ok := alerting["enabled"].(bool); ok {
			cfg.Alerting.Enabled = v
		}
	}

	// Audit log for security-critical config changes
	d.logSecurityConfigChanges(oldCfg, cfg, r)

	if err := validateRuntimeReloadableConfig(oldCfg, cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}

	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}

	// Persist to disk
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Save(); err != nil {
			if rollbackErr := d.engine.Reload(oldCfg); rollbackErr != nil {
				dashboardLog.Error("configuration persistence and rollback failed", "save_error", err, "rollback_error", rollbackErr)
			} else {
				dashboardLog.Error("configuration persistence failed; runtime rolled back", "error", err)
			}
			writeError(w, http.StatusInternalServerError, "configuration persistence failed; previous runtime configuration restored")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration updated and saved"})
}

func (d *Dashboard) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	cfg := deepCopyConfig(d.engine.Config())
	if err := validateRuntimeReloadableConfig(d.engine.Config(), cfg); err != nil {
		writeError(w, http.StatusConflict, sanitizeErr(err))
		return
	}
	if err := d.engine.Reload(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, sanitizeErr(err))
		return
	}
	if d.routingCtrl != nil {
		if err := d.routingCtrl.Rebuild(); err != nil {
			writeError(w, http.StatusInternalServerError, "proxy rebuild failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Configuration reloaded"})
}

func validateRuntimeReloadableConfig(oldCfg, newCfg *config.Config) error {
	if oldCfg == nil || newCfg == nil {
		return nil
	}

	changed := make([]string, 0)
	addBoolChange := func(path string, oldValue, newValue bool) {
		if oldValue != newValue {
			changed = append(changed, path)
		}
	}

	addBoolChange("waf.ip_acl.enabled", oldCfg.WAF.IPACL.Enabled, newCfg.WAF.IPACL.Enabled)
	addBoolChange("waf.threat_intel.enabled", oldCfg.WAF.ThreatIntel.Enabled, newCfg.WAF.ThreatIntel.Enabled)
	addBoolChange("waf.cors.enabled", oldCfg.WAF.CORS.Enabled, newCfg.WAF.CORS.Enabled)
	addBoolChange("waf.custom_rules.enabled", oldCfg.WAF.CustomRules.Enabled, newCfg.WAF.CustomRules.Enabled)
	addBoolChange("waf.rate_limit.enabled", oldCfg.WAF.RateLimit.Enabled, newCfg.WAF.RateLimit.Enabled)
	addBoolChange("waf.ato_protection.enabled", oldCfg.WAF.ATOProtection.Enabled, newCfg.WAF.ATOProtection.Enabled)
	addBoolChange("waf.api_security.enabled", oldCfg.WAF.APISecurity.Enabled, newCfg.WAF.APISecurity.Enabled)
	addBoolChange("waf.api_validation.enabled", oldCfg.WAF.APIValidation.Enabled, newCfg.WAF.APIValidation.Enabled)
	addBoolChange("waf.sanitizer.enabled", oldCfg.WAF.Sanitizer.Enabled, newCfg.WAF.Sanitizer.Enabled)
	addBoolChange("waf.crs.enabled", oldCfg.WAF.CRS.Enabled, newCfg.WAF.CRS.Enabled)
	addBoolChange("waf.detection.enabled", oldCfg.WAF.Detection.Enabled, newCfg.WAF.Detection.Enabled)
	addBoolChange("waf.virtual_patch.enabled", oldCfg.WAF.VirtualPatch.Enabled, newCfg.WAF.VirtualPatch.Enabled)
	addBoolChange("waf.dlp.enabled", oldCfg.WAF.DLP.Enabled, newCfg.WAF.DLP.Enabled)
	addBoolChange("waf.bot_detection.enabled", oldCfg.WAF.BotDetection.Enabled, newCfg.WAF.BotDetection.Enabled)
	addBoolChange("waf.client_side.enabled", oldCfg.WAF.ClientSide.Enabled, newCfg.WAF.ClientSide.Enabled)

	if len(changed) == 0 {
		return validateRuntimeReloadableWAFConfig(oldCfg, newCfg)
	}
	return fmt.Errorf("runtime reload cannot change WAF layer topology (%s); update the config file and restart GuardianWAF", strings.Join(changed, ", "))
}

func validateRuntimeReloadableWAFConfig(oldCfg, newCfg *config.Config) error {
	oldWAF := reloadGuardWAFShape(oldCfg)
	newWAF := reloadGuardWAFShape(newCfg)

	if reflect.DeepEqual(oldWAF, newWAF) {
		return nil
	}
	return fmt.Errorf("runtime reload cannot change WAF layer configuration without rebuilding the pipeline; update the config file and restart GuardianWAF")
}

func reloadGuardWAFShape(cfg *config.Config) any {
	waf := cfg.DeepCopy().WAF

	// These fields are consumed through Engine atomics and do not require
	// rebuilding layer instances.
	waf.Detection.Threshold = config.ThresholdConfig{}
	waf.Sanitizer.MaxBodySize = 0

	return struct {
		IPACL         config.IPACLConfig
		ThreatIntel   config.ThreatIntelConfig
		CORS          config.CORSConfig
		CustomRules   config.CustomRulesConfig
		RateLimit     config.RateLimitConfig
		ATOProtection config.ATOProtectionConfig
		APISecurity   config.APISecurityConfig
		APIValidation config.APIValidationConfig
		Sanitizer     config.SanitizerConfig
		CRS           config.CRSConfig
		Detection     config.DetectionConfig
		VirtualPatch  config.VirtualPatchConfig
		DLP           config.DLPConfig
		BotDetection  config.BotDetectionConfig
		ClientSide    config.ClientSideConfig
		Response      config.ResponseConfig
	}{
		IPACL:         waf.IPACL,
		ThreatIntel:   waf.ThreatIntel,
		CORS:          waf.CORS,
		CustomRules:   waf.CustomRules,
		RateLimit:     waf.RateLimit,
		ATOProtection: waf.ATOProtection,
		APISecurity:   waf.APISecurity,
		APIValidation: waf.APIValidation,
		Sanitizer:     waf.Sanitizer,
		CRS:           waf.CRS,
		Detection:     waf.Detection,
		VirtualPatch:  waf.VirtualPatch,
		DLP:           waf.DLP,
		BotDetection:  waf.BotDetection,
		ClientSide:    waf.ClientSide,
		Response:      waf.Response,
	}
}

// applyWAFPatch applies partial config updates from a JSON patch object.
func applyWAFPatch(cfg *config.Config, waf map[string]any) {
	if det, ok := waf["detection"].(map[string]any); ok {
		if v, ok := det["enabled"].(bool); ok {
			cfg.WAF.Detection.Enabled = v
		}
		if th, ok := det["threshold"].(map[string]any); ok {
			if v, ok := th["block"].(float64); ok {
				cfg.WAF.Detection.Threshold.Block = clampInt(int(v), 1, 1000)
			}
			if v, ok := th["log"].(float64); ok {
				cfg.WAF.Detection.Threshold.Log = clampInt(int(v), 0, 1000)
			}
		}
		if detectors, ok := det["detectors"].(map[string]any); ok {
			for name, raw := range detectors {
				d, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				dc := cfg.WAF.Detection.Detectors[name]
				if v, ok := d["enabled"].(bool); ok {
					dc.Enabled = v
				}
				if v, ok := d["multiplier"].(float64); ok {
					dc.Multiplier = clampFloat(v, 0.1, 10.0)
				}
				cfg.WAF.Detection.Detectors[name] = dc
			}
		}
	}

	if rl, ok := waf["rate_limit"].(map[string]any); ok {
		if v, ok := rl["enabled"].(bool); ok {
			cfg.WAF.RateLimit.Enabled = v
		}
	}

	if san, ok := waf["sanitizer"].(map[string]any); ok {
		if v, ok := san["enabled"].(bool); ok {
			cfg.WAF.Sanitizer.Enabled = v
		}
		if v, ok := san["max_body_size"].(float64); ok {
			cfg.WAF.Sanitizer.MaxBodySize = clampInt64(int64(v), 0, 100<<20)
		}
		if v, ok := san["max_url_length"].(float64); ok {
			cfg.WAF.Sanitizer.MaxURLLength = clampInt(int(v), 64, 65535)
		}
	}

	if bd, ok := waf["bot_detection"].(map[string]any); ok {
		if v, ok := bd["enabled"].(bool); ok {
			cfg.WAF.BotDetection.Enabled = v
		}
		if v, ok := bd["mode"].(string); ok {
			cfg.WAF.BotDetection.Mode = v
		}
		if ua, ok := bd["user_agent"].(map[string]any); ok {
			if v, ok := ua["block_empty"].(bool); ok {
				cfg.WAF.BotDetection.UserAgent.BlockEmpty = v
			}
			if v, ok := ua["block_known_scanners"].(bool); ok {
				cfg.WAF.BotDetection.UserAgent.BlockKnownScanners = v
			}
		}
		if beh, ok := bd["behavior"].(map[string]any); ok {
			if v, ok := beh["rps_threshold"].(float64); ok {
				cfg.WAF.BotDetection.Behavior.RPSThreshold = clampInt(int(v), 1, 100000)
			}
			if v, ok := beh["error_rate_threshold"].(float64); ok {
				cfg.WAF.BotDetection.Behavior.ErrorRateThreshold = clampInt(int(v), 1, 100)
			}
		}
	}

	if ch, ok := waf["challenge"].(map[string]any); ok {
		if v, ok := ch["enabled"].(bool); ok {
			cfg.WAF.Challenge.Enabled = v
		}
		if v, ok := ch["difficulty"].(float64); ok {
			cfg.WAF.Challenge.Difficulty = clampInt(int(v), 1, 5)
		}
	}

	if ipacl, ok := waf["ip_acl"].(map[string]any); ok {
		if v, ok := ipacl["enabled"].(bool); ok {
			cfg.WAF.IPACL.Enabled = v
		}
		if ab, ok := ipacl["auto_ban"].(map[string]any); ok {
			if v, ok := ab["enabled"].(bool); ok {
				cfg.WAF.IPACL.AutoBan.Enabled = v
			}
		}
	}

	if resp, ok := waf["response"].(map[string]any); ok {
		if sh, ok := resp["security_headers"].(map[string]any); ok {
			if v, ok := sh["enabled"].(bool); ok {
				cfg.WAF.Response.SecurityHeaders.Enabled = v
			}
		}
		if dm, ok := resp["data_masking"].(map[string]any); ok {
			if v, ok := dm["enabled"].(bool); ok {
				cfg.WAF.Response.DataMasking.Enabled = v
			}
			if v, ok := dm["mask_credit_cards"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskCreditCards = v
			}
			if v, ok := dm["mask_ssn"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskSSN = v
			}
			if v, ok := dm["mask_api_keys"].(bool); ok {
				cfg.WAF.Response.DataMasking.MaskAPIKeys = v
			}
			if v, ok := dm["strip_stack_traces"].(bool); ok {
				cfg.WAF.Response.DataMasking.StripStackTraces = v
			}
		}
	}

	// CORS Security
	if cors, ok := waf["cors"].(map[string]any); ok {
		if v, ok := cors["enabled"].(bool); ok {
			cfg.WAF.CORS.Enabled = v
		}
		if v, ok := cors["strict_mode"].(bool); ok {
			cfg.WAF.CORS.StrictMode = v
		}
		if v, ok := cors["allow_credentials"].(bool); ok {
			cfg.WAF.CORS.AllowCredentials = v
		}
	}

	// Threat Intelligence
	if ti, ok := waf["threat_intel"].(map[string]any); ok {
		if v, ok := ti["enabled"].(bool); ok {
			cfg.WAF.ThreatIntel.Enabled = v
		}
		if ipr, ok := ti["ip_reputation"].(map[string]any); ok {
			if v, ok := ipr["enabled"].(bool); ok {
				cfg.WAF.ThreatIntel.IPReputation.Enabled = v
			}
			if v, ok := ipr["block_malicious"].(bool); ok {
				cfg.WAF.ThreatIntel.IPReputation.BlockMalicious = v
			}
			if v, ok := ipr["score_threshold"].(float64); ok {
				cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold = clampInt(int(v), 0, 100)
			}
		}
		if dr, ok := ti["domain_reputation"].(map[string]any); ok {
			if v, ok := dr["enabled"].(bool); ok {
				cfg.WAF.ThreatIntel.DomainRep.Enabled = v
			}
			if v, ok := dr["block_malicious"].(bool); ok {
				cfg.WAF.ThreatIntel.DomainRep.BlockMalicious = v
			}
		}
	}

	// ATO Protection
	if ato, ok := waf["ato_protection"].(map[string]any); ok {
		if v, ok := ato["enabled"].(bool); ok {
			cfg.WAF.ATOProtection.Enabled = v
		}
		if bf, ok := ato["brute_force"].(map[string]any); ok {
			if v, ok := bf["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.BruteForce.Enabled = v
			}
			if v, ok := bf["max_attempts_per_ip"].(float64); ok {
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP = clampInt(int(v), 1, 10000)
			}
			if v, ok := bf["max_attempts_per_email"].(float64); ok {
				cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail = clampInt(int(v), 1, 10000)
			}
		}
		if cs, ok := ato["credential_stuffing"].(map[string]any); ok {
			if v, ok := cs["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.CredStuffing.Enabled = v
			}
			if v, ok := cs["distributed_threshold"].(float64); ok {
				cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold = clampInt(int(v), 1, 10000)
			}
		}
		if tr, ok := ato["impossible_travel"].(map[string]any); ok {
			if v, ok := tr["enabled"].(bool); ok {
				cfg.WAF.ATOProtection.Travel.Enabled = v
			}
			if v, ok := tr["max_distance_km"].(float64); ok {
				cfg.WAF.ATOProtection.Travel.MaxDistanceKm = clampFloat(v, 0, 20000)
			}
		}
	}

	// API Security
	if api, ok := waf["api_security"].(map[string]any); ok {
		if v, ok := api["enabled"].(bool); ok {
			cfg.WAF.APISecurity.Enabled = v
		}
		if jwt, ok := api["jwt"].(map[string]any); ok {
			if v, ok := jwt["enabled"].(bool); ok {
				cfg.WAF.APISecurity.JWT.Enabled = v
			}
			if v, ok := jwt["issuer"].(string); ok {
				cfg.WAF.APISecurity.JWT.Issuer = v
			}
			if v, ok := jwt["audience"].(string); ok {
				cfg.WAF.APISecurity.JWT.Audience = v
			}
		}
		if keys, ok := api["api_keys"].(map[string]any); ok {
			if v, ok := keys["enabled"].(bool); ok {
				cfg.WAF.APISecurity.APIKeys.Enabled = v
			}
			if v, ok := keys["header_name"].(string); ok {
				cfg.WAF.APISecurity.APIKeys.HeaderName = v
			}
		}
	}
}

// logSecurityConfigChanges logs when security features are disabled via the config API.
func (d *Dashboard) logSecurityConfigChanges(oldCfg, newCfg *config.Config, r *http.Request) {
	securityFields := []struct {
		name string
		old  bool
		new  bool
	}{
		{"detection", oldCfg.WAF.Detection.Enabled, newCfg.WAF.Detection.Enabled},
		{"rate_limit", oldCfg.WAF.RateLimit.Enabled, newCfg.WAF.RateLimit.Enabled},
		{"sanitizer", oldCfg.WAF.Sanitizer.Enabled, newCfg.WAF.Sanitizer.Enabled},
		{"bot_detection", oldCfg.WAF.BotDetection.Enabled, newCfg.WAF.BotDetection.Enabled},
		{"challenge", oldCfg.WAF.Challenge.Enabled, newCfg.WAF.Challenge.Enabled},
		{"ip_acl", oldCfg.WAF.IPACL.Enabled, newCfg.WAF.IPACL.Enabled},
		{"cors", oldCfg.WAF.CORS.Enabled, newCfg.WAF.CORS.Enabled},
		{"ato_protection", oldCfg.WAF.ATOProtection.Enabled, newCfg.WAF.ATOProtection.Enabled},
		{"api_security", oldCfg.WAF.APISecurity.Enabled, newCfg.WAF.APISecurity.Enabled},
		{"dlp", oldCfg.WAF.DLP.Enabled, newCfg.WAF.DLP.Enabled},
		{"ml_anomaly", oldCfg.WAF.MLAnomaly.Enabled, newCfg.WAF.MLAnomaly.Enabled},
		{"crs", oldCfg.WAF.CRS.Enabled, newCfg.WAF.CRS.Enabled},
	}
	clientIP := clientIPFromRequest(r)
	for _, f := range securityFields {
		if f.old && !f.new {
			dashboardLog.Warn("security feature disabled via config API",
				"feature", f.name,
				"client_ip", clientIP)
		}
	}
}
