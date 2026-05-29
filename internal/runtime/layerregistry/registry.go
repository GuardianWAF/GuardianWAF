package layerregistry

import (
	"fmt"
	"net"
	"sort"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/layers/apisecurity"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
	"github.com/guardianwaf/guardianwaf/internal/layers/ato"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
	"github.com/guardianwaf/guardianwaf/internal/layers/cors"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/response"
	"github.com/guardianwaf/guardianwaf/internal/layers/rules"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
	"github.com/guardianwaf/guardianwaf/internal/layers/threatintel"
	"github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch"
)

// Builder constructs an engine layer from application configuration.
type Builder func(*config.Config) (engine.Layer, error)

// ContextBuilder constructs an engine layer with access to build-time dependencies.
type ContextBuilder func(*BuildContext, *config.Config) (engine.Layer, error)

// BuildContext carries dependencies discovered while constructing an ordered layer pipeline.
type BuildContext struct {
	IPACLLayer *ipacl.Layer
	GeoIPDB    *geoip.DB
	StartHooks []StartHook
}

// StartHook is a lifecycle hook registered by a layer builder.
type StartHook struct {
	Name string
	Run  func()
}

// RunStartHooks starts every registered layer lifecycle hook in registration order.
func (c *BuildContext) RunStartHooks() {
	if c == nil {
		return
	}
	for _, hook := range c.StartHooks {
		if hook.Run != nil {
			hook.Run()
		}
	}
}

// Descriptor describes one configurable WAF pipeline layer.
type Descriptor struct {
	Name         string
	RuntimeName  string
	Order        int
	Enabled      func(*config.Config) bool
	Build        Builder
	ContextBuild ContextBuilder
}

// PipelineEntry is the effective enabled view of a Descriptor for one config.
type PipelineEntry struct {
	Name        string
	RuntimeName string
	Order       int
}

// DefaultRegistry returns the standalone WAF layer registry in engine order.
func DefaultRegistry() []Descriptor {
	return []Descriptor{
		{Name: "ip_acl", RuntimeName: "ipacl", Order: engine.OrderIPACL, Enabled: func(cfg *config.Config) bool { return cfg.WAF.IPACL.Enabled }, ContextBuild: buildIPACL},
		{Name: "threat_intelligence", RuntimeName: "threat_intel", Order: engine.OrderThreatIntel, Enabled: func(cfg *config.Config) bool { return cfg.WAF.ThreatIntel.Enabled }, ContextBuild: buildThreatIntel},
		{Name: "cors", RuntimeName: "cors", Order: engine.OrderCORS, Enabled: func(cfg *config.Config) bool { return cfg.WAF.CORS.Enabled }, Build: buildCORS},
		{Name: "custom_rules", RuntimeName: "rules", Order: engine.OrderRules, Enabled: func(cfg *config.Config) bool { return cfg.WAF.CustomRules.Enabled }, ContextBuild: buildCustomRules},
		{Name: "rate_limit", RuntimeName: "ratelimit", Order: engine.OrderRateLimit, Enabled: func(cfg *config.Config) bool { return cfg.WAF.RateLimit.Enabled }, ContextBuild: buildRateLimit},
		{Name: "ato_protection", RuntimeName: "ato_protection", Order: engine.OrderATO, Enabled: func(cfg *config.Config) bool { return cfg.WAF.ATOProtection.Enabled }, Build: buildATOProtection},
		{Name: "api_security", RuntimeName: "api_security", Order: engine.OrderAPISecurity, Enabled: func(cfg *config.Config) bool { return cfg.WAF.APISecurity.Enabled }, Build: buildAPISecurity},
		{Name: "api_validation", RuntimeName: "apivalidation", Order: engine.OrderAPIValidation, Enabled: func(cfg *config.Config) bool { return cfg.WAF.APIValidation.Enabled }, Build: buildAPIValidation},
		{Name: "sanitizer", RuntimeName: "sanitizer", Order: engine.OrderSanitizer, Enabled: func(cfg *config.Config) bool { return cfg.WAF.Sanitizer.Enabled }, Build: buildSanitizer},
		{Name: "crs", RuntimeName: "crs", Order: engine.OrderCRS, Enabled: func(cfg *config.Config) bool { return cfg.WAF.CRS.Enabled }, Build: buildCRS},
		{Name: "detection", RuntimeName: "detection", Order: engine.OrderDetection, Enabled: func(cfg *config.Config) bool { return cfg.WAF.Detection.Enabled }, Build: buildDetection},
		{Name: "virtual_patch", RuntimeName: "virtualpatch", Order: engine.OrderVirtualPatch, Enabled: func(cfg *config.Config) bool { return cfg.WAF.VirtualPatch.Enabled }, Build: buildVirtualPatch},
		{Name: "dlp", RuntimeName: "dlp", Order: engine.OrderDLP, Enabled: func(cfg *config.Config) bool { return cfg.WAF.DLP.Enabled }, Build: buildDLP},
		{Name: "bot_detection", RuntimeName: "botdetect", Order: engine.OrderBotDetect, Enabled: func(cfg *config.Config) bool { return cfg.WAF.BotDetection.Enabled }, Build: buildBotDetection},
		{Name: "client_side", RuntimeName: "clientside", Order: engine.OrderClientSide, Enabled: func(cfg *config.Config) bool { return cfg.WAF.ClientSide.Enabled }, Build: buildClientSide},
		{Name: "response", RuntimeName: "response", Order: engine.OrderResponse, Enabled: func(*config.Config) bool { return true }, Build: buildResponse},
	}
}

// BuildLayer constructs a layer by descriptor name when it is enabled and buildable.
func BuildLayer(name string, cfg *config.Config) (engine.OrderedLayer, bool, error) {
	return BuildLayerWithContext(name, cfg, nil)
}

// BuildLayerWithContext constructs a layer by descriptor name using optional build-time dependencies.
func BuildLayerWithContext(name string, cfg *config.Config, ctx *BuildContext) (engine.OrderedLayer, bool, error) {
	if cfg == nil {
		return engine.OrderedLayer{}, false, nil
	}
	for _, descriptor := range DefaultRegistry() {
		if descriptor.Name != name {
			continue
		}
		if descriptor.Enabled != nil && !descriptor.Enabled(cfg) {
			return engine.OrderedLayer{}, false, nil
		}
		var layer engine.Layer
		var err error
		if descriptor.ContextBuild != nil {
			layer, err = descriptor.ContextBuild(ctx, cfg)
		} else if descriptor.Build != nil {
			layer, err = descriptor.Build(cfg)
		} else {
			return engine.OrderedLayer{}, false, nil
		}
		if err != nil {
			return engine.OrderedLayer{}, false, fmt.Errorf("build %s layer: %w", name, err)
		}
		if layer == nil {
			return engine.OrderedLayer{}, false, fmt.Errorf("build %s layer: nil layer", name)
		}
		return engine.OrderedLayer{Layer: layer, Order: descriptor.Order}, true, nil
	}
	return engine.OrderedLayer{}, false, fmt.Errorf("unknown layer descriptor %q", name)
}

// EffectivePipeline returns enabled layers in deterministic engine order.
func EffectivePipeline(cfg *config.Config) []PipelineEntry {
	if cfg == nil {
		return nil
	}

	entries := make([]PipelineEntry, 0, len(DefaultRegistry()))
	for _, descriptor := range DefaultRegistry() {
		if descriptor.Enabled != nil && descriptor.Enabled(cfg) {
			entries = append(entries, PipelineEntry{Name: descriptor.Name, RuntimeName: descriptor.RuntimeName, Order: descriptor.Order})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Order == entries[j].Order {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Order < entries[j].Order
	})
	return entries
}

// PipelineSummary returns a compact, log-friendly effective pipeline summary.
func PipelineSummary(cfg *config.Config) []map[string]any {
	entries := EffectivePipeline(cfg)
	summary := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		summary = append(summary, map[string]any{
			"name":         entry.Name,
			"runtime_name": entry.RuntimeName,
			"order":        entry.Order,
		})
	}
	return summary
}

func buildIPACL(ctx *BuildContext, cfg *config.Config) (engine.Layer, error) {
	layer, err := ipacl.NewLayer(&ipacl.Config{
		Enabled:   cfg.WAF.IPACL.Enabled,
		Whitelist: cfg.WAF.IPACL.Whitelist,
		Blacklist: cfg.WAF.IPACL.Blacklist,
		AutoBan: ipacl.AutoBanConfig{
			Enabled:    cfg.WAF.IPACL.AutoBan.Enabled,
			DefaultTTL: cfg.WAF.IPACL.AutoBan.DefaultTTL,
			MaxTTL:     cfg.WAF.IPACL.AutoBan.MaxTTL,
		},
	})
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		ctx.IPACLLayer = layer
	}
	return layer, nil
}

func buildThreatIntel(ctx *BuildContext, cfg *config.Config) (engine.Layer, error) {
	feeds := make([]threatintel.FeedConfig, len(cfg.WAF.ThreatIntel.Feeds))
	for i, f := range cfg.WAF.ThreatIntel.Feeds {
		feeds[i] = threatintel.FeedConfig{
			Type:    f.Type,
			Path:    f.Path,
			URL:     f.URL,
			Refresh: f.Refresh,
			Format:  f.Format,
		}
	}
	layer, err := threatintel.NewLayer(&threatintel.Config{
		Enabled: cfg.WAF.ThreatIntel.Enabled,
		IPReputation: threatintel.IPRepConfig{
			Enabled:        cfg.WAF.ThreatIntel.IPReputation.Enabled,
			BlockMalicious: cfg.WAF.ThreatIntel.IPReputation.BlockMalicious,
			ScoreThreshold: cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold,
		},
		DomainRep: threatintel.DomainRepConfig{
			Enabled:        cfg.WAF.ThreatIntel.DomainRep.Enabled,
			BlockMalicious: cfg.WAF.ThreatIntel.DomainRep.BlockMalicious,
			CheckRedirects: cfg.WAF.ThreatIntel.DomainRep.CheckRedirects,
		},
		CacheSize: cfg.WAF.ThreatIntel.CacheSize,
		CacheTTL:  cfg.WAF.ThreatIntel.CacheTTL,
		Feeds:     feeds,
	})
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		ctx.StartHooks = append(ctx.StartHooks, StartHook{
			Name: "threat_intelligence",
			Run:  layer.Start,
		})
	}
	return layer, nil
}

func buildRateLimit(ctx *BuildContext, cfg *config.Config) (engine.Layer, error) {
	rules := make([]ratelimit.Rule, len(cfg.WAF.RateLimit.Rules))
	for i, r := range cfg.WAF.RateLimit.Rules {
		rules[i] = ratelimit.Rule{
			ID:           r.ID,
			Scope:        r.Scope,
			Paths:        r.Paths,
			Limit:        r.Limit,
			Window:       r.Window,
			Burst:        r.Burst,
			Action:       r.Action,
			AutoBanAfter: r.AutoBanAfter,
		}
	}
	layer := ratelimit.NewLayer(&ratelimit.Config{
		Enabled: cfg.WAF.RateLimit.Enabled,
		Rules:   rules,
	})
	if ctx != nil && ctx.IPACLLayer != nil && cfg.WAF.IPACL.AutoBan.Enabled {
		layer.OnAutoBan = func(ip, reason string) {
			ttl := cfg.WAF.IPACL.AutoBan.DefaultTTL
			if cfg.WAF.IPACL.AutoBan.MaxTTL > 0 && ttl > cfg.WAF.IPACL.AutoBan.MaxTTL {
				ttl = cfg.WAF.IPACL.AutoBan.MaxTTL
			}
			ctx.IPACLLayer.AddAutoBan(ip, reason, ttl)
		}
	}
	return layer, nil
}

func buildCustomRules(ctx *BuildContext, cfg *config.Config) (engine.Layer, error) {
	var geodb *geoip.DB
	if ctx != nil {
		geodb = ctx.GeoIPDB
	}
	if geodb != nil {
		engine.SetGeoIPLookup(func(ip string) (string, string) {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				return "", ""
			}
			code := geodb.Lookup(parsed)
			return code, geoip.CountryName(code)
		})
	}

	ruleList := make([]rules.Rule, len(cfg.WAF.CustomRules.Rules))
	for i, r := range cfg.WAF.CustomRules.Rules {
		conditions := make([]rules.Condition, len(r.Conditions))
		for j, c := range r.Conditions {
			conditions[j] = rules.Condition{Field: c.Field, Op: c.Op, Value: c.Value}
		}
		ruleList[i] = rules.Rule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Enabled,
			Priority:   r.Priority,
			Conditions: conditions,
			Action:     r.Action,
			Score:      r.Score,
		}
	}
	return rules.NewLayer(&rules.Config{Enabled: true, Rules: ruleList}, geodb), nil
}

func buildSanitizer(cfg *config.Config) (engine.Layer, error) {
	return sanitizer.NewLayer(&sanitizer.Config{
		MaxURLLength:   cfg.WAF.Sanitizer.MaxURLLength,
		MaxHeaderSize:  cfg.WAF.Sanitizer.MaxHeaderSize,
		MaxHeaderCount: cfg.WAF.Sanitizer.MaxHeaderCount,
		MaxBodySize:    cfg.WAF.Sanitizer.MaxBodySize,
		MaxCookieSize:  cfg.WAF.Sanitizer.MaxCookieSize,
		AllowedMethods: cfg.WAF.Sanitizer.AllowedMethods,
		BlockNullBytes: cfg.WAF.Sanitizer.BlockNullBytes,
		StripHopByHop:  cfg.WAF.Sanitizer.StripHopByHop,
	}), nil
}

func buildCORS(cfg *config.Config) (engine.Layer, error) {
	return cors.NewLayer(&cors.Config{
		Enabled:               cfg.WAF.CORS.Enabled,
		AllowOrigins:          cfg.WAF.CORS.AllowOrigins,
		AllowMethods:          cfg.WAF.CORS.AllowMethods,
		AllowHeaders:          cfg.WAF.CORS.AllowHeaders,
		ExposeHeaders:         cfg.WAF.CORS.ExposeHeaders,
		AllowCredentials:      cfg.WAF.CORS.AllowCredentials,
		MaxAgeSeconds:         cfg.WAF.CORS.MaxAgeSeconds,
		StrictMode:            cfg.WAF.CORS.StrictMode,
		PreflightCacheSeconds: cfg.WAF.CORS.PreflightCacheSeconds,
	})
}

func buildATOProtection(cfg *config.Config) (engine.Layer, error) {
	return ato.NewLayer(&ato.Config{
		Enabled:    cfg.WAF.ATOProtection.Enabled,
		LoginPaths: cfg.WAF.ATOProtection.LoginPaths,
		BruteForce: ato.BruteForceConfig{
			Enabled:             cfg.WAF.ATOProtection.BruteForce.Enabled,
			Window:              cfg.WAF.ATOProtection.BruteForce.Window,
			MaxAttemptsPerIP:    cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP,
			MaxAttemptsPerEmail: cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerEmail,
			BlockDuration:       cfg.WAF.ATOProtection.BruteForce.BlockDuration,
		},
		CredStuffing: ato.CredentialStuffingConfig{
			Enabled:              cfg.WAF.ATOProtection.CredStuffing.Enabled,
			DistributedThreshold: cfg.WAF.ATOProtection.CredStuffing.DistributedThreshold,
			Window:               cfg.WAF.ATOProtection.CredStuffing.Window,
			BlockDuration:        cfg.WAF.ATOProtection.CredStuffing.BlockDuration,
		},
		PasswordSpray: ato.PasswordSprayConfig{
			Enabled:       cfg.WAF.ATOProtection.PasswordSpray.Enabled,
			Threshold:     cfg.WAF.ATOProtection.PasswordSpray.Threshold,
			Window:        cfg.WAF.ATOProtection.PasswordSpray.Window,
			BlockDuration: cfg.WAF.ATOProtection.PasswordSpray.BlockDuration,
		},
		Travel: ato.ImpossibleTravelConfig{
			Enabled:       cfg.WAF.ATOProtection.Travel.Enabled,
			MaxDistanceKm: cfg.WAF.ATOProtection.Travel.MaxDistanceKm,
			MaxTimeHours:  cfg.WAF.ATOProtection.Travel.MaxTimeHours,
			BlockDuration: cfg.WAF.ATOProtection.Travel.BlockDuration,
		},
		GeoDBPath: cfg.WAF.ATOProtection.GeoDBPath,
	})
}

func buildAPISecurity(cfg *config.Config) (engine.Layer, error) {
	apiKeys := make([]apisecurity.APIKeyConfig, len(cfg.WAF.APISecurity.APIKeys.Keys))
	for i, k := range cfg.WAF.APISecurity.APIKeys.Keys {
		apiKeys[i] = apisecurity.APIKeyConfig{
			Name:         k.Name,
			KeyHash:      k.KeyHash,
			KeyPrefix:    k.KeyPrefix,
			RateLimit:    k.RateLimit,
			AllowedPaths: k.AllowedPaths,
			Enabled:      k.Enabled,
		}
	}
	return apisecurity.NewLayer(&apisecurity.Config{
		Enabled:    cfg.WAF.APISecurity.Enabled,
		SkipPaths:  cfg.WAF.APISecurity.SkipPaths,
		HeaderName: cfg.WAF.APISecurity.HeaderName,
		QueryParam: cfg.WAF.APISecurity.QueryParam,
		JWT: apisecurity.JWTConfig{
			Enabled:          cfg.WAF.APISecurity.JWT.Enabled,
			Issuer:           cfg.WAF.APISecurity.JWT.Issuer,
			Audience:         cfg.WAF.APISecurity.JWT.Audience,
			Algorithms:       cfg.WAF.APISecurity.JWT.Algorithms,
			PublicKeyFile:    cfg.WAF.APISecurity.JWT.PublicKeyFile,
			JWKSURL:          cfg.WAF.APISecurity.JWT.JWKSURL,
			ClockSkewSeconds: cfg.WAF.APISecurity.JWT.ClockSkewSeconds,
			PublicKeyPEM:     cfg.WAF.APISecurity.JWT.PublicKeyPEM,
		},
		APIKeys: apisecurity.APIKeysConfig{
			Enabled:    cfg.WAF.APISecurity.APIKeys.Enabled,
			HeaderName: cfg.WAF.APISecurity.APIKeys.HeaderName,
			QueryParam: cfg.WAF.APISecurity.APIKeys.QueryParam,
			Keys:       apiKeys,
		},
	})
}

func buildAPIValidation(cfg *config.Config) (engine.Layer, error) {
	schemas := make([]apivalidation.SchemaSource, len(cfg.WAF.APIValidation.Schemas))
	for i, s := range cfg.WAF.APIValidation.Schemas {
		schemas[i] = apivalidation.SchemaSource{
			Path:      s.Path,
			Type:      s.Type,
			AutoLearn: s.AutoLearn,
		}
	}
	return apivalidation.NewLayer(&apivalidation.Config{
		Enabled:          cfg.WAF.APIValidation.Enabled,
		ValidateRequest:  cfg.WAF.APIValidation.ValidateRequest,
		ValidateResponse: cfg.WAF.APIValidation.ValidateResponse,
		StrictMode:       cfg.WAF.APIValidation.StrictMode,
		BlockOnViolation: cfg.WAF.APIValidation.BlockOnViolation,
		ViolationScore:   cfg.WAF.APIValidation.ViolationScore,
		CacheSize:        cfg.WAF.APIValidation.CacheSize,
		Schemas:          schemas,
	}), nil
}

func buildCRS(cfg *config.Config) (engine.Layer, error) {
	return crs.NewLayer(&crs.Config{
		Enabled:          cfg.WAF.CRS.Enabled,
		RulePath:         cfg.WAF.CRS.RulePath,
		ParanoiaLevel:    cfg.WAF.CRS.ParanoiaLevel,
		AnomalyThreshold: cfg.WAF.CRS.AnomalyThreshold,
		Exclusions:       cfg.WAF.CRS.Exclusions,
		DisabledRules:    cfg.WAF.CRS.DisabledRules,
	}), nil
}

func buildDetection(cfg *config.Config) (engine.Layer, error) {
	detConfigs := make(map[string]detection.DetectorConfig, len(cfg.WAF.Detection.Detectors))
	for name, dc := range cfg.WAF.Detection.Detectors {
		detConfigs[name] = detection.DetectorConfig{
			Enabled:    dc.Enabled,
			Multiplier: dc.Multiplier,
		}
	}
	exclusions := make([]detection.Exclusion, 0, len(cfg.WAF.Detection.Exclusions))
	for _, exc := range cfg.WAF.Detection.Exclusions {
		exclusions = append(exclusions, detection.Exclusion{
			PathPrefix: exc.Path,
			Detectors:  exc.Detectors,
			Reason:     exc.Reason,
		})
	}
	return detection.NewLayer(&detection.Config{
		Enabled:    cfg.WAF.Detection.Enabled,
		Detectors:  detConfigs,
		Exclusions: exclusions,
	}), nil
}

func buildVirtualPatch(cfg *config.Config) (engine.Layer, error) {
	return virtualpatch.NewLayer(&virtualpatch.Config{
		Enabled:           cfg.WAF.VirtualPatch.Enabled,
		AutoUpdate:        cfg.WAF.VirtualPatch.AutoUpdate,
		UpdateInterval:    cfg.WAF.VirtualPatch.UpdateInterval,
		CVEPath:           cfg.WAF.VirtualPatch.CVEPath,
		NVDFeedURL:        cfg.WAF.VirtualPatch.NVDFeedURL,
		AutoGenerateRules: cfg.WAF.VirtualPatch.AutoGenerateRules,
		BlockSeverity:     cfg.WAF.VirtualPatch.BlockSeverity,
		NotifyOnPatch:     cfg.WAF.VirtualPatch.NotifyOnPatch,
	}), nil
}

func buildDLP(cfg *config.Config) (engine.Layer, error) {
	return dlp.NewLayer(&dlp.Config{
		Enabled:      cfg.WAF.DLP.Enabled,
		ScanRequest:  cfg.WAF.DLP.ScanRequest,
		ScanResponse: cfg.WAF.DLP.ScanResponse,
		BlockOnMatch: cfg.WAF.DLP.BlockOnMatch,
		MaskResponse: cfg.WAF.DLP.MaskResponse,
		MaxBodySize:  cfg.WAF.DLP.MaxBodySize,
		Patterns:     cfg.WAF.DLP.Patterns,
	}), nil
}

func buildBotDetection(cfg *config.Config) (engine.Layer, error) {
	return botdetect.NewLayer(&botdetect.Config{
		Enabled: cfg.WAF.BotDetection.Enabled,
		Mode:    cfg.WAF.BotDetection.Mode,
		TLSFingerprint: botdetect.TLSFingerprintConfig{
			Enabled:         cfg.WAF.BotDetection.TLSFingerprint.Enabled,
			KnownBotsAction: cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction,
			UnknownAction:   cfg.WAF.BotDetection.TLSFingerprint.UnknownAction,
			MismatchAction:  cfg.WAF.BotDetection.TLSFingerprint.MismatchAction,
		},
		UserAgent: botdetect.UAConfig{
			Enabled:            cfg.WAF.BotDetection.UserAgent.Enabled,
			BlockEmpty:         cfg.WAF.BotDetection.UserAgent.BlockEmpty,
			BlockKnownScanners: cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
		},
		Behavior: botdetect.BehaviorAnalysisConfig{
			Enabled:            cfg.WAF.BotDetection.Behavior.Enabled,
			Window:             cfg.WAF.BotDetection.Behavior.Window,
			RPSThreshold:       cfg.WAF.BotDetection.Behavior.RPSThreshold,
			ErrorRateThreshold: cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
		},
	}), nil
}

func buildClientSide(cfg *config.Config) (engine.Layer, error) {
	return clientside.NewLayer(&clientside.Config{
		Enabled: cfg.WAF.ClientSide.Enabled,
		Mode:    cfg.WAF.ClientSide.Mode,
		MagecartDetection: clientside.MagecartConfig{
			Enabled:                 cfg.WAF.ClientSide.MagecartDetection.Enabled,
			DetectObfuscatedJS:      cfg.WAF.ClientSide.MagecartDetection.DetectObfuscatedJS,
			DetectSuspiciousDomains: cfg.WAF.ClientSide.MagecartDetection.DetectSuspiciousDomains,
			DetectFormExfiltration:  cfg.WAF.ClientSide.MagecartDetection.DetectFormExfiltration,
			DetectKeyloggers:        cfg.WAF.ClientSide.MagecartDetection.DetectKeyloggers,
			KnownSkimmingDomains:    cfg.WAF.ClientSide.MagecartDetection.KnownSkimmingDomains,
			BlockScore:              cfg.WAF.ClientSide.MagecartDetection.BlockScore,
			AlertScore:              cfg.WAF.ClientSide.MagecartDetection.AlertScore,
		},
		AgentInjection: clientside.AgentConfig{
			Enabled:        cfg.WAF.ClientSide.AgentInjection.Enabled,
			ScriptURL:      cfg.WAF.ClientSide.AgentInjection.ScriptURL,
			InjectInHTML:   cfg.WAF.ClientSide.AgentInjection.InjectInHTML,
			InjectPosition: cfg.WAF.ClientSide.AgentInjection.InjectPosition,
			MonitorDOM:     cfg.WAF.ClientSide.AgentInjection.MonitorDOM,
			MonitorNetwork: cfg.WAF.ClientSide.AgentInjection.MonitorNetwork,
			MonitorForms:   cfg.WAF.ClientSide.AgentInjection.MonitorForms,
			ProtectedPaths: cfg.WAF.ClientSide.AgentInjection.ProtectedPaths,
		},
		CSP: clientside.CSPConfig{
			Enabled:         cfg.WAF.ClientSide.CSP.Enabled,
			ReportOnly:      cfg.WAF.ClientSide.CSP.ReportOnly,
			DefaultSrc:      cfg.WAF.ClientSide.CSP.DefaultSrc,
			ScriptSrc:       cfg.WAF.ClientSide.CSP.ScriptSrc,
			StyleSrc:        cfg.WAF.ClientSide.CSP.StyleSrc,
			ImgSrc:          cfg.WAF.ClientSide.CSP.ImgSrc,
			ConnectSrc:      cfg.WAF.ClientSide.CSP.ConnectSrc,
			FontSrc:         cfg.WAF.ClientSide.CSP.FontSrc,
			ObjectSrc:       cfg.WAF.ClientSide.CSP.ObjectSrc,
			MediaSrc:        cfg.WAF.ClientSide.CSP.MediaSrc,
			FrameSrc:        cfg.WAF.ClientSide.CSP.FrameSrc,
			FrameAncestors:  cfg.WAF.ClientSide.CSP.FrameAncestors,
			FormAction:      cfg.WAF.ClientSide.CSP.FormAction,
			BaseURI:         cfg.WAF.ClientSide.CSP.BaseURI,
			ReportURI:       cfg.WAF.ClientSide.CSP.ReportURI,
			UpgradeInsecure: cfg.WAF.ClientSide.CSP.UpgradeInsecure,
		},
		Exclusions: cfg.WAF.ClientSide.Exclusions,
	}), nil
}

func buildResponse(cfg *config.Config) (engine.Layer, error) {
	respCfg := response.Config{
		SecurityHeadersEnabled: cfg.WAF.Response.SecurityHeaders.Enabled,
		DataMaskingEnabled:     cfg.WAF.Response.DataMasking.Enabled,
		MaskCreditCards:        cfg.WAF.Response.DataMasking.MaskCreditCards,
		MaskSSN:                cfg.WAF.Response.DataMasking.MaskSSN,
		MaskAPIKeys:            cfg.WAF.Response.DataMasking.MaskAPIKeys,
		StripStackTraces:       cfg.WAF.Response.DataMasking.StripStackTraces,
		ErrorPageMode:          cfg.WAF.Response.ErrorPages.Mode,
	}
	if cfg.WAF.Response.SecurityHeaders.Enabled {
		respCfg.Headers = response.SecurityHeaders{
			XContentTypeOptions: "nosniff",
			XFrameOptions:       cfg.WAF.Response.SecurityHeaders.XFrameOptions,
			ReferrerPolicy:      cfg.WAF.Response.SecurityHeaders.ReferrerPolicy,
			PermissionsPolicy:   cfg.WAF.Response.SecurityHeaders.PermissionsPolicy,
		}
		if cfg.WAF.Response.SecurityHeaders.HSTS.Enabled {
			hsts := fmt.Sprintf("max-age=%d", cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge)
			if cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains {
				hsts += "; includeSubDomains"
			}
			respCfg.Headers.HSTS = hsts
		}
	}
	return response.NewLayer(&respCfg), nil
}
