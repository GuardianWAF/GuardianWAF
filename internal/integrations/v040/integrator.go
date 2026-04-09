// Package v040 provides integration for GuardianWAF v0.4.0 Phase 1 and Phase 2 features.
// Phase 1: ML Anomaly Detection, API Discovery, GraphQL Security, Enhanced Bot Management
// Phase 2: gRPC Support, Multi-tenancy
package v040

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ai/remediation"
	"github.com/guardianwaf/guardianwaf/internal/analytics"
	"github.com/guardianwaf/guardianwaf/internal/cluster"
	"github.com/guardianwaf/guardianwaf/internal/clustersync"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/discovery"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/cache"
	"github.com/guardianwaf/guardianwaf/internal/layers/canary"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
	"github.com/guardianwaf/guardianwaf/internal/layers/graphql"
	"github.com/guardianwaf/guardianwaf/internal/layers/grpc"
	"github.com/guardianwaf/guardianwaf/internal/layers/replay"
	"github.com/guardianwaf/guardianwaf/internal/layers/siem"
	"github.com/guardianwaf/guardianwaf/internal/layers/websocket"
	"github.com/guardianwaf/guardianwaf/internal/layers/zerotrust"
	"github.com/guardianwaf/guardianwaf/internal/ml/anomaly"
	proxygrpc "github.com/guardianwaf/guardianwaf/internal/proxy/grpc"
)

// Integrator manages all v0.4.0 Phase 1 and Phase 2 features.
type Integrator struct {
	cfg *config.Config

	// Phase 1 Components
	mlAnomalyLayer   *anomaly.Layer
	apiDiscovery     *discovery.Engine
	graphqlLayer     *graphql.Layer
	enhancedBotLayer *botdetect.EnhancedLayer
	botCollector     *botdetect.BiometricCollector

	// Phase 2 Components
	grpcProxy         *proxygrpc.Proxy
	grpcLayer         *grpc.Layer
	tenantIntegrator  *TenantIntegrator
	dlpLayer          *dlp.EngineLayer
	zeroTrustService  *zerotrust.Service
	siemExporter      *siem.Exporter
	cacheLayer        *cache.Layer
	replayManager     *replay.Manager
	canaryLayer       *canary.Layer
	analyticsLayer    *analytics.Layer
	clusterLayer       *cluster.Layer
	clusterSyncManager *clustersync.Manager
	remediationLayer   *remediation.Layer
	websocketLayer     *websocket.Layer

	// HTTP handlers
	biometricHandler http.HandlerFunc
	challengeHandler http.HandlerFunc
	challengeVerify  http.HandlerFunc
}

// NewIntegrator creates a new v0.4.0 feature integrator.
func NewIntegrator(cfg *config.Config) (*Integrator, error) {
	i := &Integrator{
		cfg: cfg,
	}

	// Initialize ML Anomaly Detection
	if cfg.WAF.MLAnomaly.Enabled {
		if err := i.initMLAnomaly(); err != nil {
			return nil, fmt.Errorf("ml_anomaly: %w", err)
		}
	}

	// Initialize API Discovery
	if cfg.WAF.APIDiscovery.Enabled {
		if err := i.initAPIDiscovery(); err != nil {
			return nil, fmt.Errorf("api_discovery: %w", err)
		}
	}

	// Initialize GraphQL Security
	if cfg.WAF.GraphQL.Enabled {
		if err := i.initGraphQL(); err != nil {
			return nil, fmt.Errorf("graphql: %w", err)
		}
	}

	// Initialize Enhanced Bot Management
	if cfg.WAF.BotDetection.Enhanced.Enabled {
		if err := i.initEnhancedBotDetection(); err != nil {
			return nil, fmt.Errorf("enhanced_bot_detection: %w", err)
		}
	}

	// Initialize gRPC Support (Phase 2)
	if cfg.WAF.GRPC.Enabled {
		if err := i.initGRPC(); err != nil {
			return nil, fmt.Errorf("grpc: %w", err)
		}
	}

	// Initialize Multi-tenancy (Phase 2)
	if cfg.WAF.Tenant.Enabled {
		if err := i.initMultiTenancy(); err != nil {
			return nil, fmt.Errorf("tenant: %w", err)
		}
	}

	// Initialize Advanced DLP (Phase 2)
	if cfg.WAF.DLP.Enabled {
		if err := i.initDLP(); err != nil {
			return nil, fmt.Errorf("dlp: %w", err)
		}
	}

	// Initialize Zero Trust (Phase 3)
	if cfg.WAF.ZeroTrust.Enabled {
		if err := i.initZeroTrust(); err != nil {
			return nil, fmt.Errorf("zero_trust: %w", err)
		}
	}

	// Initialize SIEM (Phase 3)
	if cfg.WAF.SIEM.Enabled {
		if err := i.initSIEM(); err != nil {
			return nil, fmt.Errorf("siem: %w", err)
		}
	}

	// Initialize Cache (Phase 3)
	if cfg.WAF.Cache.Enabled {
		if err := i.initCache(); err != nil {
			return nil, fmt.Errorf("cache: %w", err)
		}
	}

	// Initialize Request Replay (Phase 3)
	if cfg.WAF.Replay.Enabled || cfg.WAF.Replay.Replay.Enabled {
		if err := i.initReplay(); err != nil {
			return nil, fmt.Errorf("replay: %w", err)
		}
	}

	// Initialize Canary Releases (Phase 3)
	if cfg.WAF.Canary.Enabled {
		if err := i.initCanary(); err != nil {
			return nil, fmt.Errorf("canary: %w", err)
		}
	}

	// Initialize Analytics (Phase 4)
	if cfg.WAF.Analytics.Enabled {
		if err := i.initAnalytics(); err != nil {
			return nil, fmt.Errorf("analytics: %w", err)
		}
	}

	// Initialize ClusterSync (data replication between nodes)
	if cfg.WAF.ClusterSync.Enabled {
		if err := i.initClusterSync(); err != nil {
			return nil, fmt.Errorf("cluster_sync: %w", err)
		}
	}

	// Initialize Remediation (Phase 4)
	if cfg.WAF.Remediation.Enabled {
		if err := i.initRemediation(); err != nil {
			return nil, fmt.Errorf("remediation: %w", err)
		}
	}

	// Initialize WebSocket (Phase 4)
	if cfg.WAF.WebSocket.Enabled {
		if err := i.initWebSocket(); err != nil {
			return nil, fmt.Errorf("websocket: %w", err)
		}
	}

	return i, nil
}

// initMLAnomaly initializes the ML anomaly detection layer.
func (i *Integrator) initMLAnomaly() error {
	mlCfg := i.cfg.WAF.MLAnomaly

	layerCfg := &anomaly.Config{
		Enabled:   mlCfg.Enabled,
		Threshold: mlCfg.Threshold,
	}

	layer, err := anomaly.New(*layerCfg)
	if err != nil {
		return err
	}

	i.mlAnomalyLayer = layer
	log.Printf("[v0.4.0] ML Anomaly Detection enabled (mode=%s, threshold=%.2f)",
		mlCfg.Mode, mlCfg.Threshold)
	return nil
}

// initAPIDiscovery initializes the API discovery engine.
func (i *Integrator) initAPIDiscovery() error {
	adCfg := i.cfg.WAF.APIDiscovery

	engineCfg := &discovery.EngineConfig{
		CaptureMode:      adCfg.CaptureMode,
		RingBufferSize:   adCfg.RingBufferSize,
		MinSamples:       adCfg.MinSamples,
		ClusterThreshold: adCfg.ClusterThreshold,
		ExportPath:       adCfg.ExportPath,
		ExportFormat:     adCfg.ExportFormat,
		AutoExport:       adCfg.AutoExport,
		ExportInterval:   adCfg.ExportInterval,
	}

	eng, err := discovery.NewEngine(engineCfg)
	if err != nil {
		return err
	}

	i.apiDiscovery = eng
	log.Printf("[v0.4.0] API Discovery enabled (mode=%s, buffer=%d)",
		adCfg.CaptureMode, adCfg.RingBufferSize)
	return nil
}

// initGraphQL initializes the GraphQL security layer.
func (i *Integrator) initGraphQL() error {
	gqlCfg := i.cfg.WAF.GraphQL

	layerCfg := graphql.Config{
		Enabled:            gqlCfg.Enabled,
		MaxDepth:           gqlCfg.MaxDepth,
		MaxComplexity:      gqlCfg.MaxComplexity,
		BlockIntrospection: gqlCfg.BlockIntrospection,
	}

	layer, err := graphql.New(layerCfg)
	if err != nil {
		return err
	}

	i.graphqlLayer = layer
	log.Printf("[v0.4.0] GraphQL Security enabled (max_depth=%d, max_complexity=%d)",
		gqlCfg.MaxDepth, gqlCfg.MaxComplexity)
	return nil
}

// initEnhancedBotDetection initializes the enhanced bot detection layer.
func (i *Integrator) initEnhancedBotDetection() error {
	enhancedCfg := i.cfg.WAF.BotDetection.Enhanced

	layerCfg := &botdetect.EnhancedConfig{
		Enabled: enhancedCfg.Enabled,
		Mode:    enhancedCfg.Mode,
		TLSFingerprint: botdetect.TLSFingerprintConfig{
			Enabled:         i.cfg.WAF.BotDetection.TLSFingerprint.Enabled,
			KnownBotsAction: i.cfg.WAF.BotDetection.TLSFingerprint.KnownBotsAction,
			UnknownAction:   i.cfg.WAF.BotDetection.TLSFingerprint.UnknownAction,
			MismatchAction:  i.cfg.WAF.BotDetection.TLSFingerprint.MismatchAction,
		},
		UserAgent: botdetect.UAConfig{
			Enabled:            i.cfg.WAF.BotDetection.UserAgent.Enabled,
			BlockEmpty:         i.cfg.WAF.BotDetection.UserAgent.BlockEmpty,
			BlockKnownScanners: i.cfg.WAF.BotDetection.UserAgent.BlockKnownScanners,
		},
		Behavior: botdetect.BehaviorAnalysisConfig{
			Enabled:            i.cfg.WAF.BotDetection.Behavior.Enabled,
			Window:             i.cfg.WAF.BotDetection.Behavior.Window,
			RPSThreshold:       i.cfg.WAF.BotDetection.Behavior.RPSThreshold,
			ErrorRateThreshold: i.cfg.WAF.BotDetection.Behavior.ErrorRateThreshold,
			UniquePathsPerMin:  50,
			TimingStdDevMs:     10,
		},
		Challenge: botdetect.ChallengeConfig{
			Enabled:   enhancedCfg.Captcha.Enabled,
			Provider:  enhancedCfg.Captcha.Provider,
			SiteKey:   enhancedCfg.Captcha.SiteKey,
			SecretKey: enhancedCfg.Captcha.SecretKey,
			Timeout:   enhancedCfg.Captcha.Timeout,
		},
		Biometric: botdetect.BiometricConfig{
			Enabled:        enhancedCfg.Biometric.Enabled,
			MinEvents:      enhancedCfg.Biometric.MinEvents,
			ScoreThreshold: enhancedCfg.Biometric.ScoreThreshold,
			TimeWindow:     enhancedCfg.Biometric.TimeWindow,
		},
		BrowserFingerprint: botdetect.BrowserFingerprintConfig{
			Enabled:       enhancedCfg.BrowserFingerprint.Enabled,
			CheckCanvas:   enhancedCfg.BrowserFingerprint.CheckCanvas,
			CheckWebGL:    enhancedCfg.BrowserFingerprint.CheckWebGL,
			CheckFonts:    enhancedCfg.BrowserFingerprint.CheckFonts,
			CheckHeadless: enhancedCfg.BrowserFingerprint.CheckHeadless,
		},
	}

	layer := botdetect.NewEnhancedLayer(layerCfg)
	i.enhancedBotLayer = layer

	// Set up biometric collector if biometric detection is enabled
	if enhancedCfg.Biometric.Enabled || enhancedCfg.Captcha.Enabled {
		collector := botdetect.NewBiometricCollector(layer)
		i.botCollector = collector
		i.biometricHandler = collector.HandleCollect
		i.challengeHandler = collector.HandleChallengePage
		i.challengeVerify = collector.HandleChallengeVerify
	}

	log.Printf("[v0.4.0] Enhanced Bot Detection enabled (mode=%s, biometric=%v, captcha=%v)",
		enhancedCfg.Mode, enhancedCfg.Biometric.Enabled, enhancedCfg.Captcha.Enabled)
	return nil
}

// RegisterLayers registers all v0.4.0 layers with the engine pipeline.
// This should be called after the engine is created but before it starts processing requests.
func (i *Integrator) RegisterLayers(e *engine.Engine) {
	// Layer 75: Cluster (early to check cluster-wide bans before rate limiting)
	if i.clusterLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.clusterLayer,
			Order: 75,
		})
	}

	// Layer 76: WebSocket Security (early validation of handshake)
	if i.websocketLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.websocketLayer,
			Order: 76,
		})
	}

	// Layer 78: gRPC Security (after WebSocket)
	if i.grpcLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.grpcLayer,
			Order: 78,
		})
	}

	// Layer 450: GraphQL Security (before detection)
	if i.graphqlLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.graphqlLayer,
			Order: 450,
		})
	}

	// Layer 475: ML Anomaly Detection (after detection, before bot detection)
	if i.mlAnomalyLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.mlAnomalyLayer,
			Order: 475,
		})
	}

	// Layer 500: Enhanced Bot Detection (replaces or augments existing bot detection)
	if i.enhancedBotLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.enhancedBotLayer,
			Order: 500,
		})
	}

	// Layer 550: Advanced DLP (after bot detection, before response)
	if i.dlpLayer != nil {
		e.AddLayer(engine.OrderedLayer{
			Layer: i.dlpLayer,
			Order: 550,
		})
	}

	log.Println("[v0.4.0] All layers registered with engine pipeline")
}

// initGRPC initializes the gRPC proxy.
func (i *Integrator) initGRPC() error {
	grpcCfg := i.cfg.WAF.GRPC

	cfg := &proxygrpc.Config{
		Enabled:        grpcCfg.Enabled,
		GRPCWebEnabled: grpcCfg.GRPCWebEnabled,
		ProtoPaths:     grpcCfg.ProtoPaths,
		AllowedMethods: grpcCfg.AllowedMethods,
		BlockedMethods: grpcCfg.BlockedMethods,
		ValidateProto:  grpcCfg.ValidateProto,
		MaxMessageSize: grpcCfg.MaxMessageSize,
	}

	proxy, err := proxygrpc.NewProxy(cfg)
	if err != nil {
		return err
	}

	i.grpcProxy = proxy
	log.Printf("[v0.4.0] gRPC Support enabled (grpc_web=%v, validate=%v)",
		grpcCfg.GRPCWebEnabled, grpcCfg.ValidateProto)
	return nil
}

// initZeroTrust initializes the Zero Trust service.
func (i *Integrator) initZeroTrust() error {
	ztCfg := i.cfg.WAF.ZeroTrust

	cfg := &zerotrust.Config{
		Enabled:            ztCfg.Enabled,
		RequireMTLS:        ztCfg.RequireMTLS,
		RequireAttestation: ztCfg.RequireAttestation,
		SessionTTL:         ztCfg.SessionTTL,
		AttestationTTL:     ztCfg.AttestationTTL,
		TrustedCAPath:      ztCfg.TrustedCAPath,
		AllowBypassPaths:   ztCfg.AllowBypassPaths,
	}

	// Parse trust threshold
	switch ztCfg.DeviceTrustThreshold {
	case "none":
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelNone
	case "low":
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelLow
	case "medium":
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelMedium
	case "high":
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelHigh
	case "maximum":
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelMaximum
	default:
		cfg.DeviceTrustThreshold = zerotrust.TrustLevelMedium
	}

	service, err := zerotrust.NewService(cfg)
	if err != nil {
		return err
	}

	i.zeroTrustService = service
	log.Printf("[v0.4.0+] Zero Trust enabled (mTLS=%v, attestation=%v)",
		ztCfg.RequireMTLS, ztCfg.RequireAttestation)
	return nil
}

// initSIEM initializes the SIEM exporter.
func (i *Integrator) initSIEM() error {
	siemCfg := i.cfg.WAF.SIEM

	cfg := &siem.Config{
		Enabled:       siemCfg.Enabled,
		Endpoint:      siemCfg.Endpoint,
		Format:        siem.Format(siemCfg.Format),
		APIKey:        siemCfg.APIKey,
		Index:         siemCfg.Index,
		BatchSize:     siemCfg.BatchSize,
		FlushInterval: siemCfg.FlushInterval,
		Timeout:       siemCfg.Timeout,
		SkipVerify:    siemCfg.SkipVerify,
		Fields:        siemCfg.Fields,
	}

	exporter := siem.NewExporter(cfg)
	exporter.Start()

	i.siemExporter = exporter
	log.Printf("[v0.4.0+] SIEM enabled (format=%s, endpoint=%s)",
		siemCfg.Format, siemCfg.Endpoint)
	return nil
}

func (i *Integrator) initMultiTenancy() error {
	integrator, err := NewTenantIntegrator(i.cfg.WAF.Tenant)
	if err != nil {
		return err
	}

	i.tenantIntegrator = integrator
	log.Printf("[v0.4.0] Multi-tenancy enabled (max_tenants=%d)",
		i.cfg.WAF.Tenant.MaxTenants)
	return nil
}

// initDLP initializes the Advanced DLP layer.
func (i *Integrator) initDLP() error {
	dlpCfg := i.cfg.WAF.DLP

	cfg := &dlp.Config{
		Enabled:      dlpCfg.Enabled,
		ScanRequest:  dlpCfg.ScanRequest,
		ScanResponse: dlpCfg.ScanResponse,
		BlockOnMatch: dlpCfg.BlockOnMatch,
		MaskResponse: dlpCfg.MaskResponse,
		MaxBodySize:  dlpCfg.MaxBodySize,
		Patterns:     dlpCfg.Patterns,
	}

	layer := dlp.NewEngineLayer(cfg)
	i.dlpLayer = layer

	log.Printf("[v0.4.0] Advanced DLP enabled (patterns=%v, block=%v)",
		dlpCfg.Patterns, dlpCfg.BlockOnMatch)
	return nil
}

// RegisterHandlers registers HTTP handlers for v0.4.0 features.
// These should be mounted on the dashboard/proxy mux.
func (i *Integrator) RegisterHandlers(mux *http.ServeMux) {
	// Biometric event collector endpoint
	if i.biometricHandler != nil {
		mux.HandleFunc("/gwaf/biometric/collect", i.biometricHandler)
		log.Println("[v0.4.0] Registered handler: /gwaf/biometric/collect")
	}

	// Challenge pages
	if i.challengeHandler != nil {
		mux.HandleFunc("/gwaf/challenge", i.challengeHandler)
		mux.HandleFunc("/gwaf/challenge/verify", i.challengeVerify)
		log.Println("[v0.4.0] Registered handlers: /gwaf/challenge, /gwaf/challenge/verify")
	}

	// API Discovery endpoints
	if i.apiDiscovery != nil {
		mux.HandleFunc("/gwaf/api/discovery/export", i.handleDiscoveryExport)
		mux.HandleFunc("/gwaf/api/discovery/spec", i.handleDiscoverySpec)
		mux.HandleFunc("/gwaf/api/discovery/stats", i.handleDiscoveryStats)
		log.Println("[v0.4.0] Registered handlers: /gwaf/api/discovery/*")
	}

	// Tenant management endpoints (Phase 2)
	if i.tenantIntegrator != nil {
		i.tenantIntegrator.RegisterHandlers(mux)
		log.Println("[v0.4.0] Registered handlers: /api/v1/tenants/*")
	}
}

// RecordRequest records a request for API Discovery if enabled.
// This should be called for every request that passes through the WAF.
func (i *Integrator) RecordRequest(r *http.Request, statusCode int) {
	if i.apiDiscovery != nil {
		i.apiDiscovery.RecordRequest(r, statusCode)
	}
}

// initCache initializes the Advanced Caching layer.
func (i *Integrator) initCache() error {
	cacheCfg := i.cfg.WAF.Cache

	cfg := &cache.Config{
		Enabled:   cacheCfg.Enabled,
		Backend:   cacheCfg.Backend,
		TTL:       cacheCfg.TTL,
		MaxSize:   cacheCfg.MaxSize,
		RedisAddr: cacheCfg.RedisAddr,
		RedisPass: cacheCfg.RedisPass,
		RedisDB:   cacheCfg.RedisDB,
		Prefix:    cacheCfg.Prefix,
	}

	c, err := cache.New(cfg)
	if err != nil {
		return err
	}

	layerCfg := &cache.LayerConfig{
		Enabled:              cacheCfg.Enabled,
		CacheTTL:             cacheCfg.TTL,
		CacheMethods:         cacheCfg.CacheMethods,
		CacheStatus:          cacheCfg.CacheStatusCodes,
		SkipPaths:            cacheCfg.SkipPaths,
		MaxCacheSize:         cacheCfg.MaxCacheSize,
		StaleWhileRevalidate: cacheCfg.StaleWhileRevalidate,
	}

	layer := cache.NewLayer(c, layerCfg)
	i.cacheLayer = layer

	log.Printf("[v0.4.0+] Cache enabled (backend=%s, ttl=%v, max_size=%dMB)",
		cacheCfg.Backend, cacheCfg.TTL, cacheCfg.MaxSize)
	return nil
}

// GetZeroTrustService returns the Zero Trust service.
func (i *Integrator) GetZeroTrustService() *zerotrust.Service {
	return i.zeroTrustService
}

// GetSIEMExporter returns the SIEM exporter.
func (i *Integrator) GetSIEMExporter() *siem.Exporter {
	return i.siemExporter
}

// ZeroTrustMiddleware returns the Zero Trust middleware for HTTP handlers.
func (i *Integrator) ZeroTrustMiddleware(next http.Handler) http.Handler {
	if i.zeroTrustService == nil {
		return next
	}
	middleware := zerotrust.NewMiddleware(i.zeroTrustService)
	return middleware.Handler(next)
}
func (i *Integrator) GetAPIDiscovery() *discovery.Engine {
	return i.apiDiscovery
}

// GetEnhancedBotLayer returns the enhanced bot detection layer.
func (i *Integrator) GetEnhancedBotLayer() *botdetect.EnhancedLayer {
	return i.enhancedBotLayer
}

// GetGRPCProxy returns the gRPC proxy for handling gRPC requests.
func (i *Integrator) GetGRPCProxy() *proxygrpc.Proxy {
	return i.grpcProxy
}

// GetTenantIntegrator returns the tenant integrator for multi-tenancy.
func (i *Integrator) GetTenantIntegrator() *TenantIntegrator {
	return i.tenantIntegrator
}

// GetDLPLayer returns the DLP layer for response scanning.
func (i *Integrator) GetDLPLayer() *dlp.EngineLayer {
	return i.dlpLayer
}

// TenantMiddleware returns the tenant middleware for HTTP handlers.
func (i *Integrator) TenantMiddleware(next http.Handler) http.Handler {
	if i.tenantIntegrator == nil {
		return next
	}
	return i.tenantIntegrator.Middleware()(next)
}

// Cleanup performs cleanup of all v0.4.0 components.
func (i *Integrator) Cleanup() {
	if i.apiDiscovery != nil {
		i.apiDiscovery.Stop()
	}
	if i.mlAnomalyLayer != nil {
		i.mlAnomalyLayer.Stop()
	}
	if i.siemExporter != nil {
		i.siemExporter.Stop()
	}
	if i.clusterLayer != nil {
		if err := i.clusterLayer.Stop(); err != nil {
			log.Printf("[v0.4.0] warning: clusterLayer.Stop failed: %v", err)
		}
	}
	if i.remediationLayer != nil {
		i.remediationLayer.Stop()
	}
	if i.websocketLayer != nil {
		i.websocketLayer.Stop()
	}
	if i.grpcLayer != nil {
		i.grpcLayer.Stop()
	}
	log.Println("[v0.4.0] Cleanup complete")
}

// handleDiscoveryExport handles API discovery export requests.
func (i *Integrator) handleDiscoveryExport(w http.ResponseWriter, r *http.Request) {
	if i.apiDiscovery == nil {
		http.Error(w, "API Discovery not enabled", http.StatusServiceUnavailable)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "openapi"
	}

	var data []byte
	var contentType string
	var filename string

	switch format {
	case "openapi":
		spec := i.apiDiscovery.ExportToOpenAPI()
		var err error
		data, err = spec.ToJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		contentType = "application/json"
		filename = "api-spec.json"
	default:
		http.Error(w, "Unknown format", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	_, _ = w.Write(data) // Client disconnect error ignored
}

// handleDiscoverySpec handles API discovery spec viewing.
func (i *Integrator) handleDiscoverySpec(w http.ResponseWriter, r *http.Request) {
	if i.apiDiscovery == nil {
		http.Error(w, "API Discovery not enabled", http.StatusServiceUnavailable)
		return
	}

	spec := i.apiDiscovery.ExportToOpenAPI()
	data, err := spec.ToJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data) // Client disconnect error ignored
}

// handleDiscoveryStats handles API discovery statistics.
func (i *Integrator) handleDiscoveryStats(w http.ResponseWriter, r *http.Request) {
	if i.apiDiscovery == nil {
		http.Error(w, "API Discovery not enabled", http.StatusServiceUnavailable)
		return
	}

	stats := i.apiDiscovery.GetStats()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"endpoints_discovered": %d,
		"requests_analyzed": %d,
		"last_export": "%s",
		"is_learning": %t
	}`, stats.EndpointsDiscovered, stats.RequestsAnalyzed, stats.LastExport, stats.IsLearning)
}

// Stats holds v0.4.0 integration statistics.
type Stats struct {
	MLAnomalyEnabled        bool `json:"ml_anomaly_enabled"`
	APIDiscoveryEnabled     bool `json:"api_discovery_enabled"`
	GraphQLSecurityEnabled  bool `json:"graphql_security_enabled"`
	EnhancedBotEnabled      bool `json:"enhanced_bot_enabled"`
	BiometricEnabled        bool `json:"biometric_enabled"`
	CaptchaEnabled          bool `json:"captcha_enabled"`
	GRPCEnabled             bool `json:"grpc_enabled"`
	MultiTenancyEnabled     bool `json:"multi_tenancy_enabled"`
	TenantCount             int  `json:"tenant_count"`
	DLPEnabled              bool `json:"dlp_enabled"`
	DLPBlockOnMatch         bool `json:"dlp_block_on_match"`
	ZeroTrustEnabled        bool `json:"zero_trust_enabled"`
	ZeroTrustRequireMTLS    bool `json:"zero_trust_require_mtls"`
	SIEMEnabled             bool `json:"siem_enabled"`
	SIEMFormat              string `json:"siem_format"`
	CacheEnabled            bool   `json:"cache_enabled"`
	ReplayEnabled           bool   `json:"replay_enabled"`
	ReplayRecordingEnabled  bool   `json:"replay_recording_enabled"`
	CanaryEnabled           bool   `json:"canary_enabled"`
	CanaryStrategy          string `json:"canary_strategy"`
	AnalyticsEnabled        bool   `json:"analytics_enabled"`
	ClusterEnabled          bool   `json:"cluster_enabled"`
	ClusterNodeCount        int    `json:"cluster_node_count"`
	ClusterIsLeader         bool   `json:"cluster_is_leader"`
	RemediationEnabled      bool   `json:"remediation_enabled"`
	RemediationAutoApply    bool   `json:"remediation_auto_apply"`
	RemediationRulesActive  int    `json:"remediation_rules_active"`
	WebSocketEnabled        bool   `json:"websocket_enabled"`
	WebSocketConnections    int    `json:"websocket_connections"`
	GRPCSecurityEnabled     bool   `json:"grpc_security_enabled"`
	GRPCStreams             int    `json:"grpc_streams"`
}

// GetStats returns the current integration statistics.
func (i *Integrator) GetStats() Stats {
	stats := Stats{
		MLAnomalyEnabled:       i.mlAnomalyLayer != nil,
		APIDiscoveryEnabled:    i.apiDiscovery != nil,
		GraphQLSecurityEnabled: i.graphqlLayer != nil,
		EnhancedBotEnabled:     i.enhancedBotLayer != nil,
		BiometricEnabled:       i.cfg.WAF.BotDetection.Enhanced.Biometric.Enabled,
		CaptchaEnabled:         i.cfg.WAF.BotDetection.Enhanced.Captcha.Enabled,
		GRPCEnabled:            i.grpcProxy != nil,
		MultiTenancyEnabled:    i.tenantIntegrator != nil,
		DLPEnabled:             i.dlpLayer != nil,
		DLPBlockOnMatch:        i.cfg.WAF.DLP.BlockOnMatch,
		ZeroTrustEnabled:       i.zeroTrustService != nil,
		ZeroTrustRequireMTLS:   i.cfg.WAF.ZeroTrust.RequireMTLS,
		SIEMEnabled:            i.siemExporter != nil,
		SIEMFormat:             i.cfg.WAF.SIEM.Format,
		CacheEnabled:           i.cacheLayer != nil,
		ReplayEnabled:          i.replayManager != nil,
		ReplayRecordingEnabled: i.cfg.WAF.Replay.Enabled,
		CanaryEnabled:          i.canaryLayer != nil,
		CanaryStrategy:         i.cfg.WAF.Canary.Strategy,
		AnalyticsEnabled:       i.analyticsLayer != nil,
		ClusterEnabled:         i.clusterLayer != nil,
		ClusterNodeCount:       i.GetClusterNodeCount(),
		ClusterIsLeader:        i.IsClusterLeader(),
		RemediationEnabled:     i.remediationLayer != nil,
		RemediationAutoApply:   i.cfg.WAF.Remediation.AutoApply,
		WebSocketEnabled:       i.websocketLayer != nil,
	}

	if i.tenantIntegrator != nil {
		tenantStats := i.tenantIntegrator.Stats()
		stats.TenantCount = tenantStats.TenantCount
	}

	if i.remediationLayer != nil {
		stats.RemediationRulesActive = len(i.remediationLayer.GetEngine().GetActiveRules())
	}

	if i.websocketLayer != nil && i.websocketLayer.GetSecurity() != nil {
		stats.WebSocketConnections = len(i.websocketLayer.GetSecurity().GetAllConnections())
	}

	if i.grpcLayer != nil && i.grpcLayer.GetSecurity() != nil {
		stats.GRPCSecurityEnabled = true
		stats.GRPCStreams = i.grpcLayer.GetSecurity().GetStreamCount()
	}

	return stats
}

// initReplay initializes the Request Replay manager.
func (i *Integrator) initReplay() error {
	replayCfg := i.cfg.WAF.Replay

	cfg := &replay.ManagerConfig{
		Recording: &replay.Config{
			Enabled:         replayCfg.Enabled,
			StoragePath:     replayCfg.StoragePath,
			Format:          replay.RecordFormat(replayCfg.Format),
			MaxFileSize:     replayCfg.MaxFileSize,
			MaxFiles:        replayCfg.MaxFiles,
			RetentionDays:   replayCfg.RetentionDays,
			CaptureRequest:  replayCfg.CaptureRequest,
			CaptureResponse: replayCfg.CaptureResponse,
			CaptureHeaders:  replayCfg.CaptureHeaders,
			SkipPaths:       replayCfg.SkipPaths,
			SkipMethods:     replayCfg.SkipMethods,
			Compress:        replayCfg.Compress,
		},
		Replay: &replay.ReplayerConfig{
			Enabled:          replayCfg.Replay.Enabled,
			TargetBaseURL:    replayCfg.Replay.TargetBaseURL,
			RateLimit:        replayCfg.Replay.RateLimit,
			Concurrency:      replayCfg.Replay.Concurrency,
			Timeout:          replayCfg.Replay.Timeout,
			FollowRedirects:  replayCfg.Replay.FollowRedirects,
			ModifyHost:       replayCfg.Replay.ModifyHost,
			PreserveIDs:      replayCfg.Replay.PreserveIDs,
			DryRun:           replayCfg.Replay.DryRun,
			Headers:          replayCfg.Replay.Headers,
		},
	}

	manager, err := replay.NewManager(cfg)
	if err != nil {
		return err
	}

	i.replayManager = manager
	log.Printf("[v0.4.0+] Request Replay enabled (recording=%v, replay=%v)",
		replayCfg.Enabled, replayCfg.Replay.Enabled)
	return nil
}

// GetReplayManager returns the replay manager.
func (i *Integrator) GetReplayManager() *replay.Manager {
	return i.replayManager
}

// RecordRequestForReplay captures a request/response for replay.
func (i *Integrator) RecordRequestForReplay(req *http.Request, resp *http.Response, duration time.Duration) error {
	if i.replayManager == nil {
		return nil
	}
	return i.replayManager.Record(req, resp, duration)
}

// initCanary initializes the Canary Releases layer.
func (i *Integrator) initCanary() error {
	canaryCfg := i.cfg.WAF.Canary

	cfg := &canary.Config{
		Enabled:          canaryCfg.Enabled,
		CanaryVersion:    canaryCfg.CanaryVersion,
		StableUpstream:   canaryCfg.StableUpstream,
		CanaryUpstream:   canaryCfg.CanaryUpstream,
		Strategy:         canary.Strategy(canaryCfg.Strategy),
		Percentage:       canaryCfg.Percentage,
		HeaderName:       canaryCfg.HeaderName,
		HeaderValue:      canaryCfg.HeaderValue,
		CookieName:       canaryCfg.CookieName,
		CookieValue:      canaryCfg.CookieValue,
		Regions:          canaryCfg.Regions,
		AutoRollback:     canaryCfg.AutoRollback,
		ErrorThreshold:   canaryCfg.ErrorThreshold,
		LatencyThreshold: canaryCfg.LatencyThreshold,
		Metadata:         canaryCfg.Metadata,
	}

	layer, err := canary.NewLayer(&canary.LayerConfig{
		Enabled: cfg.Enabled,
		Config:  cfg,
	})
	if err != nil {
		return err
	}

	i.canaryLayer = layer
	log.Printf("[v0.4.0+] Canary Releases enabled (strategy=%s, percentage=%d%%)",
		canaryCfg.Strategy, canaryCfg.Percentage)
	return nil
}

// GetCanaryLayer returns the canary layer.
func (i *Integrator) GetCanaryLayer() *canary.Layer {
	return i.canaryLayer
}

// CanaryMiddleware returns the canary middleware for HTTP handlers.
func (i *Integrator) CanaryMiddleware(next http.Handler) http.Handler {
	if i.canaryLayer == nil || i.canaryLayer.GetCanary() == nil {
		return next
	}
	middleware := canary.NewMiddleware(i.canaryLayer.GetCanary())
	return middleware.Handler(next)
}

// initAnalytics initializes the Analytics layer.
func (i *Integrator) initAnalytics() error {
	analyticsCfg := i.cfg.WAF.Analytics

	cfg := &analytics.Config{
		Enabled:          analyticsCfg.Enabled,
		StoragePath:      analyticsCfg.StoragePath,
		RetentionDays:    analyticsCfg.RetentionDays,
		FlushInterval:    analyticsCfg.FlushInterval,
		MaxDataPoints:    analyticsCfg.MaxDataPoints,
		EnableTimeSeries: analyticsCfg.EnableTimeSeries,
	}

	layer, err := analytics.NewLayer(&analytics.LayerConfig{
		Enabled: cfg.Enabled,
		Config:  cfg,
	})
	if err != nil {
		return err
	}

	i.analyticsLayer = layer
	log.Printf("[v0.4.0+] Analytics enabled (storage=%s, retention=%d days)",
		analyticsCfg.StoragePath, analyticsCfg.RetentionDays)
	return nil
}

// GetAnalyticsLayer returns the analytics layer.
func (i *Integrator) GetAnalyticsLayer() *analytics.Layer {
	return i.analyticsLayer
}

// AnalyticsHandler returns the analytics HTTP handler.
func (i *Integrator) AnalyticsHandler() http.Handler {
	if i.analyticsLayer == nil {
		return nil
	}
	return i.analyticsLayer.GetHandler()
}

// initClusterSync initializes the cluster synchronization layer.
func (i *Integrator) initClusterSync() error {
	clusterCfg := i.cfg.WAF.ClusterSync

	// Initialize cluster sync manager
	cfg := &clustersync.Config{
		Enabled:            clusterCfg.Enabled,
		NodeID:             clusterCfg.NodeID,
		NodeName:           clusterCfg.NodeName,
		BindAddress:        clusterCfg.Listen,
		APIPort:            clusterCfg.Port,
		SharedSecret:       clusterCfg.SharedSecret,
		SyncInterval:       clusterCfg.SyncInterval,
		ConflictResolution: clustersync.LastWriteWins,
		MaxRetries:         clusterCfg.MaxRetries,
		RetryDelay:         clusterCfg.RetryDelay,
	}

	// Convert cluster memberships
	for _, cm := range clusterCfg.Clusters {
		cc := clustersync.ClusterConfig{
			ID:            cm.ID,
			Name:          cm.Name,
			SyncScope:     cm.SyncScope,
			Bidirectional: cm.Bidirectional,
		}
		for _, n := range cm.Nodes {
			cc.Nodes = append(cc.Nodes, clustersync.Node{
				ID:      n.ID,
				Name:    n.Name,
				Address: n.Address,
			})
		}
		cfg.Clusters = append(cfg.Clusters, cc)
	}

	// Conflict resolution
	switch clusterCfg.ConflictResolution {
	case "source_priority":
		cfg.ConflictResolution = clustersync.SourcePriority
	case "manual":
		cfg.ConflictResolution = clustersync.Manual
	default:
		cfg.ConflictResolution = clustersync.LastWriteWins
	}

	manager := clustersync.NewManager(cfg)
	if err := manager.Start(); err != nil {
		return err
	}

	i.clusterSyncManager = manager
	log.Printf("[v0.4.0+] ClusterSync enabled (node=%s, port=%d, clusters=%d)",
		cfg.NodeID, cfg.APIPort, len(cfg.Clusters))
	return nil
}

// GetClusterLayer returns the cluster layer.
func (i *Integrator) GetClusterLayer() *cluster.Layer {
	return i.clusterLayer
}

// GetCluster returns the underlying cluster instance.
func (i *Integrator) GetCluster() *cluster.Cluster {
	if i.clusterLayer == nil {
		return nil
	}
	return i.clusterLayer.GetCluster()
}

// IsClusterLeader returns true if this node is the cluster leader.
func (i *Integrator) IsClusterLeader() bool {
	if i.clusterLayer == nil {
		return false
	}
	return i.clusterLayer.IsLeader()
}

// GetClusterNodeCount returns the number of nodes in the cluster.
func (i *Integrator) GetClusterNodeCount() int {
	if i.clusterLayer == nil {
		return 1
	}
	return i.clusterLayer.GetNodeCount()
}

// initRemediation initializes the AI auto-remediation layer.
func (i *Integrator) initRemediation() error {
	remCfg := i.cfg.WAF.Remediation

	cfg := &remediation.Config{
		Enabled:             remCfg.Enabled,
		AutoApply:           remCfg.AutoApply,
		ConfidenceThreshold: remCfg.ConfidenceThreshold,
		MaxRulesPerDay:      remCfg.MaxRulesPerDay,
		RuleTTL:             remCfg.RuleTTL,
		ExcludedPaths:       remCfg.ExcludedPaths,
		StoragePath:         remCfg.StoragePath,
	}

	layer, err := remediation.NewLayer(cfg)
	if err != nil {
		return err
	}

	i.remediationLayer = layer
	log.Printf("[v0.4.0+] Remediation enabled (auto_apply=%v, threshold=%d%%)",
		remCfg.AutoApply, remCfg.ConfidenceThreshold)
	return nil
}

// GetRemediationLayer returns the remediation layer.
func (i *Integrator) GetRemediationLayer() *remediation.Layer {
	return i.remediationLayer
}

// GetRemediationEngine returns the remediation engine.
func (i *Integrator) GetRemediationEngine() *remediation.Engine {
	if i.remediationLayer == nil {
		return nil
	}
	return i.remediationLayer.GetEngine()
}

// RemediationHandler returns the remediation HTTP handler.
func (i *Integrator) RemediationHandler() http.Handler {
	if i.remediationLayer == nil {
		return nil
	}
	return i.remediationLayer.GetHandler()
}

// initWebSocket initializes the WebSocket security layer.
func (i *Integrator) initWebSocket() error {
	wsCfg := i.cfg.WAF.WebSocket

	cfg := &websocket.Config{
		Enabled:             wsCfg.Enabled,
		MaxMessageSize:      wsCfg.MaxMessageSize,
		MaxFrameSize:        wsCfg.MaxFrameSize,
		RateLimitPerSecond:  wsCfg.RateLimitPerSecond,
		RateLimitBurst:      wsCfg.RateLimitBurst,
		AllowedOrigins:      wsCfg.AllowedOrigins,
		BlockedExtensions:   wsCfg.BlockedExtensions,
		BlockEmptyMessages:  wsCfg.BlockEmptyMessages,
		BlockBinaryMessages: wsCfg.BlockBinaryMessages,
		MaxConcurrentPerIP:  wsCfg.MaxConcurrentPerIP,
		HandshakeTimeout:    wsCfg.HandshakeTimeout,
		IdleTimeout:         wsCfg.IdleTimeout,
		ScanPayloads:        wsCfg.ScanPayloads,
	}

	layer, err := websocket.NewLayer(cfg)
	if err != nil {
		return err
	}

	i.websocketLayer = layer
	log.Printf("[v0.4.0+] WebSocket Security enabled (scan_payloads=%v, rate_limit=%d/s)",
		wsCfg.ScanPayloads, wsCfg.RateLimitPerSecond)
	return nil
}

// GetWebSocketLayer returns the WebSocket layer.
func (i *Integrator) GetWebSocketLayer() *websocket.Layer {
	return i.websocketLayer
}

// GetWebSocketSecurity returns the WebSocket security instance.
func (i *Integrator) GetWebSocketSecurity() *websocket.Security {
	if i.websocketLayer == nil {
		return nil
	}
	return i.websocketLayer.GetSecurity()
}

// WebSocketHandler returns the WebSocket HTTP handler.
func (i *Integrator) WebSocketHandler() http.Handler {
	if i.websocketLayer == nil {
		return nil
	}
	return websocket.NewHandler(i.websocketLayer.GetSecurity())
}

// GetGRPCLayer returns the gRPC layer.
func (i *Integrator) GetGRPCLayer() *grpc.Layer {
	return i.grpcLayer
}

// GetGRPCSecurity returns the gRPC security instance.
func (i *Integrator) GetGRPCSecurity() *grpc.Security {
	if i.grpcLayer == nil {
		return nil
	}
	return i.grpcLayer.GetSecurity()
}

// GRPCHandler returns the gRPC HTTP handler.
func (i *Integrator) GRPCHandler() http.Handler {
	if i.grpcLayer == nil {
		return nil
	}
	return grpc.NewHandler(i.grpcLayer.GetSecurity())
}

