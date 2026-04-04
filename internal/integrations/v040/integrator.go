// Package v040 provides integration for GuardianWAF v0.4.0 Phase 1 features.
// This wires together: ML Anomaly Detection, API Discovery, GraphQL Security,
// and Enhanced Bot Management.
package v040

import (
	"fmt"
	"log"
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/discovery"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect"
	"github.com/guardianwaf/guardianwaf/internal/layers/graphql"
	"github.com/guardianwaf/guardianwaf/internal/ml/anomaly"
)

// Integrator manages all v0.4.0 Phase 1 features.
type Integrator struct {
	cfg *config.Config

	// Components
	mlAnomalyLayer   *anomaly.Layer
	apiDiscovery     *discovery.Engine
	graphqlLayer     *graphql.Layer
	enhancedBotLayer *botdetect.EnhancedLayer
	botCollector     *botdetect.BiometricCollector

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

	log.Println("[v0.4.0] All layers registered with engine pipeline")
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
}

// RecordRequest records a request for API Discovery if enabled.
// This should be called for every request that passes through the WAF.
func (i *Integrator) RecordRequest(r *http.Request, statusCode int) {
	if i.apiDiscovery != nil {
		i.apiDiscovery.RecordRequest(r, statusCode)
	}
}

// GetAPIDiscovery returns the API discovery engine for dashboard integration.
func (i *Integrator) GetAPIDiscovery() *discovery.Engine {
	return i.apiDiscovery
}

// GetEnhancedBotLayer returns the enhanced bot detection layer.
func (i *Integrator) GetEnhancedBotLayer() *botdetect.EnhancedLayer {
	return i.enhancedBotLayer
}

// Cleanup performs cleanup of all v0.4.0 components.
func (i *Integrator) Cleanup() {
	if i.apiDiscovery != nil {
		i.apiDiscovery.Stop()
	}
	if i.mlAnomalyLayer != nil {
		i.mlAnomalyLayer.Stop()
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
	w.Write(data)
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
	w.Write(data)
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
}

// GetStats returns the current integration statistics.
func (i *Integrator) GetStats() Stats {
	return Stats{
		MLAnomalyEnabled:       i.mlAnomalyLayer != nil,
		APIDiscoveryEnabled:    i.apiDiscovery != nil,
		GraphQLSecurityEnabled: i.graphqlLayer != nil,
		EnhancedBotEnabled:     i.enhancedBotLayer != nil,
		BiometricEnabled:       i.cfg.WAF.BotDetection.Enhanced.Biometric.Enabled,
		CaptchaEnabled:         i.cfg.WAF.BotDetection.Enhanced.Captcha.Enabled,
	}
}
