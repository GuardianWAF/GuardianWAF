package main

import (
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/dashboard"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type eventSubscriber interface {
	Subscribe(ch chan<- engine.Event)
}

type autoBanner interface {
	AddAutoBan(ip string, reason string, ttl time.Duration)
}

func setupAIRuntime(
	cfg *config.Config,
	eng *engine.Engine,
	eventBus eventSubscriber,
	dash *dashboard.Dashboard,
) *ai.Analyzer {
	if cfg == nil || eng == nil || eventBus == nil || !cfg.WAF.AIAnalysis.Enabled {
		return nil
	}

	aiStore := ai.NewStore(cfg.WAF.AIAnalysis.StorePath)
	if cfg.Dashboard.APIKey != "" {
		aiStore.SetEncryptionKey(cfg.Dashboard.APIKey)
	}

	aiAnalyzer := ai.NewAnalyzer(aiAnalyzerConfig(cfg), aiStore, cfg.WAF.AIAnalysis.CatalogURL)
	aiAnalyzer.SetLogger(eng.Logs.Add)

	if ipaclL := eng.FindLayer("ipacl"); ipaclL != nil {
		if ab, ok := ipaclL.(autoBanner); ok {
			aiAnalyzer.SetBlocker(ab)
		}
	}

	aiCh := make(chan engine.Event, 512)
	eventBus.Subscribe(aiCh)
	aiAnalyzer.Start(aiCh)
	eng.Logs.Info("AI threat analysis enabled")

	if dash != nil {
		dash.SetAIAnalyzer(aiAnalyzer)
	}
	return aiAnalyzer
}

func aiAnalyzerConfig(cfg *config.Config) ai.AnalyzerConfig {
	aiCfg := cfg.WAF.AIAnalysis
	return ai.AnalyzerConfig{
		Enabled:          true,
		BatchSize:        aiCfg.BatchSize,
		BatchInterval:    aiCfg.BatchInterval,
		MaxTokensHour:    aiCfg.MaxTokensPerHour,
		MaxTokensDay:     aiCfg.MaxTokensPerDay,
		MaxRequestsHour:  aiCfg.MaxRequestsHour,
		AutoBlockEnabled: aiCfg.AutoBlock,
		AutoBlockTTL:     aiCfg.AutoBlockTTL,
		MinScoreForAI:    aiCfg.MinScore,
	}
}
