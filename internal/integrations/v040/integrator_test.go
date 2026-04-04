package v040

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestNewIntegrator(t *testing.T) {
	// Create config with all v0.4.0 features disabled
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = false
	cfg.WAF.APIDiscovery.Enabled = false
	cfg.WAF.GraphQL.Enabled = false
	cfg.WAF.BotDetection.Enhanced.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	if i == nil {
		t.Fatal("expected integrator, got nil")
	}

	// Verify all components are nil when disabled
	if i.mlAnomalyLayer != nil {
		t.Error("mlAnomalyLayer should be nil when disabled")
	}
	if i.apiDiscovery != nil {
		t.Error("apiDiscovery should be nil when disabled")
	}
	if i.graphqlLayer != nil {
		t.Error("graphqlLayer should be nil when disabled")
	}
	if i.enhancedBotLayer != nil {
		t.Error("enhancedBotLayer should be nil when disabled")
	}
}

func TestIntegrator_GetStats(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = false
	cfg.WAF.APIDiscovery.Enabled = false
	cfg.WAF.GraphQL.Enabled = false
	cfg.WAF.BotDetection.Enhanced.Enabled = false

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	stats := i.GetStats()

	// All features should be disabled
	if stats.MLAnomalyEnabled {
		t.Error("MLAnomalyEnabled should be false")
	}
	if stats.APIDiscoveryEnabled {
		t.Error("APIDiscoveryEnabled should be false")
	}
	if stats.GraphQLSecurityEnabled {
		t.Error("GraphQLSecurityEnabled should be false")
	}
	if stats.EnhancedBotEnabled {
		t.Error("EnhancedBotEnabled should be false")
	}
}

func TestNewIntegrator_WithFeatures(t *testing.T) {
	// Create config with features enabled
	cfg := config.DefaultConfig()
	cfg.WAF.MLAnomaly.Enabled = true
	cfg.WAF.MLAnomaly.Threshold = 0.7
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.APIDiscovery.RingBufferSize = 1000
	cfg.WAF.GraphQL.Enabled = true
	cfg.WAF.GraphQL.MaxDepth = 10
	cfg.WAF.BotDetection.Enhanced.Enabled = true
	cfg.WAF.BotDetection.Enhanced.Mode = "monitor"

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	// Verify components are initialized
	if i.mlAnomalyLayer == nil {
		t.Error("mlAnomalyLayer should be initialized")
	}
	if i.apiDiscovery == nil {
		t.Error("apiDiscovery should be initialized")
	}
	if i.graphqlLayer == nil {
		t.Error("graphqlLayer should be initialized")
	}
	if i.enhancedBotLayer == nil {
		t.Error("enhancedBotLayer should be initialized")
	}

	// Check stats
	stats := i.GetStats()
	if !stats.MLAnomalyEnabled {
		t.Error("MLAnomalyEnabled should be true")
	}
	if !stats.APIDiscoveryEnabled {
		t.Error("APIDiscoveryEnabled should be true")
	}
	if !stats.GraphQLSecurityEnabled {
		t.Error("GraphQLSecurityEnabled should be true")
	}
	if !stats.EnhancedBotEnabled {
		t.Error("EnhancedBotEnabled should be true")
	}
}

func TestIntegrator_Cleanup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.APIDiscovery.Enabled = true
	cfg.WAF.MLAnomaly.Enabled = true

	i, err := NewIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewIntegrator failed: %v", err)
	}

	// Cleanup should not panic
	i.Cleanup()
}
