package ratelimit

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- AddRule ---

func TestAddRule_NewRule(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	// Add a new rule
	layer.AddRule(Rule{ID: "r2", Scope: "path", Limit: 5, Window: time.Second, Burst: 5, Action: "block"})
	if len(layer.config.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(layer.config.Rules))
	}
}

func TestAddRule_ReplaceExisting(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	// Replace existing rule
	layer.AddRule(Rule{ID: "r1", Scope: "ip", Limit: 100, Window: time.Second, Burst: 100, Action: "log"})
	if len(layer.config.Rules) != 1 {
		t.Errorf("expected 1 rule (replaced), got %d", len(layer.config.Rules))
	}
	if layer.config.Rules[0].Limit != 100 {
		t.Errorf("expected limit 100, got %d", layer.config.Rules[0].Limit)
	}
}

// --- RemoveRule ---

func TestRemoveRule_Found(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
			{ID: "r2", Scope: "path", Limit: 5, Window: time.Second, Burst: 5, Action: "block"},
		},
	})

	removed := layer.RemoveRule("r1")
	if !removed {
		t.Error("expected rule to be removed")
	}
	if len(layer.config.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(layer.config.Rules))
	}
	if layer.config.Rules[0].ID != "r2" {
		t.Errorf("expected r2 to remain, got %s", layer.config.Rules[0].ID)
	}
}

func TestRemoveRule_NotFound(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: time.Second, Burst: 10, Action: "block"},
		},
	})

	removed := layer.RemoveRule("nonexistent")
	if removed {
		t.Error("expected false for nonexistent rule")
	}
	if len(layer.config.Rules) != 1 {
		t.Error("rule should not be removed")
	}
}

func TestRemoveRule_CleansBuckets(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 10, Window: 1 * time.Second, Burst: 10, Action: "block"},
		},
	}
	layer := NewLayer(&cfg)

	// Create a bucket entry
	ctx := makeContext("192.0.2.1", "/api/test")
	layer.Process(ctx)

	// Verify bucket exists
	count := 0
	layer.buckets.Range(func(_, _ any) bool { count++; return true })
	if count == 0 {
		t.Fatal("expected at least one bucket after processing")
	}

	// Remove rule — should clean up buckets
	removed := layer.RemoveRule("r1")
	if !removed {
		t.Error("expected rule to be removed")
	}

	count = 0
	layer.buckets.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("expected 0 buckets after rule removal, got %d", count)
	}
}

// --- Process with dynamic rule changes ---

func TestProcess_AddRuleThenBlock(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules:   []Rule{},
	})

	// Initially no rules, should pass
	ctx := makeContext("192.0.2.1", "/api/test")
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with no rules, got %v", result.Action)
	}

	// Add a very restrictive rule
	layer.AddRule(Rule{ID: "strict", Scope: "ip", Limit: 2, Window: 1 * time.Second, Burst: 2, Action: "block"})

	// First 2 should pass
	for i := 0; i < 2; i++ {
		ctx := makeContext("192.0.2.1", "/api/test")
		result := layer.Process(ctx)
		if result.Action == engine.ActionBlock {
			t.Errorf("request %d should pass", i+1)
		}
	}

	// 3rd should block
	ctx = makeContext("192.0.2.1", "/api/test")
	result = layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block after exceeding limit, got %v", result.Action)
	}
}

// --- RemoveRule then process should pass ---

func TestProcess_RemoveRuleThenPass(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Rules: []Rule{
			{ID: "r1", Scope: "ip", Limit: 1, Window: 1 * time.Second, Burst: 1, Action: "block"},
		},
	})

	// Use up the limit
	ctx := makeContext("192.0.2.1", "/api/test")
	layer.Process(ctx)

	// Next should block
	ctx = makeContext("192.0.2.1", "/api/test")
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Error("expected block")
	}

	// Remove rule
	layer.RemoveRule("r1")

	// Should now pass (no rules)
	ctx = makeContext("192.0.2.1", "/api/test")
	result = layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass after removing all rules, got %v", result.Action)
	}
}
