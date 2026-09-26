package main

// Regression: the MCP adapter's config-mutating methods Reloaded the engine
// but persisted nothing, so every operator posture change made through MCP
// tools (mode, CRS paranoia/exclusions, API-validation flags, client-side
// settings) was reverted by a restart. Fixed with the round-74 persistence
// contract shared with the dashboard's config-mutating handlers: oldCfg
// snapshot, Reload, then persistFn (config.SaveFile(cfgPath, eng.Config()),
// wired by newMCPAdapter from the operator's config path) with fail-rollback.
// AddCRSExclusion additionally reverts the layer-side DisableRule on rollback
// — Reload cannot undo layer-internal state (the CRS round-74 lesson).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
)

type mcpPersistMockEventStore struct{}

func (mcpPersistMockEventStore) Store(event engine.Event) error { return nil }
func (mcpPersistMockEventStore) Close() error                   { return nil }

type mcpPersistMockEventBus struct{}

func (mcpPersistMockEventBus) Subscribe(ch chan<- engine.Event) {}
func (mcpPersistMockEventBus) Publish(event engine.Event)       {}
func (mcpPersistMockEventBus) Close()                           {}

// newMCPAdapterPersistenceHarness writes a config file at a temp path, loads
// the engine from it, and returns an adapter persisting to that path.
func newMCPAdapterPersistenceHarness(t *testing.T) (*engine.Engine, *mcpEngineAdapter, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := config.DefaultConfig()
	if err := config.SaveFile(cfgPath, cfg); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	e, err := engine.NewEngine(loaded, mcpPersistMockEventStore{}, mcpPersistMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	adapter := &mcpEngineAdapter{engine: e, cfg: loaded}
	adapter.persistFn = func() error { return config.SaveFile(cfgPath, e.Config()) }
	return e, adapter, cfgPath
}

// addMCPTestCRSLayer registers a CRS layer holding one loadable rule so
// AddCRSExclusion's existence check passes.
func addMCPTestCRSLayer(t *testing.T, e *engine.Engine) {
	t.Helper()
	rulePath := filepath.Join(t.TempDir(), "zz-rule.conf")
	rule := "SecRule REQUEST_URI \"@contains /zz-probe\" \"id:950001,phase:1,pass\"\n"
	if err := os.WriteFile(rulePath, []byte(rule), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	crsLayer := crs.NewLayer(&crs.Config{Enabled: true, ParanoiaLevel: 1, RulePath: rulePath})
	e.AddLayer(engine.OrderedLayer{Layer: crsLayer, Order: engine.OrderCRS})
}

func persistBoolPtr(b bool) *bool { return &b }

// TestMCPAdapterConfigMethodsPersist drives every config-mutating adapter
// method through the real Reload + persist path and asserts the config file
// reflects the change.
func TestMCPAdapterConfigMethodsPersist(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, e *engine.Engine)
		invoke func(t *testing.T, a *mcpEngineAdapter) error
		assert func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "SetMode",
			invoke: func(t *testing.T, a *mcpEngineAdapter) error {
				return a.SetMode("monitor")
			},
			assert: func(t *testing.T, cfg *config.Config) {
				if cfg.Mode != "monitor" {
					t.Fatalf("Mode = %q, want %q", cfg.Mode, "monitor")
				}
			},
		},
		{
			name: "SetParanoiaLevel",
			invoke: func(t *testing.T, a *mcpEngineAdapter) error {
				return a.SetParanoiaLevel(3)
			},
			assert: func(t *testing.T, cfg *config.Config) {
				if cfg.WAF.CRS.ParanoiaLevel != 3 {
					t.Fatalf("ParanoiaLevel = %d, want 3", cfg.WAF.CRS.ParanoiaLevel)
				}
			},
		},
		{
			name: "SetAPIValidationMode",
			invoke: func(t *testing.T, a *mcpEngineAdapter) error {
				return a.SetAPIValidationMode(nil, nil, persistBoolPtr(true), nil)
			},
			assert: func(t *testing.T, cfg *config.Config) {
				if !cfg.WAF.APIValidation.StrictMode {
					t.Fatalf("APIValidation.StrictMode = false, want true")
				}
			},
		},
		{
			name: "SetClientSideMode",
			invoke: func(t *testing.T, a *mcpEngineAdapter) error {
				return a.SetClientSideMode("strict", nil, nil, persistBoolPtr(true))
			},
			assert: func(t *testing.T, cfg *config.Config) {
				if cfg.WAF.ClientSide.Mode != "strict" {
					t.Fatalf("ClientSide.Mode = %q, want %q", cfg.WAF.ClientSide.Mode, "strict")
				}
				if !cfg.WAF.ClientSide.CSP.Enabled {
					t.Fatalf("ClientSide.CSP.Enabled = false, want true")
				}
			},
		},
		{
			name: "AddCRSExclusion",
			setup: func(t *testing.T, e *engine.Engine) {
				addMCPTestCRSLayer(t, e)
			},
			invoke: func(t *testing.T, a *mcpEngineAdapter) error {
				return a.AddCRSExclusion("950001", "/zz", "", "test")
			},
			assert: func(t *testing.T, cfg *config.Config) {
				found := false
				for _, id := range cfg.WAF.CRS.DisabledRules {
					if id == "950001" {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("CRS.DisabledRules = %v, want it to contain 950001", cfg.WAF.CRS.DisabledRules)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, adapter, cfgPath := newMCPAdapterPersistenceHarness(t)
			if tc.setup != nil {
				tc.setup(t, e)
			}

			if err := tc.invoke(t, adapter); err != nil {
				t.Fatalf("invoke: %v", err)
			}

			reloaded, err := config.LoadFile(cfgPath)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			tc.assert(t, reloaded)
		})
	}
}

// TestMCPAdapterPersistFailureRollsBack asserts the fail-rollback contract:
// a failing persistFn returns an error, restores the prior runtime posture,
// leaves the config file untouched, and (for the exclusion path) undoes the
// layer-side disable.
func TestMCPAdapterPersistFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := config.DefaultConfig()
	if err := config.SaveFile(cfgPath, cfg); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	e, err := engine.NewEngine(loaded, mcpPersistMockEventStore{}, mcpPersistMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	addMCPTestCRSLayer(t, e)

	adapter := &mcpEngineAdapter{engine: e, cfg: loaded}
	adapter.persistFn = func() error { return errors.New("disk full") }

	if err := adapter.SetParanoiaLevel(3); err == nil {
		t.Fatalf("SetParanoiaLevel: want persistence-failure error, got nil")
	}
	if got := e.Config().WAF.CRS.ParanoiaLevel; got != loaded.WAF.CRS.ParanoiaLevel {
		t.Fatalf("rollback: runtime ParanoiaLevel %d, want restored %d", got, loaded.WAF.CRS.ParanoiaLevel)
	}
	reloaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if reloaded.WAF.CRS.ParanoiaLevel == 3 {
		t.Fatalf("rollback: config file was updated despite failing persistence")
	}

	if err := adapter.AddCRSExclusion("950001", "/zz", "", "test"); err == nil {
		t.Fatalf("AddCRSExclusion: want persistence-failure error, got nil")
	}
	crsLayer, ok := e.FindLayer("crs").(*crs.Layer)
	if !ok {
		t.Fatalf("CRS layer missing after setup")
	}
	if !crsLayer.IsRuleEnabled("950001") {
		t.Fatalf("rollback: rule 950001 still disabled in the layer after persistence failure")
	}
}

// TestMCPAdapterNilPersistFNSkipsPersistence pins the nil-guard that keeps
// bare adapters (and every test constructing one without a config path) on
// the pre-fix behavior: the mutation applies at runtime, nothing persists.
func TestMCPAdapterNilPersistFNSkipsPersistence(t *testing.T) {
	e, adapter, cfgPath := newMCPAdapterPersistenceHarness(t)
	adapter.persistFn = nil

	if err := adapter.SetParanoiaLevel(3); err != nil {
		t.Fatalf("SetParanoiaLevel: %v", err)
	}
	if got := e.Config().WAF.CRS.ParanoiaLevel; got != 3 {
		t.Fatalf("runtime ParanoiaLevel = %d, want 3", got)
	}
	reloaded, err := config.LoadFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if reloaded.WAF.CRS.ParanoiaLevel == 3 {
		t.Fatalf("bare adapter unexpectedly persisted the config file")
	}
}
