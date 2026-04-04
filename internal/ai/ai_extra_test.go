package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- SetLogger ---

func TestAnalyzer_SetLogger(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	called := false
	a.SetLogger(func(level, msg string) { called = true })
	a.logs("info", "test")
	if !called {
		t.Error("expected logger to be called")
	}
}

// --- SetBlocker ---

type mockBlocker struct {
	calls []string
}

func (m *mockBlocker) AddAutoBan(ip string, reason string, ttl time.Duration) {
	m.calls = append(m.calls, ip)
}

func TestAnalyzer_SetBlocker(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true, AutoBlockEnabled: true, AutoBlockTTL: time.Hour}, store, "")

	var mb mockBlocker
	a.SetBlocker(&mb)
	a.applyVerdicts([]Verdict{{IP: "1.2.3.4", Action: "block", Confidence: 0.85}})
	if len(mb.calls) != 1 || mb.calls[0] != "1.2.3.4" {
		t.Errorf("expected [1.2.3.4], got %v", mb.calls)
	}
}

// --- ManualAnalyze ---

func TestAnalyzer_ManualAnalyze(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[{"ip":"1.2.3.4","action":"block","reason":"suspicious","confidence":0.85}],"summary":"threat detected","threats_detected":["sqli"]}`}},
			},
			"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		MaxTokensHour:   50000,
		MaxTokensDay:    500000,
		MaxRequestsHour: 30,
	}, store, "")

	events := []engine.Event{
		{
			ClientIP:  "1.2.3.4",
			Method:    "POST",
			Path:      "/login",
			Score:     80,
			Action:    engine.ActionBlock,
			Timestamp: time.Now(),
			Findings:  []engine.Finding{{DetectorName: "sqli", Description: "SQL injection", Score: 80}},
		},
	}

	result, err := a.ManualAnalyze(events)
	if err != nil {
		t.Fatalf("ManualAnalyze error: %v", err)
	}
	if result.Summary != "threat detected" {
		t.Errorf("expected 'threat detected', got %q", result.Summary)
	}
	if result.EventCount != 1 {
		t.Errorf("expected 1 event, got %d", result.EventCount)
	}
	if result.TokensUsed != 150 {
		t.Errorf("expected 150 tokens, got %d", result.TokensUsed)
	}
}

func TestAnalyzer_ManualAnalyze_NoProvider(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	_, err := a.ManualAnalyze([]engine.Event{})
	if err == nil {
		t.Error("expected error without provider")
	}
}

// --- UpdateProvider ---

func TestAnalyzer_UpdateProvider(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	err := a.UpdateProvider(ProviderConfig{
		ProviderID: "openai",
		ModelID:    "gpt-4o-mini",
		APIKey:     "sk-test",
		BaseURL:    "https://api.openai.com/v1",
	})
	if err != nil {
		t.Fatalf("UpdateProvider error: %v", err)
	}

	cfg := store.GetConfig()
	if cfg.ModelID != "gpt-4o-mini" {
		t.Errorf("expected gpt-4o-mini, got %q", cfg.ModelID)
	}
	if a.client == nil {
		t.Error("expected client to be created")
	}
}

// --- GetCatalog ---

func TestAnalyzer_GetCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"test-provider": map[string]any{
				"id":   "test-provider",
				"name": "Test Provider",
				"api":  "https://api.test.com/v1",
				"models": map[string]any{
					"model-1": map[string]any{
						"id":   "model-1",
						"name": "Test Model",
						"modalities": map[string]any{
							"input":  []string{"text"},
							"output": []string{"text"},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, srv.URL)

	summaries, err := a.GetCatalog()
	if err != nil {
		t.Fatalf("GetCatalog error: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 provider, got %d", len(summaries))
	}
}

// --- GetStore ---

func TestAnalyzer_GetStore(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	if a.GetStore() != store {
		t.Error("expected same store reference")
	}
}

// --- TestConnection ---

func TestAnalyzer_TestConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "ok"}},
			},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	if err := a.TestConnection(); err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
}

func TestAnalyzer_TestConnection_NoProvider(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	if err := a.TestConnection(); err == nil {
		t.Error("expected error without provider")
	}
}

// --- Store.Path ---

func TestStore_Path(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	if store.Path() != dir {
		t.Errorf("expected %q, got %q", dir, store.Path())
	}
}

// --- Client.TestConnection ---

func TestClient_TestConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "ok"}},
			},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL: srv.URL,
		APIKey:  "test-key",
		Model:   "test-model",
	})

	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
}

// --- applyVerdicts with blocker ---

func TestAnalyzer_ApplyVerdicts(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{
		Enabled:          true,
		AutoBlockEnabled: true,
		AutoBlockTTL:     time.Hour,
	}, store, "")

	var mb mockBlocker
	a.SetBlocker(&mb)

	verdicts := []Verdict{
		{IP: "1.2.3.4", Action: "block", Reason: "malicious", Confidence: 0.85},
		{IP: "5.6.7.8", Action: "block", Reason: "suspicious", Confidence: 0.50}, // below 0.7 threshold
		{IP: "9.10.11.12", Action: "monitor", Reason: "watch", Confidence: 0.90}, // not block action
	}

	a.applyVerdicts(verdicts)

	if len(mb.calls) != 1 || mb.calls[0] != "1.2.3.4" {
		t.Errorf("expected only 1.2.3.4 blocked, got %v", mb.calls)
	}
}

// --- ManualAnalyze with parse error ---

func TestAnalyzer_ManualAnalyze_ParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": "This is not valid JSON response"}},
			},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		MaxTokensHour:   50000,
		MaxTokensDay:    500000,
		MaxRequestsHour: 30,
	}, store, "")

	events := []engine.Event{
		{
			ClientIP:  "1.2.3.4",
			Method:    "POST",
			Path:      "/login",
			Score:     50,
			Timestamp: time.Now(),
		},
	}

	result, err := a.ManualAnalyze(events)
	if err != nil {
		t.Fatalf("should not return error for parse error: %v", err)
	}
	if result.Error == "" {
		t.Error("expected parse error in result")
	}
	if result.Summary == "" {
		t.Error("expected raw text in summary")
	}
}

// --- ManualAnalyze with usage limit exceeded ---

func TestAnalyzer_ManualAnalyze_UsageLimit(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    "https://fake.url",
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		MaxTokensHour:   0, // zero = no tokens allowed
		MaxTokensDay:    0,
		MaxRequestsHour: 0,
	}, store, "")

	_, err := a.ManualAnalyze([]engine.Event{
		{ClientIP: "1.2.3.4", Method: "GET", Path: "/", Timestamp: time.Now()},
	})
	if err == nil {
		t.Error("expected usage limit error")
	}
}

// --- CatalogCache.Get with error ---

func TestCatalogCache_Get_Error(t *testing.T) {
	cc := NewCatalogCache("http://127.0.0.1:1/nonexistent")
	_, err := cc.Get()
	if err == nil {
		t.Error("expected error from unreachable URL")
	}
}

// --- Provider Config Defaults ---

func TestProviderConfig_Empty(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	cfg := store.GetConfig()
	if cfg.ProviderID != "" {
		t.Errorf("expected empty provider, got %q", cfg.ProviderID)
	}
	if store.HasConfig() {
		t.Error("expected no config without API key")
	}
}
