package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- CatalogCache.Get: valid cached data ---

func TestCatalogCache_Get_CacheHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"p1": map[string]any{
				"id":   "p1",
				"name": "Provider 1",
				"api":  "https://api.p1.com",
				"models": map[string]any{
					"m1": map[string]any{
						"id":   "m1",
						"name": "Model 1",
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

	cc := NewCatalogCache(srv.URL)

	// First call fetches
	cat, err := cc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(cat.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(cat.Providers))
	}

	// Second call should use cache (no HTTP request)
	cat2, err := cc.Get()
	if err != nil {
		t.Fatalf("Get cached: %v", err)
	}
	if cat2 != cat {
		t.Error("expected same cached catalog pointer")
	}
}

// --- CatalogCache.refresh: stale data returned on fetch error ---

func TestCatalogCache_Refresh_StaleFallback(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call succeeds
			catalog := map[string]any{
				"p1": map[string]any{"id": "p1", "name": "P1", "api": "https://api.p1.com",
					"models": map[string]any{}},
			}
			json.NewEncoder(w).Encode(catalog)
		} else {
			// Subsequent calls fail
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	cc := NewCatalogCache(srv.URL)

	// First fetch populates cache
	cat, err := cc.Get()
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if cat == nil {
		t.Fatal("expected non-nil catalog")
	}

	// Expire the cache
	cc.fetchedAt = time.Now().Add(-25 * time.Hour)

	// Second fetch fails but should return stale data
	cat2, err := cc.Get()
	if err != nil {
		t.Fatalf("expected stale fallback, got error: %v", err)
	}
	if cat2 == nil {
		t.Fatal("expected stale catalog")
	}
}

// --- FetchCatalog: non-200 status ---

func TestFetchCatalog_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := FetchCatalog(srv.URL)
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}

// --- FetchCatalog: malformed JSON ---

func TestFetchCatalog_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := FetchCatalog(srv.URL)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// --- FetchCatalog: provider with missing name/id gets defaulted ---

func TestFetchCatalog_DefaultNameID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"my-provider": map[string]any{
				// No "id" or "name" fields — should default to map key
				"api": "https://api.my.com",
				"models": map[string]any{
					"m1": map[string]any{"id": "m1", "name": "M1"},
				},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cat, err := FetchCatalog(srv.URL)
	if err != nil {
		t.Fatalf("FetchCatalog: %v", err)
	}
	p := cat.Providers["my-provider"]
	if p.ID != "my-provider" {
		t.Errorf("expected ID 'my-provider', got %q", p.ID)
	}
	if p.Name != "my-provider" {
		t.Errorf("expected Name 'my-provider', got %q", p.Name)
	}
}

// --- FetchCatalog: malformed provider skipped ---

func TestFetchCatalog_MalformedProviderSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One valid, one invalid (not a valid ProviderInfo JSON object)
		w.Write([]byte(`{"good":{"id":"good","name":"Good","models":{"m":{"id":"m","name":"M"}}},"bad":"not-an-object"}`))
	}))
	defer srv.Close()

	cat, err := FetchCatalog(srv.URL)
	if err != nil {
		t.Fatalf("FetchCatalog: %v", err)
	}
	if len(cat.Providers) != 1 {
		t.Errorf("expected 1 provider (bad skipped), got %d", len(cat.Providers))
	}
	if _, ok := cat.Providers["good"]; !ok {
		t.Error("expected 'good' provider")
	}
}

// --- Summaries: model without text modality filtered out ---

func TestCatalogCache_Summaries_NonTextFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"p1": map[string]any{
				"id": "p1", "name": "P1", "api": "https://api.p1.com",
				"models": map[string]any{
					"text-model": map[string]any{
						"id":   "text-model",
						"name": "Text Model",
						"modalities": map[string]any{
							"input":  []string{"text"},
							"output": []string{"text"},
						},
					},
					"image-model": map[string]any{
						"id":   "image-model",
						"name": "Image Model",
						"modalities": map[string]any{
							"input":  []string{"image"},
							"output": []string{"image"},
						},
					},
				},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cc := NewCatalogCache(srv.URL)
	summaries, err := cc.Summaries()
	if err != nil {
		t.Fatalf("Summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	// Only text-model should be included
	for _, m := range summaries[0].Models {
		if m.ID == "image-model" {
			t.Error("image model should be filtered out")
		}
	}
}

// --- Summaries: provider with no models filtered out ---

func TestCatalogCache_Summaries_NoModelsFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"empty": map[string]any{
				"id": "empty", "name": "Empty", "api": "https://api.empty.com",
				"models": map[string]any{},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cc := NewCatalogCache(srv.URL)
	summaries, err := cc.Summaries()
	if err != nil {
		t.Fatalf("Summaries: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries for empty provider, got %d", len(summaries))
	}
}

// --- Store: NewStore creates directory ---

func TestNewStore_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "subdir", "ai")
	store := NewStore(dir)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("expected directory %s to exist", dir)
	}
	// Config file should exist
	configFile := filepath.Join(dir, "ai_config.json")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Errorf("expected config file %s to exist", configFile)
	}
}

// --- Store: NewStore empty path defaults ---

func TestNewStore_EmptyPath(t *testing.T) {
	store := NewStore("")
	if store == nil {
		t.Fatal("expected non-nil store with empty path")
	}
}

// --- Store: save and reload ---

func TestStore_SaveAndReload(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID:   "openai",
		ProviderName: "OpenAI",
		ModelID:      "gpt-4o",
		ModelName:    "GPT-4o",
		APIKey:       "sk-test-key",
		BaseURL:      "https://api.openai.com/v1",
	}
	if err := store.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// Add a result
	if err := store.AddResult(AnalysisResult{
		ID:         "r1",
		Summary:    "test analysis",
		TokensUsed: 100,
		CostUSD:    0.01,
		Verdicts:   []Verdict{{IP: "1.2.3.4", Action: "block", Confidence: 0.9}},
	}); err != nil {
		t.Fatalf("AddResult: %v", err)
	}

	// Reload
	store2 := NewStore(dir)
	history := store2.GetHistory(10)
	if len(history) != 1 {
		t.Fatalf("expected 1 history entry after reload, got %d", len(history))
	}
	if history[0].ID != "r1" {
		t.Errorf("expected ID 'r1', got %q", history[0].ID)
	}

	usage := store2.GetUsage()
	if usage.TotalTokensUsed != 100 {
		t.Errorf("expected 100 total tokens, got %d", usage.TotalTokensUsed)
	}
	if usage.BlocksTriggered != 1 {
		t.Errorf("expected 1 block triggered, got %d", usage.BlocksTriggered)
	}
}

// --- Store: history ring buffer trim ---

func TestStore_HistoryRingBuffer(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Add 105 results (maxHistorySize = 100)
	for i := range 105 {
		_ = store.AddResult(AnalysisResult{
			ID:         "r" + string(rune('0'+i%10)),
			TokensUsed: 10,
		})
	}

	history := store.GetHistory(0) // all
	if len(history) != 100 {
		t.Fatalf("expected 100 (max), got %d", len(history))
	}
	// Most recent first
	if history[0].ID != "r4" { // last added: i=104 → '0'+4 = '4'
		t.Errorf("expected most recent first, got %q", history[0].ID)
	}
}

// --- Store: WithinLimits boundary conditions ---

func TestStore_WithinLimits_ExactBoundary(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Track exactly 10000 tokens
	store.TrackUsage(10000)

	// Exactly at hourly token limit
	if store.WithinLimits(10000, 100000, 100) {
		t.Error("expected over limit when exactly at boundary (>=)")
	}
	// One below limit
	if !store.WithinLimits(10001, 100000, 100) {
		t.Error("expected within limits when one below boundary")
	}
	// Zero limits means no limit
	if !store.WithinLimits(0, 0, 0) {
		t.Error("zero limits should always be within limits")
	}
}

func TestStore_WithinLimits_DailyTokens(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	store.TrackUsage(50000)

	if store.WithinLimits(100000, 50000, 100) {
		t.Error("expected over daily token limit")
	}
}

func TestStore_WithinLimits_RequestsHour(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Track one request
	store.TrackUsage(100)

	if store.WithinLimits(100000, 1000000, 1) {
		t.Error("expected over requests-per-hour limit")
	}
}

// --- Client.Analyze: non-200 response ---

func TestClient_Analyze_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("overloaded"))
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL: srv.URL,
		APIKey:  "test",
		Model:   "test",
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}

// --- Client.Analyze: response with no choices ---

func TestClient_Analyze_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL:   srv.URL,
		APIKey:    "test",
		Model:     "test",
		MaxTokens: 1024,
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error for empty choices")
	}
}

// --- Client.Analyze: error from HTTP request ---

func TestClient_Analyze_Unreachable(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "http://127.0.0.1:1/v1",
		APIKey:  "test",
		Model:   "test",
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

// --- Analyzer: batch with usage limit exceeded skips API call ---

func TestAnalyzer_BatchUsageLimitExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should not be called
		t.Error("API should not be called when usage limit exceeded")
		w.WriteHeader(200)
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

	// Exhaust the usage limits first
	store.TrackUsage(100000)

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		BatchSize:       1, // flush immediately after 1 event
		BatchInterval:   time.Hour,
		MinScoreForAI:   10,
		MaxTokensHour:   1, // very small limit, already exceeded
		MaxTokensDay:    1000000,
		MaxRequestsHour: 1000,
	}, store, "")

	a.SetLogger(func(_, _ string) {})

	eventCh := make(chan engine.Event, 10)
	a.Start(eventCh)

	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     50,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 50}},
	}

	time.Sleep(200 * time.Millisecond)
	a.Stop()

	// No results should be stored since API was not called
	history := store.GetHistory(10)
	if len(history) != 0 {
		t.Errorf("expected 0 results when usage limit exceeded, got %d", len(history))
	}
}

// --- Analyzer: collectEvent and flush via channel ---

func TestAnalyzer_CollectAndFlush_SmallBatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[],"summary":"clean","threats_detected":[]}`}},
			},
			"usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
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
		Enabled:       true,
		BatchSize:     1, // flush immediately after 1 event
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
	}, store, "")

	eventCh := make(chan engine.Event, 10)
	a.Start(eventCh)
	defer a.Stop()

	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     50,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 50}},
	}

	time.Sleep(300 * time.Millisecond)

	history := store.GetHistory(10)
	if len(history) == 0 {
		t.Error("expected analysis result after collecting batch")
	}
}

// --- Analyzer: UpdateProvider ---

func TestAnalyzer_UpdateProvider_Success(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	err := a.UpdateProvider(ProviderConfig{
		ProviderID:   "openai",
		ProviderName: "OpenAI",
		ModelID:      "gpt-4o",
		ModelName:    "GPT-4o",
		APIKey:       "sk-test",
		BaseURL:      "https://api.openai.com/v1",
	})
	if err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}

	cfg := store.GetConfig()
	if cfg.ProviderID != "openai" {
		t.Errorf("expected openai, got %q", cfg.ProviderID)
	}
}

// --- Store: AddResult with monitor verdict ---

func TestStore_AddResult_MonitorVerdict(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	_ = store.AddResult(AnalysisResult{
		ID:    "r1",
		Verdicts: []Verdict{
			{IP: "1.2.3.4", Action: "monitor", Confidence: 0.6},
		},
	})

	usage := store.GetUsage()
	if usage.MonitorsTriggered != 1 {
		t.Errorf("expected 1 monitor triggered, got %d", usage.MonitorsTriggered)
	}
}

// --- Client: NewClient defaults ---

func TestNewClient_DefaultMaxTokens(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://api.example.com",
		APIKey:  "test",
		Model:   "test-model",
	})
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}
