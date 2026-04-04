package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- CatalogCache.Get: valid cached data returns same pointer ---

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
			catalog := map[string]any{
				"p1": map[string]any{
					"id": "p1", "name": "P1", "api": "https://api.p1.com",
					"models": map[string]any{},
				},
			}
			json.NewEncoder(w).Encode(catalog)
		} else {
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

// --- CatalogCache.refresh: double-check after write lock returns cached ---

func TestCatalogCache_Refresh_DoubleCheckLock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"p1": map[string]any{
				"id": "p1", "name": "P1", "api": "https://api.p1.com",
				"models": map[string]any{},
			},
		}
		json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cc := NewCatalogCache(srv.URL)

	// Pre-populate the cache so the double-check in refresh() hits
	cat, err := cc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Now expire and do a refresh via the refresh method directly.
	// The double-check should find the cache still valid (within TTL)
	// if we don't actually expire it.
	cat2, err := cc.refresh()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if cat2 != cat {
		t.Error("expected same catalog from double-check path")
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

// --- FetchCatalog: bad URL causes request creation error ---

func TestFetchCatalog_BadURL(t *testing.T) {
	// A URL with spaces will cause http.NewRequestWithContext to fail
	_, err := FetchCatalog("http://invalid host with spaces/api.json")
	if err == nil {
		t.Error("expected error for bad URL")
	}
}

// --- FetchCatalog: provider with missing name/id gets defaulted ---

func TestFetchCatalog_DefaultNameID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"my-provider": map[string]any{
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

// --- Summaries: provider with only non-text models excluded entirely ---

func TestCatalogCache_Summaries_AllModelsFiltered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"vision-only": map[string]any{
				"id": "vision-only", "name": "Vision", "api": "https://api.v.com",
				"models": map[string]any{
					"v1": map[string]any{
						"id":   "v1",
						"name": "Vision1",
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
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries when all models are non-text, got %d", len(summaries))
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

// --- Store: NewStore fallback to temp on permission error ---

func TestNewStore_FallbackToTemp(t *testing.T) {
	// On Windows, creating a dir inside a non-existent root should fail
	// and fall back to temp dir. Use a path that can't be created.
	// We use a very deep path with a null-byte-like invalid segment won't work,
	// but we can use a path under a read-only location.
	// Instead, try creating under a path where parent is a file (not a dir).
	tmpFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	badPath := filepath.Join(tmpFile, "sub", "ai")

	store := NewStore(badPath)
	if store == nil {
		t.Fatal("expected non-nil store even on MkdirAll failure")
	}
	// Should have fallen back to temp dir
	if store.path == badPath {
		t.Error("expected fallback to temp dir, got original path")
	}
}

// --- Store: NewStore loads existing config ---

func TestNewStore_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "ai_config.json")

	existing := storeData{
		Config: ProviderConfig{
			ProviderID: "openai",
			ModelID:    "gpt-4o",
			APIKey:     "sk-existing",
			BaseURL:    "https://api.openai.com/v1",
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	_ = os.WriteFile(configFile, data, 0o600)

	store := NewStore(dir)
	cfg := store.GetConfig()
	if cfg.ProviderID != "openai" {
		t.Errorf("expected 'openai', got %q", cfg.ProviderID)
	}
	if cfg.APIKey != "sk-existing" {
		t.Errorf("expected 'sk-existing', got %q", cfg.APIKey)
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

// --- Store: save with relative path ---

func TestStore_Save_RelativePath(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Force a relative path to exercise the relative-path resolution in save()
	store.path = "data/ai_rel_test"

	cfg := ProviderConfig{
		ProviderID: "test",
		ModelID:    "model",
		APIKey:     "key",
		BaseURL:    "https://api.example.com",
	}
	err := store.SetConfig(cfg)
	if err != nil {
		t.Fatalf("SetConfig with relative path: %v", err)
	}

	// Verify it was saved to the relative path
	abs, _ := filepath.Abs("data/ai_rel_test")
	configFile := filepath.Join(abs, "ai_config.json")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		t.Errorf("expected config at %s", configFile)
	}

	// Clean up
	os.RemoveAll("data/ai_rel_test")
}

// --- Store: history ring buffer trim ---

func TestStore_HistoryRingBuffer(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

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
	if history[0].ID != "r4" { // last added: i=104 -> '0'+4 = '4'
		t.Errorf("expected most recent first, got %q", history[0].ID)
	}
}

// --- Store: WithinLimits boundary conditions ---

func TestStore_WithinLimits_ExactBoundary(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	store.TrackUsage(10000)

	// Exactly at hourly token limit (>= check)
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

	store.TrackUsage(100)

	if store.WithinLimits(100000, 1000000, 1) {
		t.Error("expected over requests-per-hour limit")
	}
}

// --- Store: GetHistory with limit ---

func TestStore_GetHistory_WithLimit(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	for i := range 10 {
		_ = store.AddResult(AnalysisResult{
			ID:         fmt.Sprintf("r%d", i),
			TokensUsed: 10,
		})
	}

	// Get 5 most recent
	history := store.GetHistory(5)
	if len(history) != 5 {
		t.Fatalf("expected 5, got %d", len(history))
	}
	// Most recent is r9
	if history[0].ID != "r9" {
		t.Errorf("expected r9 first, got %q", history[0].ID)
	}
}

// --- Store: GetUsage returns correct stats ---

func TestStore_GetUsage_Stats(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	_ = store.AddResult(AnalysisResult{
		ID:         "r1",
		TokensUsed: 500,
		CostUSD:    0.05,
		Verdicts: []Verdict{
			{IP: "1.2.3.4", Action: "block", Confidence: 0.9},
			{IP: "5.6.7.8", Action: "monitor", Confidence: 0.6},
		},
	})

	usage := store.GetUsage()
	if usage.TotalTokensUsed != 500 {
		t.Errorf("expected 500 total tokens, got %d", usage.TotalTokensUsed)
	}
	if usage.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", usage.TotalRequests)
	}
	if usage.TotalCostUSD != 0.05 {
		t.Errorf("expected 0.05 cost, got %f", usage.TotalCostUSD)
	}
	if usage.BlocksTriggered != 1 {
		t.Errorf("expected 1 block, got %d", usage.BlocksTriggered)
	}
	if usage.MonitorsTriggered != 1 {
		t.Errorf("expected 1 monitor, got %d", usage.MonitorsTriggered)
	}
}

// --- Store: AddResult with monitor verdict ---

func TestStore_AddResult_MonitorVerdict(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	_ = store.AddResult(AnalysisResult{
		ID: "r1",
		Verdicts: []Verdict{
			{IP: "1.2.3.4", Action: "monitor", Confidence: 0.6},
		},
	})

	usage := store.GetUsage()
	if usage.MonitorsTriggered != 1 {
		t.Errorf("expected 1 monitor triggered, got %d", usage.MonitorsTriggered)
	}
}

// --- Store: AddResult multiple results persist ---

func TestStore_AddResult_MultiplePersist(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	for i := range 5 {
		_ = store.AddResult(AnalysisResult{
			ID:         fmt.Sprintf("r%d", i),
			TokensUsed: 100 * (i + 1),
			CostUSD:    float64(i) * 0.01,
		})
	}

	// Reload from disk
	store2 := NewStore(dir)
	history := store2.GetHistory(0)
	if len(history) != 5 {
		t.Fatalf("expected 5 persisted results, got %d", len(history))
	}

	usage := store2.GetUsage()
	if usage.TotalTokensUsed != 1500 { // 100+200+300+400+500
		t.Errorf("expected 1500 total tokens, got %d", usage.TotalTokensUsed)
	}
	if usage.TotalRequests != 5 {
		t.Errorf("expected 5 total requests, got %d", usage.TotalRequests)
	}
}

// --- Store: save error (read-only directory) ---

func TestStore_Save_Error(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Make the config file a directory to cause WriteFile to fail
	configFile := filepath.Join(dir, "ai_config.json")
	os.Remove(configFile)
	os.MkdirAll(configFile, 0o755)

	err := store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test",
		APIKey:     "key",
		BaseURL:    "https://api.example.com",
	})
	if err == nil {
		t.Error("expected error when writing to directory-as-file")
	}

	// Clean up the directory so other tests aren't affected
	os.Remove(configFile)
}

// --- Summaries: Get() error propagation ---

func TestCatalogCache_Summaries_GetError(t *testing.T) {
	// Create a cache pointing to unreachable URL, never fetched before
	cc := NewCatalogCache("http://127.0.0.1:1/nonexistent")

	_, err := cc.Summaries()
	if err == nil {
		t.Error("expected error from Summaries when Get fails")
	}
}

// --- Store: save MkdirAll error ---

func TestStore_Save_MkdirAllError(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Make the store path point to a file (not a directory), so MkdirAll fails
	filePath := filepath.Join(t.TempDir(), "blocker")
	os.WriteFile(filePath, []byte("x"), 0o600)
	store.path = filePath

	err := store.save()
	if err == nil {
		t.Error("expected error when MkdirAll fails (path is a file)")
	}
}

// --- Client.Analyze: bad URL (NewRequestWithContext error) ---

func TestClient_Analyze_BadURL(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "http://invalid host spaces/v1",
		APIKey:  "test",
		Model:   "test",
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error for bad URL")
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

// --- Client.Analyze: response with error field ---

func TestClient_Analyze_ResponseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{},
			"usage":   map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
			"error":   map[string]any{"message": "rate limit exceeded", "type": "rate_limit"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL: srv.URL,
		APIKey:  "test",
		Model:   "test",
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error from API error field")
	}
}

// --- Client.Analyze: invalid JSON response ---

func TestClient_Analyze_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL: srv.URL,
		APIKey:  "test",
		Model:   "test",
	})

	_, _, err := client.Analyze(context.Background(), "sys", "user")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// --- Client.Analyze: error from unreachable HTTP server ---

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

// --- Client.Analyze: context canceled ---

func TestClient_Analyze_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL: srv.URL,
		APIKey:  "test",
		Model:   "test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err := client.Analyze(ctx, "sys", "user")
	if err == nil {
		t.Error("expected error for canceled context")
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
	if client.maxTokens != 2048 {
		t.Errorf("expected default maxTokens 2048, got %d", client.maxTokens)
	}
}

// --- Analyzer: loop exits on channel close ---

func TestAnalyzer_Loop_ChannelClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[],"summary":"ok","threats_detected":[]}`}},
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
		Enabled:       true,
		BatchSize:     1,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
	}, store, "")

	eventCh := make(chan engine.Event, 10)
	a.Start(eventCh)

	// Send an event then close the channel
	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     50,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 50}},
	}
	close(eventCh)

	// Wait for the goroutine to finish (loop should exit on channel close)
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// loop exited cleanly via channel close
	case <-time.After(3 * time.Second):
		t.Fatal("loop did not exit after channel close")
	}
}

// --- Analyzer: flushBatch with no client configured ---

func TestAnalyzer_FlushBatch_NoClient(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	// No provider config set, so client is nil

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:       true,
		BatchSize:     1,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
	}, store, "")

	a.SetLogger(func(_, _ string) {})

	eventCh := make(chan engine.Event, 10)
	a.Start(eventCh)

	// Send event that triggers batch flush (BatchSize=1)
	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     50,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 50}},
	}

	time.Sleep(200 * time.Millisecond)
	a.Stop()

	// No results because no client was configured
	history := store.GetHistory(10)
	if len(history) != 0 {
		t.Errorf("expected 0 results without client, got %d", len(history))
	}
}

// --- Analyzer: flushBatch with AI analysis error ---

func TestAnalyzer_FlushBatch_AnalysisError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
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
		BatchSize:     1,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
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

	time.Sleep(300 * time.Millisecond)
	a.Stop()

	// Result should be stored with error
	history := store.GetHistory(10)
	if len(history) == 0 {
		t.Fatal("expected result even on error")
	}
	if history[0].Error == "" {
		t.Error("expected error message in result")
	}
}

// --- Analyzer: flushBatch with JSON parse error from AI ---

func TestAnalyzer_FlushBatch_ParseError(t *testing.T) {
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
		Enabled:       true,
		BatchSize:     1,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
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

	time.Sleep(300 * time.Millisecond)
	a.Stop()

	history := store.GetHistory(10)
	if len(history) == 0 {
		t.Fatal("expected result even on parse error")
	}
	if history[0].Error == "" {
		t.Error("expected parse error in result")
	}
	if history[0].Summary == "" {
		t.Error("expected raw text in summary")
	}
}

// --- Analyzer: batch with usage limit exceeded skips API call ---

func TestAnalyzer_BatchUsageLimitExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	store.TrackUsage(100000)

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		BatchSize:       1,
		BatchInterval:   time.Hour,
		MinScoreForAI:   10,
		MaxTokensHour:   1,
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

	history := store.GetHistory(10)
	if len(history) != 0 {
		t.Errorf("expected 0 results when usage limit exceeded, got %d", len(history))
	}
}

// --- Analyzer: UpdateProvider success ---

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

// --- Analyzer: UpdateProvider error (save fails) ---

func TestAnalyzer_UpdateProvider_SaveError(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Make config file a directory so save fails
	configFile := filepath.Join(dir, "ai_config.json")
	os.Remove(configFile)
	os.MkdirAll(configFile, 0o755)

	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	err := a.UpdateProvider(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test",
		APIKey:     "key",
		BaseURL:    "https://api.example.com",
	})
	if err == nil {
		t.Error("expected error when save fails")
	}

	// Clean up
	os.Remove(configFile)
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
		BatchSize:     1,
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

// --- Analyzer: loop stopCh path ---

func TestAnalyzer_Loop_StopCh(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test",
		APIKey:     "key",
		BaseURL:    "https://fake.url",
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:       true,
		BatchSize:     100,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
	}, store, "")

	eventCh := make(chan engine.Event, 100)
	a.Start(eventCh)

	// Send some events but don't fill the batch
	for i := range 3 {
		eventCh <- engine.Event{
			ClientIP:  fmt.Sprintf("1.2.3.%d", i),
			Score:     50,
			Action:    engine.ActionBlock,
			Timestamp: time.Now(),
		}
	}

	time.Sleep(100 * time.Millisecond)
	a.Stop()
	// Should exit cleanly via stopCh
}

// --- Analyzer: ManualAnalyze with usage limit exceeded ---

func TestAnalyzer_ManualAnalyze_UsageLimitExceeded(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    "https://fake.url",
	})

	// Exhaust the limit
	store.TrackUsage(100000)

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		MaxTokensHour:   1, // very low, already exceeded
		MaxTokensDay:    1000000,
		MaxRequestsHour: 1000,
	}, store, "")

	_, err := a.ManualAnalyze([]engine.Event{
		{ClientIP: "1.2.3.4", Method: "GET", Path: "/", Timestamp: time.Now()},
	})
	if err == nil {
		t.Error("expected usage limit error")
	}
}

// --- Analyzer: flushBatch via ticker ---

func TestAnalyzer_FlushViaTicker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[],"summary":"ok","threats_detected":[]}`}},
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
		Enabled:       true,
		BatchSize:     100, // large so events don't trigger immediate flush
		BatchInterval: 100 * time.Millisecond,
		MinScoreForAI: 10,
	}, store, "")

	eventCh := make(chan engine.Event, 100)
	a.Start(eventCh)

	// Send fewer events than BatchSize
	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     50,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 50}},
	}

	// Wait for ticker to fire
	time.Sleep(500 * time.Millisecond)
	a.Stop()

	history := store.GetHistory(10)
	if len(history) == 0 {
		t.Error("expected result from ticker-triggered flush")
	}
}
