package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewCatalogCache(t *testing.T) {
	cc := NewCatalogCache("")
	if cc.url != defaultCatalogURL {
		t.Errorf("expected default URL, got %s", cc.url)
	}

	cc2 := NewCatalogCache("https://custom.url/api.json")
	if cc2.url != "https://custom.url/api.json" {
		t.Errorf("expected custom URL, got %s", cc2.url)
	}
}

func TestFetchCatalog_MockServer(t *testing.T) {
	// Mock models.dev API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"test-provider": map[string]any{
				"id":   "test-provider",
				"name": "Test Provider",
				"api":  "https://api.test.com/v1",
				"doc":  "https://docs.test.com",
				"models": map[string]any{
					"test-model-1": map[string]any{
						"id":     "test-model-1",
						"name":   "Test Model",
						"family": "test",
						"modalities": map[string]any{
							"input":  []string{"text"},
							"output": []string{"text"},
						},
						"cost":  map[string]any{"input": 1.0, "output": 2.0},
						"limit": map[string]any{"context": 128000, "output": 4096},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cat, err := FetchCatalog(srv.URL)
	if err != nil {
		t.Fatalf("FetchCatalog error: %v", err)
	}

	if len(cat.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(cat.Providers))
	}

	p := cat.Providers["test-provider"]
	if p.Name != "Test Provider" {
		t.Errorf("expected 'Test Provider', got %q", p.Name)
	}
	if len(p.Models) != 1 {
		t.Errorf("expected 1 model, got %d", len(p.Models))
	}
}

func TestCatalogCache_Summaries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := map[string]any{
			"provider1": map[string]any{
				"id": "provider1", "name": "Provider One",
				"api": "https://api.p1.com/v1",
				"models": map[string]any{
					"model-a": map[string]any{
						"id": "model-a", "name": "Model A", "family": "llama",
						"reasoning": true, "tool_call": true,
						"modalities": map[string]any{"input": []string{"text"}, "output": []string{"text"}},
						"cost":       map[string]any{"input": 0.5, "output": 1.5},
						"limit":      map[string]any{"context": 32000, "output": 2048},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(catalog)
	}))
	defer srv.Close()

	cc := NewCatalogCache(srv.URL)
	summaries, err := cc.Summaries()
	if err != nil {
		t.Fatalf("Summaries error: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 provider summary, got %d", len(summaries))
	}
	if summaries[0].Name != "Provider One" {
		t.Errorf("expected 'Provider One', got %q", summaries[0].Name)
	}
	if len(summaries[0].Models) != 1 {
		t.Errorf("expected 1 model, got %d", len(summaries[0].Models))
	}
}

func TestClient_Analyze_MockServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request format
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("expected Bearer token")
		}
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[],"summary":"test","threats_detected":[]}`}},
			},
			"usage": map[string]any{
				"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(ClientConfig{
		BaseURL:   srv.URL,
		APIKey:    "test-key",
		Model:     "test-model",
		MaxTokens: 1024,
	})

	ctx := context.Background()
	content, usage, err := client.Analyze(ctx, "system prompt", "user content")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if usage.TotalTokens != 150 {
		t.Errorf("expected 150 tokens, got %d", usage.TotalTokens)
	}
	if content == "" {
		t.Error("expected non-empty response")
	}
}

func TestStore_ConfigPersistence(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID: "openai",
		ModelID:    "gpt-4o-mini",
		APIKey:     "sk-test-123",
		BaseURL:    "https://api.openai.com/v1",
	}

	if err := store.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig error: %v", err)
	}

	// Reload from disk
	store2 := NewStore(dir)
	got := store2.GetConfig()
	if got.ProviderID != "openai" {
		t.Errorf("expected 'openai', got %q", got.ProviderID)
	}
	if got.APIKey != "sk-test-123" {
		t.Errorf("expected API key to persist")
	}
}

func TestStore_History(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	for i := range 5 {
		_ = store.AddResult(AnalysisResult{
			ID:         "test-" + string(rune('0'+i)),
			Timestamp:  time.Now(),
			EventCount: 10,
			TokensUsed: 100,
		})
	}

	history := store.GetHistory(3)
	if len(history) != 3 {
		t.Fatalf("expected 3, got %d", len(history))
	}
}

func TestStore_UsageLimits(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Track some usage
	store.TrackUsage(10000)
	store.TrackUsage(10000)

	// Should be within limits
	if !store.WithinLimits(50000, 500000, 30) {
		t.Error("expected within limits")
	}

	// Track up to limit
	store.TrackUsage(30000)
	if store.WithinLimits(50000, 500000, 30) {
		t.Error("expected over hourly token limit")
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`{"key": "value"}`, `{"key": "value"}`},
		{"```json\n{\"key\": \"value\"}\n```", `{"key": "value"}`},
		{"Here is the analysis:\n{\"verdicts\": []}", `{"verdicts": []}`},
		{"no json here", "no json here"},
	}
	for _, tt := range tests {
		got := extractJSON(tt.input)
		if got != tt.want {
			t.Errorf("extractJSON(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAnalyzer_CollectAndFlush(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Create mock AI server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": `{"verdicts":[{"ip":"1.2.3.4","action":"block","reason":"test","confidence":0.9}],"summary":"test","threats_detected":["sqli"]}`}},
			},
			"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Configure provider
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	analyzer := NewAnalyzer(AnalyzerConfig{
		Enabled:       true,
		BatchSize:     3,
		BatchInterval: 100 * time.Millisecond,
		MinScoreForAI: 10,
	}, store, "")

	// Start with event channel
	eventCh := make(chan engine.Event, 100)
	analyzer.Start(eventCh)

	// Send events
	for i := range 5 {
		eventCh <- engine.Event{
			ClientIP:  "1.2.3.4",
			Method:    "GET",
			Path:      "/test",
			Score:     50 + i,
			Action:    engine.ActionBlock,
			Timestamp: time.Now(),
			Findings: []engine.Finding{
				{DetectorName: "sqli", Description: "test", Score: 50},
			},
		}
	}

	// Wait for batch processing
	time.Sleep(500 * time.Millisecond)
	analyzer.Stop()

	// Check results
	history := store.GetHistory(10)
	if len(history) == 0 {
		t.Fatal("expected analysis results in history")
	}

	usage := store.GetUsage()
	if usage.TotalTokensUsed == 0 {
		t.Error("expected token usage tracked")
	}
}

func TestHasText(t *testing.T) {
	if !hasText([]string{"text", "image"}) {
		t.Error("expected true for text+image")
	}
	if hasText([]string{"image"}) {
		t.Error("expected false for image only")
	}
	if !hasText([]string{}) {
		t.Error("expected true for empty (assume text)")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("should not truncate short string")
	}
	if truncate("this is a long string", 10) != "this is a ..." {
		t.Error("should truncate long string")
	}
}

func TestMain(m *testing.M) {
	testAllowPrivate = true // allow httptest servers in tests
	os.Exit(m.Run())
}
