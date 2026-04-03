package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/docker"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Mock AI Analyzer ---

type mockAIAnalyzer struct {
	catalog []*ai.ProviderSummary
	config  ai.ProviderConfig
	history []ai.AnalysisResult
	usage   ai.UsageStats
	store   *ai.Store
	testErr error
	analyzeResult *ai.AnalysisResult
}

func newMockAIAnalyzer(t *testing.T) *mockAIAnalyzer {
	t.Helper()
	return &mockAIAnalyzer{
		store: ai.NewStore(t.TempDir()),
	}
}

func (m *mockAIAnalyzer) GetCatalog() ([]ai.ProviderSummary, error) {
	if m.testErr != nil {
		return nil, m.testErr
	}
	result := make([]ai.ProviderSummary, len(m.catalog))
	for i := range m.catalog {
		result[i] = *m.catalog[i]
	}
	return result, nil
}

func (m *mockAIAnalyzer) GetStore() *ai.Store {
	return m.store
}

func (m *mockAIAnalyzer) UpdateProvider(cfg ai.ProviderConfig) error {
	if m.testErr != nil {
		return m.testErr
	}
	m.config = cfg
	return m.store.SetConfig(cfg)
}

func (m *mockAIAnalyzer) TestConnection() error {
	return m.testErr
}

func (m *mockAIAnalyzer) ManualAnalyze(evts []engine.Event) (*ai.AnalysisResult, error) {
	if m.testErr != nil {
		return nil, m.testErr
	}
	if m.analyzeResult != nil {
		return m.analyzeResult, nil
	}
	return &ai.AnalysisResult{
		ID:         "analysis-1",
		EventCount: len(evts),
		Summary:    "mock analysis",
	}, nil
}

// --- Mock Docker Watcher ---

type mockDockerWatcher struct {
	services []docker.DiscoveredService
}

func (m *mockDockerWatcher) Services() []docker.DiscoveredService {
	return m.services
}

func (m *mockDockerWatcher) ServiceCount() int {
	return len(m.services)
}

// =====================================================================
// 1. SetSessionSecret tests (auth.go:39)
// =====================================================================

func TestSetSessionSecret_EmptyKey(t *testing.T) {
	// Capture current secret before calling with empty key
	before := loadSecret()
	SetSessionSecret("")
	after := loadSecret()
	// Should be a no-op: secret unchanged
	if string(before) != string(after) {
		t.Error("SetSessionSecret with empty key should be a no-op")
	}
}

func TestSetSessionSecret_ValidHex(t *testing.T) {
	// 32 hex chars = 16 bytes, should be accepted as-is
	hexKey := "0123456789abcdef0123456789abcdef"
	SetSessionSecret(hexKey)
	secret := loadSecret()
	if len(secret) != 16 {
		t.Errorf("expected 16-byte secret from hex decode, got %d", len(secret))
	}
}

func TestSetSessionSecret_LongHex(t *testing.T) {
	// 64 hex chars = 32 bytes
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	SetSessionSecret(hexKey)
	secret := loadSecret()
	if len(secret) != 32 {
		t.Errorf("expected 32-byte secret from hex decode, got %d", len(secret))
	}
}

func TestSetSessionSecret_ShortKey(t *testing.T) {
	// Short non-hex key should be SHA-256 hashed (32 bytes)
	SetSessionSecret("short")
	secret := loadSecret()
	if len(secret) != 32 {
		t.Errorf("expected 32-byte SHA-256 hash for short key, got %d", len(secret))
	}
}

func TestSetSessionSecret_InvalidHex(t *testing.T) {
	// Not valid hex, should be SHA-256 hashed
	SetSessionSecret("zzzz-not-hex-zzzz-but-long")
	secret := loadSecret()
	if len(secret) != 32 {
		t.Errorf("expected 32-byte SHA-256 hash for invalid hex, got %d", len(secret))
	}
}

func TestSetSessionSecret_SignVerifyRoundTrip(t *testing.T) {
	SetSessionSecret("test-secret-key-for-roundtrip")
	token := signSession()
	if !verifySession(token) {
		t.Error("token signed with new secret should verify")
	}
}

// =====================================================================
// 2. AI Handler tests
// =====================================================================

// --- SetAIAnalyzer ---

func TestSetAIAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	if d.aiAnalyzer != nil {
		t.Error("expected nil aiAnalyzer initially")
	}
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)
	if d.aiAnalyzer == nil {
		t.Error("expected aiAnalyzer to be set")
	}
}

// --- handleAIProviders ---

func TestAIProviders_WithAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	analyzer.catalog = []*ai.ProviderSummary{
		{ID: "openai", Name: "OpenAI", ModelCount: 5},
		{ID: "anthropic", Name: "Anthropic", ModelCount: 3},
	}
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/providers", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["count"] == nil {
		t.Error("expected count field")
	}
}

func TestAIProviders_WithAnalyzerError(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	analyzer.testErr = fmt.Errorf("catalog fetch failed")
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/providers", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAIProviders_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	// aiAnalyzer is nil — should use catalogCache fallback
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/providers", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- handleAIGetConfig ---

func TestAIGetConfig_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/config", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", result["enabled"])
	}
}

func TestAIGetConfig_WithAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	_ = analyzer.UpdateProvider(ai.ProviderConfig{
		ProviderID:   "openai",
		ProviderName: "OpenAI",
		ModelID:      "gpt-4",
		ModelName:    "GPT-4",
		APIKey:       "sk-test-api-key-12345678",
		BaseURL:      "https://api.openai.com/v1",
	})
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/config", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", result["enabled"])
	}
	if result["api_key_set"] != true {
		t.Error("expected api_key_set=true")
	}
	mask, _ := result["api_key_mask"].(string)
	if !strings.Contains(mask, "sk-t") || !strings.Contains(mask, "5678") {
		t.Errorf("expected masked key, got %s", mask)
	}
}

func TestAIGetConfig_ShortAPIKey(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	_ = analyzer.UpdateProvider(ai.ProviderConfig{
		APIKey:  "short",
		BaseURL: "https://api.example.com",
	})
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/config", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	mask, _ := result["api_key_mask"].(string)
	if mask != "****" {
		t.Errorf("expected '****' for short key, got %s", mask)
	}
}

// --- handleAISetConfig ---

func TestAISetConfig_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config",
		`{"api_key":"sk-test","base_url":"https://api.openai.com"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAISetConfig_InvalidJSON(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config", "bad json", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAISetConfig_MissingFields(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config",
		`{"provider_id":"openai"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", w.Code)
	}
}

func TestAISetConfig_MissingBaseURL(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config",
		`{"api_key":"sk-test","provider_id":"openai"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing base_url, got %d", w.Code)
	}
}

func TestAISetConfig_Success(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config",
		`{"provider_id":"openai","provider_name":"OpenAI","model_id":"gpt-4","model_name":"GPT-4","api_key":"sk-test-key","base_url":"https://api.openai.com/v1"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAISetConfig_UpdateError(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	analyzer.testErr = fmt.Errorf("update failed")
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/ai/config",
		`{"api_key":"sk-test","base_url":"https://api.openai.com"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- handleAIHistory ---

func TestAIHistory_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/history", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	history, ok := result["history"].([]any)
	if !ok || len(history) != 0 {
		t.Errorf("expected empty history array, got %v", result["history"])
	}
}

func TestAIHistory_WithAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	_ = analyzer.store.AddResult(ai.AnalysisResult{
		ID:      "r1",
		Summary: "test result 1",
	})
	_ = analyzer.store.AddResult(ai.AnalysisResult{
		ID:      "r2",
		Summary: "test result 2",
	})
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/history", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	history, ok := result["history"].([]any)
	if !ok {
		t.Fatalf("expected history array, got %v", result["history"])
	}
	if len(history) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(history))
	}
}

func TestAIHistory_WithLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	_ = analyzer.store.AddResult(ai.AnalysisResult{ID: "r1"})
	_ = analyzer.store.AddResult(ai.AnalysisResult{ID: "r2"})
	_ = analyzer.store.AddResult(ai.AnalysisResult{ID: "r3"})
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/history?limit=1", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	history, _ := result["history"].([]any)
	if len(history) != 1 {
		t.Errorf("expected 1 history entry with limit=1, got %d", len(history))
	}
}

func TestAIHistory_InvalidLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/history?limit=invalid", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with invalid limit (uses default), got %d", w.Code)
	}
}

// --- handleAIStats ---

func TestAIStats_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/stats", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", result["enabled"])
	}
}

func TestAIStats_WithAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/ai/stats", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", result["enabled"])
	}
	if result["store_path"] == nil {
		t.Error("expected store_path field")
	}
}

// --- handleAIAnalyze ---

func TestAIAnalyze_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAIAnalyze_NoEvents(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	msg, _ := result["message"].(string)
	if !strings.Contains(msg, "no suspicious events") {
		t.Errorf("expected 'no suspicious events' message, got %s", msg)
	}
}

func TestAIAnalyze_WithEvents(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	// Store a suspicious event (score >= 25)
	_ = d.eventStore.Store(engine.Event{
		ID:       "evt-suspicious",
		ClientIP: "1.2.3.4",
		Action:   engine.ActionBlock,
		Score:    60,
	})

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAIAnalyze_WithLimit(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	// Store multiple events
	for i := range 5 {
		_ = d.eventStore.Store(engine.Event{
			ID:       fmt.Sprintf("evt-%d", i),
			ClientIP: "1.2.3.4",
			Action:   engine.ActionBlock,
			Score:    50,
		})
	}

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze?limit=2", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAIAnalyze_AnalyzeError(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	analyzer.testErr = fmt.Errorf("analysis failed")
	d.SetAIAnalyzer(analyzer)

	_ = d.eventStore.Store(engine.Event{
		ID:     "evt-1",
		Score:  30,
		Action: engine.ActionBlock,
	})

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/analyze", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- handleAITest ---

func TestAITest_NilAnalyzer(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/test", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAITest_Success(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/test", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestAITest_ConnectionError(t *testing.T) {
	d := newTestDashboard(t, "k")
	analyzer := newMockAIAnalyzer(t)
	analyzer.testErr = fmt.Errorf("connection refused")
	d.SetAIAnalyzer(analyzer)

	w := httptest.NewRecorder()
	req := authenticatedRequest("POST", "/api/v1/ai/test", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error in body), got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "error" {
		t.Errorf("expected status error, got %v", result["status"])
	}
}

// =====================================================================
// 3. Docker Handler tests
// =====================================================================

// --- SetDockerWatcher ---

func TestSetDockerWatcher(t *testing.T) {
	d := newTestDashboard(t, "k")
	if d.dockerWatcher != nil {
		t.Error("expected nil dockerWatcher initially")
	}
	watcher := &mockDockerWatcher{}
	d.SetDockerWatcher(watcher)
	if d.dockerWatcher == nil {
		t.Error("expected dockerWatcher to be set")
	}
}

// --- handleDockerServices ---

func TestDockerServices_NilWatcher(t *testing.T) {
	d := newTestDashboard(t, "k")
	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/docker/services", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", result["enabled"])
	}
}

func TestDockerServices_WithWatcher(t *testing.T) {
	d := newTestDashboard(t, "k")
	watcher := &mockDockerWatcher{
		services: []docker.DiscoveredService{
			{
				ContainerID:   "abc123def456",
				ContainerName: "web-backend",
				Image:         "nginx:latest",
				Host:          "example.com",
				Port:          8080,
				IPAddress:     "172.17.0.2",
				Status:        "running",
			},
		},
	}
	d.SetDockerWatcher(watcher)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/docker/services", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", result["enabled"])
	}
	if result["count"] != 1.0 {
		t.Errorf("expected count=1, got %v", result["count"])
	}
	services, ok := result["services"].([]any)
	if !ok || len(services) != 1 {
		t.Errorf("expected 1 service, got %v", result["services"])
	}
}

func TestDockerServices_EmptyServices(t *testing.T) {
	d := newTestDashboard(t, "k")
	watcher := &mockDockerWatcher{services: nil}
	d.SetDockerWatcher(watcher)

	w := httptest.NewRecorder()
	req := authenticatedRequest("GET", "/api/v1/docker/services", "", "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result["enabled"] != true {
		t.Errorf("expected enabled=true, got %v", result["enabled"])
	}
	if result["count"] != 0.0 {
		t.Errorf("expected count=0, got %v", result["count"])
	}
}

// =====================================================================
// 4. Mux(), SetSaveFn(), handleSSE() delegation
// =====================================================================

func TestMux(t *testing.T) {
	d := newTestDashboard(t, "k")
	mux := d.Mux()
	if mux == nil {
		t.Error("expected non-nil mux")
	}
	if mux != d.mux {
		t.Error("Mux() should return the internal mux")
	}
}

func TestSetSaveFn(t *testing.T) {
	d := newTestDashboard(t, "k")
	called := false
	d.SetSaveFn(func() error {
		called = true
		return nil
	})

	// Trigger saveFn via handleUpdateConfig with a minimal config
	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config",
		`{"mode":"proxy"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("expected saveFn to be called from handleUpdateConfig")
	}
}

func TestSetSaveFn_Error(t *testing.T) {
	d := newTestDashboard(t, "k")
	d.SetSaveFn(func() error {
		return fmt.Errorf("disk full")
	})

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config",
		`{"mode":"proxy"}`, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (graceful degradation), got %d", w.Code)
	}
	var result map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	msg, _ := result["message"].(string)
	if !strings.Contains(msg, "save to disk failed") {
		t.Errorf("expected save failure message, got %s", msg)
	}
}

func TestHandleSSE_DelegatesToBroadcaster(t *testing.T) {
	d := newTestDashboard(t, "")
	// Use a cancellable context so the SSE handler unblocks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/sse", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		d.Handler().ServeHTTP(w, req)
		close(done)
	}()

	// Let SSE handler connect and set headers
	time.Sleep(50 * time.Millisecond)

	ct := w.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %s", ct)
	}

	// Cancel context to unblock the SSE handler
	cancel()
	<-done
}

// =====================================================================
// 5. applyWAFPatch additional branches
// =====================================================================

func TestApplyWAFPatch_CORS(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"cors":{"enabled":true,"strict_mode":true,"allow_credentials":false}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	cfg := d.engine.Config()
	if !cfg.WAF.CORS.Enabled {
		t.Error("expected CORS enabled")
	}
	if !cfg.WAF.CORS.StrictMode {
		t.Error("expected CORS strict_mode")
	}
}

func TestApplyWAFPatch_ThreatIntel(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"threat_intel":{"enabled":true,"ip_reputation":{"enabled":true,"block_malicious":true,"score_threshold":75},"domain_reputation":{"enabled":true,"block_malicious":false}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	cfg := d.engine.Config()
	if !cfg.WAF.ThreatIntel.Enabled {
		t.Error("expected ThreatIntel enabled")
	}
	if !cfg.WAF.ThreatIntel.IPReputation.Enabled {
		t.Error("expected IPReputation enabled")
	}
	if cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold != 75 {
		t.Errorf("expected score_threshold=75, got %d", cfg.WAF.ThreatIntel.IPReputation.ScoreThreshold)
	}
	if !cfg.WAF.ThreatIntel.DomainRep.Enabled {
		t.Error("expected DomainRep enabled")
	}
}

func TestApplyWAFPatch_ATOProtection(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"ato_protection":{"enabled":true,"brute_force":{"enabled":true,"max_attempts_per_ip":10,"max_attempts_per_email":5},"credential_stuffing":{"enabled":true,"distributed_threshold":20},"impossible_travel":{"enabled":true,"max_distance_km":500}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	cfg := d.engine.Config()
	if !cfg.WAF.ATOProtection.Enabled {
		t.Error("expected ATOProtection enabled")
	}
	if !cfg.WAF.ATOProtection.BruteForce.Enabled {
		t.Error("expected BruteForce enabled")
	}
	if cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP != 10 {
		t.Errorf("expected max_attempts_per_ip=10, got %d", cfg.WAF.ATOProtection.BruteForce.MaxAttemptsPerIP)
	}
	if !cfg.WAF.ATOProtection.CredStuffing.Enabled {
		t.Error("expected CredStuffing enabled")
	}
	if !cfg.WAF.ATOProtection.Travel.Enabled {
		t.Error("expected Travel enabled")
	}
	if cfg.WAF.ATOProtection.Travel.MaxDistanceKm != 500 {
		t.Errorf("expected max_distance_km=500, got %f", cfg.WAF.ATOProtection.Travel.MaxDistanceKm)
	}
}

func TestApplyWAFPatch_APISecurity(t *testing.T) {
	d := newTestDashboard(t, "k")
	body := `{"waf":{"api_security":{"enabled":true,"jwt":{"enabled":true,"issuer":"https://auth.example.com","audience":"my-api"},"api_keys":{"enabled":true,"header_name":"X-API-Key"}}}}`

	w := httptest.NewRecorder()
	req := authenticatedRequest("PUT", "/api/v1/config", body, "k")
	d.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	cfg := d.engine.Config()
	if !cfg.WAF.APISecurity.Enabled {
		t.Error("expected APISecurity enabled")
	}
	if !cfg.WAF.APISecurity.JWT.Enabled {
		t.Error("expected JWT enabled")
	}
	if cfg.WAF.APISecurity.JWT.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer, got %s", cfg.WAF.APISecurity.JWT.Issuer)
	}
	if cfg.WAF.APISecurity.JWT.Audience != "my-api" {
		t.Errorf("expected audience, got %s", cfg.WAF.APISecurity.JWT.Audience)
	}
	if !cfg.WAF.APISecurity.APIKeys.Enabled {
		t.Error("expected APIKeys enabled")
	}
	if cfg.WAF.APISecurity.APIKeys.HeaderName != "X-API-Key" {
		t.Errorf("expected header_name=X-API-Key, got %s", cfg.WAF.APISecurity.APIKeys.HeaderName)
	}
}

// =====================================================================
// 6. HandleSSE "not supported" branch (non-Flusher ResponseWriter)
// =====================================================================

// nonFlusherRecorder is an http.ResponseWriter that does NOT implement http.Flusher.
type nonFlusherRecorder struct {
	code    int
	headers http.Header
	body    strings.Builder
}

func (n *nonFlusherRecorder) Header() http.Header         { return n.headers }
func (n *nonFlusherRecorder) Write(b []byte) (int, error) { return n.body.Write(b) }
func (n *nonFlusherRecorder) WriteHeader(code int)         { n.code = code }

func TestHandleSSE_NotSupported(t *testing.T) {
	b := NewSSEBroadcaster()
	w := &nonFlusherRecorder{headers: make(http.Header)}
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)

	b.HandleSSE(w, req)

	if w.code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-Flusher, got %d", w.code)
	}
	if !strings.Contains(w.body.String(), "SSE not supported") {
		t.Errorf("expected 'SSE not supported' message, got %s", w.body.String())
	}
}

// Also test through dashboard handler for coverage of the delegation path
func TestHandleSSE_NotSupportedViaDashboard(t *testing.T) {
	d := newTestDashboard(t, "")
	// Use a custom handler that wraps SSE with a non-flusher
	b := d.SSE()
	w := &nonFlusherRecorder{headers: make(http.Header)}
	req := httptest.NewRequest("GET", "/api/v1/sse", nil)

	// Call the broadcaster directly (as handleSSE delegates to it)
	b.HandleSSE(w, req)

	if w.code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-Flusher, got %d", w.code)
	}
}
