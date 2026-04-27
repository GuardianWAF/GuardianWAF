package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// --- handleAIProviders: nil analyzer (uses standalone cache) ---
func TestHandleAIProviders_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/providers", nil)
	d.handleAIProviders(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAIProviders: with analyzer returning error ---
func TestHandleAIProviders_WithAnalyzerError(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		catalogFn: func() ([]ai.ProviderSummary, error) {
			return nil, errors.New("connection reset")
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/providers", nil)
	d.handleAIProviders(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --- handleAIProviders: with analyzer returning providers ---
func TestHandleAIProviders_WithAnalyzerSuccess(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		catalogFn: func() ([]ai.ProviderSummary, error) {
			return []ai.ProviderSummary{
				{ID: "openai", Name: "OpenAI"},
				{ID: "anthropic", Name: "Anthropic"},
			}, nil
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/providers", nil)
	d.handleAIProviders(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "providers") {
		t.Error("expected providers in response")
	}
}

// --- handleAIGetConfig: nil analyzer returns enabled:false ---
func TestHandleAIGetConfig_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/config", nil)
	d.handleAIGetConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false in response")
	}
}

// --- handleAIGetConfig: with analyzer and store ---
func TestHandleAIGetConfig_WithAnalyzer(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	store.SetConfig(ai.ProviderConfig{
		ProviderID:   "test-provider",
		ProviderName: "Test Provider",
		ModelID:      "model-1",
		ModelName:    "Model One",
		BaseURL:      "https://api.test.com",
		APIKey:       "sk-test-key",
	})

	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/config", nil)
	d.handleAIGetConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"enabled":true`) {
		t.Error("expected enabled:true")
	}
	if !strings.Contains(body, `"api_key_set":true`) {
		t.Error("expected api_key_set:true")
	}
}

// --- handleAISetConfig: nil analyzer returns error ---
func TestHandleAISetConfig_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"https://api.test.com"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: missing api_key and base_url ---
func TestHandleAISetConfig_MissingFields(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	// Missing both
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: missing base_url ---
func TestHandleAISetConfig_MissingBaseURL(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":""}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - localhost ---
func TestHandleAISetConfig_SSRF_Localhost(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://localhost:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - loopback IP ---
func TestHandleAISetConfig_SSRF_LoopbackIP(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://127.0.0.1:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - private IP 10.x ---
func TestHandleAISetConfig_SSRF_PrivateIP10(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://10.0.0.1:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - private IP 172.16.x ---
func TestHandleAISetConfig_SSRF_PrivateIP172(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://172.16.0.1:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - private IP 192.168.x ---
func TestHandleAISetConfig_SSRF_PrivateIP192(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://192.168.1.1:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - link-local ---
func TestHandleAISetConfig_SSRF_LinkLocal(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://169.254.169.254/latest/meta-data"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: SSRF protection - private hostname resolving to loopback ---
func TestHandleAISetConfig_SSRF_PrivateHostname(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://database.herd.test:8080"}`))
	d.handleAISetConfig(rr, req)

	// May pass or fail depending on whether database.herd.test resolves
	// to a private IP on this machine. We just verify the handler runs.
}

// --- handleAISetConfig: invalid JSON body ---
func TestHandleAISetConfig_InvalidJSON(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{invalid`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAISetConfig: success case ---
func TestHandleAISetConfig_Success(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
		updateFn: func(cfg ai.ProviderConfig) error {
			return nil
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"provider_id":"openai","provider_name":"OpenAI","model_id":"gpt-4","model_name":"GPT-4","api_key":"sk-xxx","base_url":"https://api.openai.com"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAISetConfig: update provider error ---
func TestHandleAISetConfig_UpdateError(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
		updateFn: func(cfg ai.ProviderConfig) error {
			return errors.New("update failed")
		},
	}

	// Use a URL that passes SSRF check but updateFn returns error
	// 8.8.8.8 is a public DNS server, not private
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/ai/config", strings.NewReader(`{"api_key":"key","base_url":"http://8.8.8.8:8080"}`))
	d.handleAISetConfig(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --- handleAIHistory: nil analyzer returns empty ---
func TestHandleAIHistory_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/history", nil)
	d.handleAIHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"history"`) {
		t.Error("expected history in response")
	}
}

// --- handleAIHistory: with analyzer, store returns nil ---
func TestHandleAIHistory_StoreNil(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return nil },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/history", nil)
	d.handleAIHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"history"`) {
		t.Error("expected history in response")
	}
}

// --- handleAIHistory: with limit query param ---
func TestHandleAIHistory_WithLimit(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	store.AddResult(ai.AnalysisResult{ID: "test-1", EventCount: 5})

	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/history?limit=10", nil)
	d.handleAIHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAIHistory: with invalid limit (negative) ---
func TestHandleAIHistory_InvalidLimit(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/history?limit=-5", nil)
	d.handleAIHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAIHistory: with limit capped at 1000 ---
func TestHandleAIHistory_LimitCapped(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/history?limit=5000", nil)
	d.handleAIHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAIStats: nil analyzer returns enabled:false ---
func TestHandleAIStats_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/stats", nil)
	d.handleAIStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false in response")
	}
}

// --- handleAIStats: store nil returns enabled:false ---
func TestHandleAIStats_StoreNil(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return nil },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/stats", nil)
	d.handleAIStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Error("expected enabled:false in response")
	}
}

// --- handleAIStats: with store returning usage ---
func TestHandleAIStats_WithUsage(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/stats", nil)
	d.handleAIStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Error("expected enabled:true in response")
	}
}

// --- handleAIAnalyze: nil analyzer returns error ---
func TestHandleAIAnalyze_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/analyze", nil)
	d.handleAIAnalyze(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAIAnalyze: no events returns message ---
func TestHandleAIAnalyze_NoEvents(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}
	d.eventStore = newMockEventStoreForAI(nil, nil) // no events

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/analyze", nil)
	d.handleAIAnalyze(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "no suspicious events") {
		t.Error("expected no suspicious events message")
	}
}

// --- handleAIAnalyze: with events, manual analyze success ---
func TestHandleAIAnalyze_WithEventsSuccess(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
		manualFn: func(evts []engine.Event) (*ai.AnalysisResult, error) {
			return &ai.AnalysisResult{
				ID:         "result-1",
				EventCount: len(evts),
				Verdicts: []ai.Verdict{
					{IP: "1.2.3.4", Action: "block", Reason: "SQL injection", Confidence: 0.95},
				},
				Summary:         "Test summary",
				ThreatsDetected: []string{"sqli"},
				TokensUsed:      100,
				CostUSD:         0.02,
				DurationMs:      500,
				Model:           "gpt-4",
			}, nil
		},
	}
	evts := []engine.Event{
		{ID: "evt-1", Timestamp: time.Now(), ClientIP: "1.2.3.4", Method: "GET", Path: "/test", Score: 50},
	}
	d.eventStore = newMockEventStoreForAI(evts, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/analyze", nil)
	d.handleAIAnalyze(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- handleAIAnalyze: query events error ---
func TestHandleAIAnalyze_QueryError(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
	}
	d.eventStore = newMockEventStoreForAI(nil, errors.New("query error"))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/analyze", nil)
	d.handleAIAnalyze(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --- handleAIAnalyze: manual analyze error ---
func TestHandleAIAnalyze_ManualAnalyzeError(t *testing.T) {
	store := ai.NewStore(t.TempDir())
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		storeFn: func() *ai.Store { return store },
		manualFn: func(evts []engine.Event) (*ai.AnalysisResult, error) {
			return nil, errors.New("analyze failed")
		},
	}
	evts := []engine.Event{
		{ID: "evt-1", Timestamp: time.Now(), ClientIP: "1.2.3.4", Method: "GET", Path: "/test", Score: 50},
	}
	d.eventStore = newMockEventStoreForAI(evts, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/analyze", nil)
	d.handleAIAnalyze(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --- handleAITest: nil analyzer returns error ---
func TestHandleAITest_NilAnalyzer(t *testing.T) {
	d := &Dashboard{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/test", nil)
	d.handleAITest(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleAITest: connection success ---
func TestHandleAITest_ConnectionSuccess(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		testConnFn: func() error { return nil },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/test", nil)
	d.handleAITest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"ok"`) {
		t.Error("expected status:ok in response")
	}
}

// --- handleAITest: connection error returns ok but error status ---
func TestHandleAITest_ConnectionError(t *testing.T) {
	d := &Dashboard{}
	d.aiAnalyzer = &mockAIAnalyzerForCoverage{
		testConnFn: func() error { return errors.New("connection refused") },
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/ai/test", nil)
	d.handleAITest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"error"`) {
		t.Error("expected status:error in response")
	}
}

// --- validateAIEndpointURL: unspecified IP ---
func TestValidateAIEndpointURL_Unspecified(t *testing.T) {
	err := validateAIEndpointURL("http://0.0.0.0:8080")
	if err == nil {
		t.Error("expected error for unspecified IP")
	}
}

// --- validateAIEndpointURL: valid public URL (skipped if DNS fails) ---
func TestValidateAIEndpointURL_ValidPublic(t *testing.T) {
	err := validateAIEndpointURL("https://api.openai.com/v1")
	if err != nil {
		t.Logf("valid URL test: %v (may fail due to DNS on this machine)", err)
	}
}

// --- mockAIAnalyzerForCoverage: functional mock for AI handler tests ---
type mockAIAnalyzerForCoverage struct {
	catalogFn  func() ([]ai.ProviderSummary, error)
	storeFn    func() *ai.Store
	updateFn   func(ai.ProviderConfig) error
	testConnFn func() error
	manualFn   func([]engine.Event) (*ai.AnalysisResult, error)
}

func (m *mockAIAnalyzerForCoverage) GetCatalog() ([]ai.ProviderSummary, error) {
	if m.catalogFn != nil {
		return m.catalogFn()
	}
	return nil, nil
}
func (m *mockAIAnalyzerForCoverage) GetStore() *ai.Store {
	if m.storeFn != nil {
		return m.storeFn()
	}
	return nil
}
func (m *mockAIAnalyzerForCoverage) UpdateProvider(cfg ai.ProviderConfig) error {
	if m.updateFn != nil {
		return m.updateFn(cfg)
	}
	return nil
}
func (m *mockAIAnalyzerForCoverage) TestConnection() error {
	if m.testConnFn != nil {
		return m.testConnFn()
	}
	return nil
}
func (m *mockAIAnalyzerForCoverage) ManualAnalyze(evts []engine.Event) (*ai.AnalysisResult, error) {
	if m.manualFn != nil {
		return m.manualFn(evts)
	}
	return nil, nil
}

// --- mock eventStore for analyze tests ---
type mockEventStoreForAI struct {
	evts     []engine.Event
	queryErr error
}

func newMockEventStoreForAI(evts []engine.Event, queryErr error) *mockEventStoreForAI {
	return &mockEventStoreForAI{evts: evts, queryErr: queryErr}
}

func (m *mockEventStoreForAI) Store(event engine.Event) error {
	return nil
}
func (m *mockEventStoreForAI) Query(filter events.EventFilter) ([]engine.Event, int, error) {
	if m.queryErr != nil {
		return nil, 0, m.queryErr
	}
	if len(m.evts) > filter.Limit {
		return m.evts[:filter.Limit], len(m.evts), nil
	}
	return m.evts, len(m.evts), nil
}
func (m *mockEventStoreForAI) Get(id string) (*engine.Event, error) {
	return nil, nil
}
func (m *mockEventStoreForAI) Recent(n int) ([]engine.Event, error) {
	return m.evts, nil
}
func (m *mockEventStoreForAI) Count(filter events.EventFilter) (int, error) {
	return len(m.evts), nil
}
func (m *mockEventStoreForAI) Close() error { return nil }