package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/guardianwaf/guardianwaf/internal/ai"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// aiAnalyzerInterface defines what the dashboard needs from the AI analyzer.
// This avoids importing the ai package's concrete types in the Dashboard struct.
type aiAnalyzerInterface interface {
	GetCatalog() ([]ai.ProviderSummary, error)
	GetStore() *ai.Store
	UpdateProvider(cfg ai.ProviderConfig) error
	TestConnection() error
	ManualAnalyze(evts []engine.Event) (*ai.AnalysisResult, error)
}

// SetAIAnalyzer injects the AI analyzer for dashboard API access.
func (d *Dashboard) SetAIAnalyzer(analyzer aiAnalyzerInterface) {
	d.aiAnalyzer = analyzer
}

// catalogCache is a standalone catalog cache for the providers endpoint.
// Works even when the AI analyzer is not enabled.
var catalogCache *ai.CatalogCache

func init() {
	catalogCache = ai.NewCatalogCache("")
}

// handleAIProviders returns the models.dev provider catalog.
// Always works — doesn't require AI analyzer to be enabled.
func (d *Dashboard) handleAIProviders(w http.ResponseWriter, r *http.Request) {
	// Use analyzer's catalog if available, otherwise standalone cache
	if d.aiAnalyzer != nil {
		// Get from analyzer (shares cache)
		providers, err := d.aiAnalyzer.GetCatalog()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to fetch providers: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": providers, "count": len(providers)})
		return
	}

	// Standalone fetch — AI not enabled but we still show providers
	providers, err := catalogCache.Summaries()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to fetch catalog: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers, "count": len(providers)})
}

// handleAIGetConfig returns the current AI provider configuration.
func (d *Dashboard) handleAIGetConfig(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	store := d.aiAnalyzer.GetStore()
	cfg := store.GetConfig()
	// Mask API key for display
	maskedKey := ""
	if cfg.APIKey != "" {
		if len(cfg.APIKey) > 8 {
			maskedKey = cfg.APIKey[:4] + "..." + cfg.APIKey[len(cfg.APIKey)-4:]
		} else {
			maskedKey = "****"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       true,
		"provider_id":   cfg.ProviderID,
		"provider_name": cfg.ProviderName,
		"model_id":      cfg.ModelID,
		"model_name":    cfg.ModelName,
		"base_url":      cfg.BaseURL,
		"api_key_set":   cfg.APIKey != "",
		"api_key_mask":  maskedKey,
	})
}

// handleAISetConfig updates the AI provider configuration.
func (d *Dashboard) handleAISetConfig(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AI analysis not enabled"})
		return
	}

	var body struct {
		ProviderID   string `json:"provider_id"`
		ProviderName string `json:"provider_name"`
		ModelID      string `json:"model_id"`
		ModelName    string `json:"model_name"`
		APIKey       string `json:"api_key"`
		BaseURL      string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}

	if body.APIKey == "" || body.BaseURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "api_key and base_url are required"})
		return
	}

	cfg := ai.ProviderConfig{
		ProviderID:   body.ProviderID,
		ProviderName: body.ProviderName,
		ModelID:      body.ModelID,
		ModelName:    body.ModelName,
		APIKey:       body.APIKey,
		BaseURL:      body.BaseURL,
	}

	if err := d.aiAnalyzer.UpdateProvider(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "AI provider configured"})
}

// handleAIHistory returns recent AI analysis results.
func (d *Dashboard) handleAIHistory(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"history": []any{}})
		return
	}

	n := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}

	store := d.aiAnalyzer.GetStore()
	history := store.GetHistory(n)
	writeJSON(w, http.StatusOK, map[string]any{"history": history, "count": len(history)})
}

// handleAIStats returns AI usage statistics.
func (d *Dashboard) handleAIStats(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}

	store := d.aiAnalyzer.GetStore()
	usage := store.GetUsage()
	storePath := store.Path()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":            true,
		"store_path":         storePath,
		"tokens_used_hour":   usage.TokensUsedHour,
		"tokens_used_day":    usage.TokensUsedDay,
		"requests_hour":      usage.RequestsHour,
		"requests_day":       usage.RequestsDay,
		"total_tokens_used":  usage.TotalTokensUsed,
		"total_requests":     usage.TotalRequests,
		"total_cost_usd":     usage.TotalCostUSD,
		"blocks_triggered":   usage.BlocksTriggered,
		"monitors_triggered": usage.MonitorsTriggered,
	})
}

// handleAIAnalyze triggers a manual AI analysis of recent suspicious events.
func (d *Dashboard) handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AI analysis not enabled"})
		return
	}

	// Get recent suspicious events
	n := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}

	evts, _, err := d.eventStore.Query(events.EventFilter{
		Limit:    n,
		MinScore: 25,
		SortBy:   "timestamp",
		SortOrder: "desc",
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to query events: " + err.Error()})
		return
	}

	if len(evts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"message": "no suspicious events to analyze"})
		return
	}

	result, err := d.aiAnalyzer.ManualAnalyze(evts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// handleAITest tests the AI provider connection.
func (d *Dashboard) handleAITest(w http.ResponseWriter, r *http.Request) {
	if d.aiAnalyzer == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AI analysis not enabled"})
		return
	}

	if err := d.aiAnalyzer.TestConnection(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "message": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Connection successful"})
}
