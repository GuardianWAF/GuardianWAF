package dashboard

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to fetch providers"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": providers, "count": len(providers)})
		return
	}

	// Standalone fetch — AI not enabled but we still show providers
	providers, err := catalogCache.Summaries()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to fetch catalog"})
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
	// Mask API key for display - show only last 4 chars to prevent partial exposure
	maskedKey := ""
	if cfg.APIKey != "" {
		if len(cfg.APIKey) >= 8 {
			maskedKey = "****" + cfg.APIKey[len(cfg.APIKey)-4:]
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
	if !limitedDecodeJSON(w, r, &body) {
		return
	}

	if body.APIKey == "" || body.BaseURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "api_key and base_url are required"})
		return
	}

	// Validate BaseURL to prevent SSRF — reject private/loopback/reserved IPs
	if err := validateAIEndpointURL(body.BaseURL); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
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
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
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
			n = min(parsed, 1000)
		}
	}

	store := d.aiAnalyzer.GetStore()
	if store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"history": []any{}, "count": 0})
		return
	}
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
	if store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	usage := store.GetUsage()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":            true,
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
			n = min(parsed, 1000)
		}
	}

	evts, _, err := d.eventStore.Query(events.EventFilter{
		Limit:     n,
		MinScore:  25,
		SortBy:    "timestamp",
		SortOrder: "desc",
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to query events"})
		return
	}

	if len(evts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"message": "no suspicious events to analyze"})
		return
	}

	result, err := d.aiAnalyzer.ManualAnalyze(evts)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": sanitizeErr(err)})
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
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "message": sanitizeErr(err)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Connection successful"})
}

// validateAIEndpointURL rejects URLs pointing to private, loopback, or reserved
// IP addresses to prevent SSRF via the AI provider base_url configuration.
func validateAIEndpointURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("AI endpoint URL must not target localhost")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("AI endpoint URL must not target private/loopback/link-local addresses")
		}
		return nil
	}
	// Resolve hostname and validate all resulting IPs
	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return fmt.Errorf("AI endpoint hostname %q resolves to private/loopback address %s", host, addr)
			}
		}
	}
	return nil
}
