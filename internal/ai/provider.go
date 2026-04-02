// Package ai provides AI-powered threat analysis for GuardianWAF.
// It fetches model catalogs from models.dev, manages provider configurations,
// and runs background batch analysis of security events using AI APIs.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	defaultCatalogURL = "https://models.dev/api.json"
	catalogCacheTTL   = 24 * time.Hour
)

// ProviderInfo describes an AI provider from the models.dev catalog.
type ProviderInfo struct {
	ID     string               `json:"id"`
	Name   string               `json:"name"`
	API    string               `json:"api"`
	Doc    string               `json:"doc"`
	Env    []string             `json:"env"`
	Models map[string]ModelInfo `json:"models"`
}

// ModelInfo describes a single AI model.
type ModelInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Family      string     `json:"family"`
	ReleaseDate string     `json:"release_date"`
	OpenWeights bool       `json:"open_weights"`
	Reasoning   bool       `json:"reasoning"`
	ToolCall    bool       `json:"tool_call"`
	Modalities  Modalities `json:"modalities"`
	Cost        CostInfo   `json:"cost"`
	Limit       LimitInfo  `json:"limit"`
}

// Modalities describes input/output types supported by a model.
type Modalities struct {
	Input  []string `json:"input"`
	Output []string `json:"output"`
}

// CostInfo holds pricing per million tokens.
type CostInfo struct {
	Input     float64 `json:"input"`
	Output    float64 `json:"output"`
	CacheRead float64 `json:"cache_read,omitempty"`
}

// LimitInfo holds token limits for a model.
type LimitInfo struct {
	Context int `json:"context"`
	Output  int `json:"output"`
}

// Catalog holds the full provider/model catalog from models.dev.
type Catalog struct {
	Providers map[string]*ProviderInfo `json:"providers"`
	FetchedAt time.Time                `json:"fetched_at"`
}

// ProviderSummary is a lightweight view for the dashboard.
type ProviderSummary struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	API        string         `json:"api"`
	Doc        string         `json:"doc"`
	ModelCount int            `json:"model_count"`
	Models     []ModelSummary `json:"models"`
}

// ModelSummary is a lightweight model view for the dashboard.
type ModelSummary struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Family    string  `json:"family"`
	Reasoning bool    `json:"reasoning"`
	ToolCall  bool    `json:"tool_call"`
	CostIn    float64 `json:"cost_input_per_m"`
	CostOut   float64 `json:"cost_output_per_m"`
	Context   int     `json:"context_window"`
	MaxOutput int     `json:"max_output"`
}

// CatalogCache caches the models.dev catalog with TTL.
type CatalogCache struct {
	mu        sync.RWMutex
	catalog   *Catalog
	url       string
	fetchedAt time.Time
}

// NewCatalogCache creates a new catalog cache.
func NewCatalogCache(url string) *CatalogCache {
	if url == "" {
		url = defaultCatalogURL
	}
	return &CatalogCache{url: url}
}

// Get returns the cached catalog, fetching if expired or missing.
func (cc *CatalogCache) Get() (*Catalog, error) {
	cc.mu.RLock()
	if cc.catalog != nil && time.Since(cc.fetchedAt) < catalogCacheTTL {
		cat := cc.catalog
		cc.mu.RUnlock()
		return cat, nil
	}
	cc.mu.RUnlock()

	return cc.refresh()
}

// refresh fetches the catalog from the remote URL.
func (cc *CatalogCache) refresh() (*Catalog, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Double-check after acquiring write lock
	if cc.catalog != nil && time.Since(cc.fetchedAt) < catalogCacheTTL {
		return cc.catalog, nil
	}

	cat, err := FetchCatalog(cc.url)
	if err != nil {
		// Return stale data if available
		if cc.catalog != nil {
			return cc.catalog, nil
		}
		return nil, err
	}

	cc.catalog = cat
	cc.fetchedAt = time.Now()
	return cat, nil
}

// Summaries returns lightweight provider summaries for the dashboard.
func (cc *CatalogCache) Summaries() ([]ProviderSummary, error) {
	cat, err := cc.Get()
	if err != nil {
		return nil, err
	}

	var result []ProviderSummary
	for _, p := range cat.Providers {
		if len(p.Models) == 0 {
			continue
		}
		ps := ProviderSummary{
			ID:         p.ID,
			Name:       p.Name,
			API:        p.API,
			Doc:        p.Doc,
			ModelCount: len(p.Models),
		}
		for _, m := range p.Models {
			// Only include models that support text input/output
			if !hasText(m.Modalities.Input) || !hasText(m.Modalities.Output) {
				continue
			}
			ps.Models = append(ps.Models, ModelSummary{
				ID:        m.ID,
				Name:      m.Name,
				Family:    m.Family,
				Reasoning: m.Reasoning,
				ToolCall:  m.ToolCall,
				CostIn:    m.Cost.Input,
				CostOut:   m.Cost.Output,
				Context:   m.Limit.Context,
				MaxOutput: m.Limit.Output,
			})
		}
		if len(ps.Models) > 0 {
			result = append(result, ps)
		}
	}
	return result, nil
}

// FetchCatalog fetches the models.dev catalog from the given URL.
func FetchCatalog(url string) (*Catalog, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024)) // 50MB max
	if err != nil {
		return nil, fmt.Errorf("reading catalog: %w", err)
	}

	// Parse as map[providerID] -> ProviderInfo
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing catalog: %w", err)
	}

	providers := make(map[string]*ProviderInfo, len(raw))
	for id, data := range raw {
		var p ProviderInfo
		if err := json.Unmarshal(data, &p); err != nil {
			continue // skip malformed providers
		}
		if p.ID == "" {
			p.ID = id
		}
		if p.Name == "" {
			p.Name = id
		}
		providers[id] = &p
	}

	return &Catalog{
		Providers: providers,
		FetchedAt: time.Now(),
	}, nil
}

func hasText(modalities []string) bool {
	if len(modalities) == 0 {
		return true // empty = assume text
	}
	return slices.Contains(modalities, "text")
}
