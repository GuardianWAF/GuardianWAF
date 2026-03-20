package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxHistorySize = 100

// ProviderConfig holds the user's selected AI provider configuration.
type ProviderConfig struct {
	ProviderID string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	ModelID    string `json:"model_id"`
	ModelName  string `json:"model_name"`
	APIKey     string `json:"api_key"`
	BaseURL    string `json:"base_url"`
}

// Verdict is an AI-generated threat assessment for a specific IP.
type Verdict struct {
	IP         string  `json:"ip"`
	Action     string  `json:"action"` // "block", "monitor", "safe"
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

// AnalysisResult holds the outcome of a single batch AI analysis.
type AnalysisResult struct {
	ID              string        `json:"id"`
	Timestamp       time.Time     `json:"timestamp"`
	EventCount      int           `json:"event_count"`
	Verdicts        []Verdict     `json:"verdicts"`
	Summary         string        `json:"summary"`
	ThreatsDetected []string      `json:"threats_detected"`
	TokensUsed      int           `json:"tokens_used"`
	CostUSD         float64       `json:"cost_usd"`
	DurationMs      int64         `json:"duration_ms"`
	Model           string        `json:"model"`
	Error           string        `json:"error,omitempty"`
}

// UsageStats tracks AI API usage for cost control.
type UsageStats struct {
	TokensUsedHour    int64     `json:"tokens_used_hour"`
	TokensUsedDay     int64     `json:"tokens_used_day"`
	RequestsHour      int       `json:"requests_hour"`
	RequestsDay       int       `json:"requests_day"`
	TotalTokensUsed   int64     `json:"total_tokens_used"`
	TotalRequests     int       `json:"total_requests"`
	TotalCostUSD      float64   `json:"total_cost_usd"`
	HourResetAt       time.Time `json:"hour_reset_at"`
	DayResetAt        time.Time `json:"day_reset_at"`
	BlocksTriggered   int       `json:"blocks_triggered"`
	MonitorsTriggered int       `json:"monitors_triggered"`
}

// storeData is the on-disk JSON format.
type storeData struct {
	Config  ProviderConfig   `json:"config"`
	History []AnalysisResult `json:"history"`
	Usage   UsageStats       `json:"usage"`
}

// Store manages persistent storage for AI configuration and analysis history.
type Store struct {
	mu      sync.RWMutex
	path    string // directory path
	data    storeData
}

// NewStore creates or loads an AI store from the given directory.
// Always succeeds — creates the directory and empty config if needed.
// Converts relative paths to absolute to avoid working directory issues.
func NewStore(dirPath string) *Store {
	if dirPath == "" {
		dirPath = "data/ai"
	}
	// Convert to absolute path to avoid CWD issues
	if !filepath.IsAbs(dirPath) {
		if abs, err := filepath.Abs(dirPath); err == nil {
			dirPath = abs
		}
	}

	// Ensure directory exists
	os.MkdirAll(dirPath, 0700)

	s := &Store{path: dirPath}

	// Try loading existing config
	configFile := filepath.Join(dirPath, "ai_config.json")
	if data, err := os.ReadFile(configFile); err == nil {
		json.Unmarshal(data, &s.data)
	} else {
		// First run — write empty config so file always exists
		empty, _ := json.MarshalIndent(s.data, "", "  ")
		os.WriteFile(configFile, empty, 0600)
	}
	return s
}

// save writes stored data to disk.
func (s *Store) save() error {
	dir := s.path
	// Always resolve to absolute path
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	target := filepath.Join(dir, "ai_config.json")
	if err := os.WriteFile(target, data, 0600); err != nil {
		return fmt.Errorf("save to %s: %w", target, err)
	}
	return nil
}

// Path returns the store directory path for debugging.
func (s *Store) Path() string { return s.path }

// GetConfig returns the current provider configuration.
func (s *Store) GetConfig() ProviderConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config
}

// SetConfig updates the provider configuration and persists to disk.
func (s *Store) SetConfig(cfg ProviderConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Config = cfg
	return s.save()
}

// HasConfig returns true if a provider is configured with an API key.
func (s *Store) HasConfig() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config.APIKey != "" && s.data.Config.BaseURL != ""
}

// AddResult appends an analysis result to history (ring buffer).
// AddResult appends an analysis result. Disk persistence is best-effort.
func (s *Store) AddResult(result AnalysisResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.History = append(s.data.History, result)
	if len(s.data.History) > maxHistorySize {
		s.data.History = s.data.History[len(s.data.History)-maxHistorySize:]
	}

	// Update usage stats
	s.data.Usage.TotalTokensUsed += int64(result.TokensUsed)
	s.data.Usage.TotalRequests++
	s.data.Usage.TotalCostUSD += result.CostUSD

	for _, v := range result.Verdicts {
		switch v.Action {
		case "block":
			s.data.Usage.BlocksTriggered++
		case "monitor":
			s.data.Usage.MonitorsTriggered++
		}
	}

	return s.save()
}

// GetHistory returns the most recent N analysis results.
func (s *Store) GetHistory(n int) []AnalysisResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 || n > len(s.data.History) {
		n = len(s.data.History)
	}

	// Return most recent first
	result := make([]AnalysisResult, n)
	for i := range n {
		result[i] = s.data.History[len(s.data.History)-1-i]
	}
	return result
}

// GetUsage returns current usage stats, resetting hourly/daily counters if needed.
func (s *Store) GetUsage() UsageStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Reset hourly counters
	if now.After(s.data.Usage.HourResetAt) {
		s.data.Usage.TokensUsedHour = 0
		s.data.Usage.RequestsHour = 0
		s.data.Usage.HourResetAt = now.Truncate(time.Hour).Add(time.Hour)
	}

	// Reset daily counters
	if now.After(s.data.Usage.DayResetAt) {
		s.data.Usage.TokensUsedDay = 0
		s.data.Usage.RequestsDay = 0
		s.data.Usage.DayResetAt = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}

	return s.data.Usage
}

// TrackUsage increments hourly and daily usage counters.
func (s *Store) TrackUsage(tokens int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Reset if needed
	if now.After(s.data.Usage.HourResetAt) {
		s.data.Usage.TokensUsedHour = 0
		s.data.Usage.RequestsHour = 0
		s.data.Usage.HourResetAt = now.Truncate(time.Hour).Add(time.Hour)
	}
	if now.After(s.data.Usage.DayResetAt) {
		s.data.Usage.TokensUsedDay = 0
		s.data.Usage.RequestsDay = 0
		s.data.Usage.DayResetAt = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}

	s.data.Usage.TokensUsedHour += int64(tokens)
	s.data.Usage.TokensUsedDay += int64(tokens)
	s.data.Usage.RequestsHour++
	s.data.Usage.RequestsDay++
}

// WithinLimits checks if usage is within the configured limits.
func (s *Store) WithinLimits(maxTokensHour, maxTokensDay int64, maxReqsHour int) bool {
	usage := s.GetUsage()

	if maxTokensHour > 0 && usage.TokensUsedHour >= maxTokensHour {
		return false
	}
	if maxTokensDay > 0 && usage.TokensUsedDay >= maxTokensDay {
		return false
	}
	if maxReqsHour > 0 && usage.RequestsHour >= maxReqsHour {
		return false
	}
	return true
}
