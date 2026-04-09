package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const systemPrompt = `You are a WAF (Web Application Firewall) security analyst AI. Analyze the following batch of HTTP request events that were flagged by the rule-based WAF engine.

Your task:
1. Identify attack patterns and their severity
2. Determine which source IPs should be blocked (confirmed attackers)
3. Identify IPs that appear to be false positives (safe traffic)
4. Detect coordinated attack patterns across multiple IPs
5. Classify the types of threats detected

IMPORTANT: Respond ONLY with valid JSON in this exact format:
{
  "verdicts": [
    {"ip": "1.2.3.4", "action": "block", "reason": "Confirmed SQL injection campaign with 15 attempts", "confidence": 0.95},
    {"ip": "5.6.7.8", "action": "monitor", "reason": "Suspicious but might be legitimate scanner", "confidence": 0.6},
    {"ip": "9.10.11.12", "action": "safe", "reason": "False positive from health check bot", "confidence": 0.9}
  ],
  "summary": "Detected coordinated SQL injection campaign from 3 IPs targeting /api endpoints",
  "threats_detected": ["sql_injection_campaign", "credential_stuffing"]
}`

// IPBlocker is the interface for auto-banning IPs.
// Implemented by ipacl.Layer to avoid circular imports.
type IPBlocker interface {
	AddAutoBan(ip string, reason string, ttl time.Duration)
}

// AnalyzerConfig holds configuration for the AI analyzer.
type AnalyzerConfig struct {
	Enabled          bool
	BatchSize        int
	BatchInterval    time.Duration
	MaxTokensHour    int64
	MaxTokensDay     int64
	MaxRequestsHour  int
	AutoBlockEnabled bool
	AutoBlockTTL     time.Duration
	MinScoreForAI    int
}

// Analyzer is the background AI threat analysis engine.
type Analyzer struct {
	mu      sync.RWMutex
	client  *Client
	store   *Store
	blocker IPBlocker
	config  AnalyzerConfig
	catalog *CatalogCache
	logs    logFunc

	// Event collection
	pending []eventSummary
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

type logFunc func(level, msg string)

// eventSummary is a compact representation of an event for AI analysis.
type eventSummary struct {
	Timestamp string   `json:"ts"`
	ClientIP  string   `json:"ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Query     string   `json:"query,omitempty"`
	UA        string   `json:"ua,omitempty"`
	Score     int      `json:"score"`
	Action    string   `json:"action"`
	Findings  []string `json:"findings"`
}

// aiResponse is the expected JSON response from the AI.
type aiResponse struct {
	Verdicts        []Verdict `json:"verdicts"`
	Summary         string    `json:"summary"`
	ThreatsDetected []string  `json:"threats_detected"`
}

// NewAnalyzer creates a new AI threat analyzer.
func NewAnalyzer(cfg AnalyzerConfig, store *Store, catalogURL string) *Analyzer {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 20
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = 60 * time.Second
	}
	if cfg.MinScoreForAI <= 0 {
		cfg.MinScoreForAI = 25
	}
	if cfg.AutoBlockTTL <= 0 {
		cfg.AutoBlockTTL = time.Hour
	}
	if cfg.MaxTokensHour <= 0 {
		cfg.MaxTokensHour = 50000
	}
	if cfg.MaxTokensDay <= 0 {
		cfg.MaxTokensDay = 500000
	}
	if cfg.MaxRequestsHour <= 0 {
		cfg.MaxRequestsHour = 30
	}

	a := &Analyzer{
		store:   store,
		config:  cfg,
		catalog: NewCatalogCache(catalogURL),
		stopCh:  make(chan struct{}),
		logs:    func(_, _ string) {}, // noop default
	}

	// Initialize client from stored config if available
	if store.HasConfig() {
		provCfg := store.GetConfig()
		a.client = NewClient(ClientConfig{
			BaseURL: provCfg.BaseURL,
			APIKey:  provCfg.APIKey,
			Model:   provCfg.ModelID,
		})
	}

	return a
}

// SetLogger sets the log function (typically eng.Logs.Add).
func (a *Analyzer) SetLogger(fn logFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logs = fn
}

// SetBlocker sets the IP blocker for auto-ban verdicts.
func (a *Analyzer) SetBlocker(b IPBlocker) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blocker = b
}

// Start begins the background analysis loop, reading events from the channel.
func (a *Analyzer) Start(eventCh <-chan engine.Event) {
	a.wg.Add(1)
	go a.loop(eventCh)
}

// Stop gracefully stops the analyzer.
func (a *Analyzer) Stop() {
	close(a.stopCh)
	a.wg.Wait()
}

// loop is the main background processing loop.
func (a *Analyzer) loop(eventCh <-chan engine.Event) {
	defer a.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			// AI analyzer panic recovery — prevent silent failure of threat analysis
			fmt.Printf("[ERROR] AI analyzer loop panic: %v\n", r)
		}
	}()

	ticker := time.NewTicker(a.config.BatchInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-eventCh:
			if !ok {
				a.flushBatch()
				return
			}
			// Only collect suspicious events
			if ev.Score >= a.config.MinScoreForAI {
				a.collectEvent(ev)
			}
			// Flush if batch is full
			if len(a.pending) >= a.config.BatchSize {
				a.flushBatch()
			}

		case <-ticker.C:
			if len(a.pending) > 0 {
				a.flushBatch()
			}

		case <-a.stopCh:
			a.flushBatch()
			return
		}
	}
}

// collectEvent adds an event to the pending batch.
func (a *Analyzer) collectEvent(ev engine.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	findings := make([]string, 0, len(ev.Findings))
	for _, f := range ev.Findings {
		findings = append(findings, fmt.Sprintf("%s:%s(score=%d)", f.DetectorName, f.Description, f.Score))
	}

	a.pending = append(a.pending, eventSummary{
		Timestamp: ev.Timestamp.Format("15:04:05"),
		ClientIP:  ev.ClientIP,
		Method:    ev.Method,
		Path:      ev.Path,
		Query:     ev.Query,
		UA:        truncate(ev.UserAgent, 80),
		Score:     ev.Score,
		Action:    ev.Action.String(),
		Findings:  findings,
	})
}

// flushBatch sends the pending events to AI for analysis.
func (a *Analyzer) flushBatch() {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return
	}
	batch := make([]eventSummary, len(a.pending))
	copy(batch, a.pending)
	a.pending = a.pending[:0]
	client := a.client
	a.mu.Unlock()

	if client == nil {
		a.logs("warn", "AI analyzer: no provider configured, skipping batch")
		return
	}

	// Check cost limits
	if !a.store.WithinLimits(a.config.MaxTokensHour, a.config.MaxTokensDay, a.config.MaxRequestsHour) {
		a.logs("warn", "AI analyzer: usage limit reached, skipping batch")
		return
	}

	// Build prompt
	eventsJSON, _ := json.Marshal(batch)
	userContent := fmt.Sprintf("Analyze these %d WAF events:\n\n%s", len(batch), string(eventsJSON))

	// Call AI
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	responseText, usage, err := client.Analyze(ctx, systemPrompt, userContent)
	duration := time.Since(start)

	// Track usage regardless of success
	a.store.TrackUsage(usage.TotalTokens)

	// Calculate cost (estimate)
	provCfg := a.store.GetConfig()
	cost := float64(usage.PromptTokens)/1_000_000*1.0 + float64(usage.CompletionTokens)/1_000_000*3.0

	result := AnalysisResult{
		ID:         fmt.Sprintf("ai-%d", time.Now().UnixMilli()),
		Timestamp:  time.Now(),
		EventCount: len(batch),
		TokensUsed: usage.TotalTokens,
		CostUSD:    cost,
		DurationMs: duration.Milliseconds(),
		Model:      provCfg.ModelID,
	}

	if err != nil {
		result.Error = err.Error()
		a.logs("error", fmt.Sprintf("AI analysis failed: %v", err))
		_ = a.store.AddResult(result)
		return
	}

	// Parse AI response
	var aiResp aiResponse
	// Try to extract JSON from response (AI might include markdown)
	jsonStr := extractJSON(responseText)
	if err := json.Unmarshal([]byte(jsonStr), &aiResp); err != nil {
		result.Error = fmt.Sprintf("failed to parse AI response: %v", err)
		result.Summary = truncate(responseText, 500)
		a.logs("warn", fmt.Sprintf("AI response parse error: %v", err))
		_ = a.store.AddResult(result)
		return
	}

	result.Verdicts = aiResp.Verdicts
	result.Summary = aiResp.Summary
	result.ThreatsDetected = aiResp.ThreatsDetected

	a.logs("info", fmt.Sprintf("AI analysis complete: %d events, %d verdicts, %d tokens ($%.4f)",
		len(batch), len(aiResp.Verdicts), usage.TotalTokens, cost))

	// Apply verdicts
	a.applyVerdicts(aiResp.Verdicts)

	// Store result
	_ = a.store.AddResult(result)
}

// applyVerdicts applies AI verdicts (auto-ban for "block" actions).
func (a *Analyzer) applyVerdicts(verdicts []Verdict) {
	a.mu.RLock()
	blocker := a.blocker
	autoBlock := a.config.AutoBlockEnabled
	ttl := a.config.AutoBlockTTL
	a.mu.RUnlock()

	if blocker == nil || !autoBlock {
		return
	}

	for _, v := range verdicts {
		if v.Action == "block" && v.Confidence >= 0.7 {
			reason := fmt.Sprintf("AI verdict: %s (confidence: %.0f%%)", v.Reason, v.Confidence*100)
			blocker.AddAutoBan(v.IP, reason, ttl)
			a.logs("info", fmt.Sprintf("AI auto-blocked IP %s: %s", v.IP, v.Reason))
		}
	}
}

// ManualAnalyze triggers an immediate analysis with the given events.
func (a *Analyzer) ManualAnalyze(events []engine.Event) (*AnalysisResult, error) {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("no AI provider configured")
	}

	if !a.store.WithinLimits(a.config.MaxTokensHour, a.config.MaxTokensDay, a.config.MaxRequestsHour) {
		return nil, fmt.Errorf("usage limit reached")
	}

	batch := make([]eventSummary, 0, len(events))
	for _, ev := range events {
		findings := make([]string, 0, len(ev.Findings))
		for _, f := range ev.Findings {
			findings = append(findings, fmt.Sprintf("%s:%s(score=%d)", f.DetectorName, f.Description, f.Score))
		}
		batch = append(batch, eventSummary{
			Timestamp: ev.Timestamp.Format("15:04:05"),
			ClientIP:  ev.ClientIP,
			Method:    ev.Method,
			Path:      ev.Path,
			Score:     ev.Score,
			Action:    ev.Action.String(),
			Findings:  findings,
		})
	}

	eventsJSON, _ := json.Marshal(batch)
	userContent := fmt.Sprintf("Analyze these %d WAF events:\n\n%s", len(batch), string(eventsJSON))

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	responseText, usage, err := client.Analyze(ctx, systemPrompt, userContent)
	duration := time.Since(start)
	a.store.TrackUsage(usage.TotalTokens)

	provCfg := a.store.GetConfig()
	cost := float64(usage.PromptTokens)/1_000_000*1.0 + float64(usage.CompletionTokens)/1_000_000*3.0

	result := &AnalysisResult{
		ID:         fmt.Sprintf("ai-%d", time.Now().UnixMilli()),
		Timestamp:  time.Now(),
		EventCount: len(batch),
		TokensUsed: usage.TotalTokens,
		CostUSD:    cost,
		DurationMs: duration.Milliseconds(),
		Model:      provCfg.ModelID,
	}

	if err != nil {
		result.Error = err.Error()
		_ = a.store.AddResult(*result)
		return result, err
	}

	var aiResp aiResponse
	jsonStr := extractJSON(responseText)
	if err := json.Unmarshal([]byte(jsonStr), &aiResp); err != nil {
		result.Error = "parse error: " + err.Error()
		result.Summary = truncate(responseText, 500)
		_ = a.store.AddResult(*result)
		return result, nil
	}

	result.Verdicts = aiResp.Verdicts
	result.Summary = aiResp.Summary
	result.ThreatsDetected = aiResp.ThreatsDetected

	a.applyVerdicts(aiResp.Verdicts)
	_ = a.store.AddResult(*result)
	return result, nil
}

// UpdateProvider updates the AI provider configuration and recreates the client.
func (a *Analyzer) UpdateProvider(cfg ProviderConfig) error {
	if err := a.store.SetConfig(cfg); err != nil {
		return err
	}

	a.mu.Lock()
	a.client = NewClient(ClientConfig{
		BaseURL: cfg.BaseURL,
		APIKey:  cfg.APIKey,
		Model:   cfg.ModelID,
	})
	a.mu.Unlock()
	return nil
}

// GetCatalog returns the models.dev catalog (cached).
func (a *Analyzer) GetCatalog() ([]ProviderSummary, error) {
	return a.catalog.Summaries()
}

// GetStore returns the underlying store for dashboard access.
func (a *Analyzer) GetStore() *Store {
	return a.store
}

// TestConnection tests the current provider configuration.
func (a *Analyzer) TestConnection() error {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()
	if client == nil {
		return fmt.Errorf("no AI provider configured")
	}
	return client.TestConnection(context.Background())
}

// extractJSON tries to find a JSON object in a string that may contain markdown.
func extractJSON(s string) string {
	// Find first { and last }
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
