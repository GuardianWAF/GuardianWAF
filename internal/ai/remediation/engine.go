// Package remediation provides AI-driven automatic rule generation and remediation.
package remediation

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config for remediation engine.
type Config struct {
	Enabled            bool          `yaml:"enabled"`
	AutoApply          bool          `yaml:"auto_apply"`
	ConfidenceThreshold int          `yaml:"confidence_threshold"`
	MaxRulesPerDay     int           `yaml:"max_rules_per_day"`
	RuleTTL            time.Duration `yaml:"rule_ttl"`
	ExcludedPaths      []string      `yaml:"excluded_paths"`
	StoragePath        string        `yaml:"storage_path"`
}

// DefaultConfig returns default remediation config.
func DefaultConfig() *Config {
	return &Config{
		Enabled:             false,
		AutoApply:           false,
		ConfidenceThreshold: 85,
		MaxRulesPerDay:      10,
		RuleTTL:             24 * time.Hour,
		ExcludedPaths:       []string{"/healthz", "/metrics", "/api/v1/status"},
		StoragePath:         "data/remediation",
	}
}

// AnalysisResult represents AI analysis findings.
type AnalysisResult struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AttackType  string                 `json:"attack_type"`
	Confidence  float64                `json:"confidence"`
	SourceIP    string                 `json:"source_ip"`
	Path        string                 `json:"path"`
	Method      string                 `json:"method"`
	Payload     string                 `json:"payload"`
	Severity    string                 `json:"severity"`
	Details     map[string]interface{} `json:"details"`
}

// GeneratedRule represents an auto-generated security rule.
type GeneratedRule struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	AnalysisID  string    `json:"analysis_id"`
	RuleType    string    `json:"rule_type"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pattern     string    `json:"pattern"`
	Action      string    `json:"action"`
	Confidence  float64   `json:"confidence"`
	Applied     bool      `json:"applied"`
	AutoApplied bool      `json:"auto_applied"`
	HitCount    int       `json:"hit_count"`
	LastHit     time.Time `json:"last_hit"`
}

// Stats holds remediation statistics.
type Stats struct {
	TotalGenerated  int       `json:"total_generated"`
	TotalApplied    int       `json:"total_applied"`
	TotalAutoApplied int      `json:"total_auto_applied"`
	ActiveRules     int       `json:"active_rules"`
	ExpiredRules    int       `json:"expired_rules"`
	LastRuleTime    time.Time `json:"last_rule_time"`
	RulesToday      int       `json:"rules_today"`
}

// Engine provides AI-driven remediation capabilities.
type Engine struct {
	config    *Config
	rules     map[string]*GeneratedRule
	rulesMu   sync.RWMutex
	stats     Stats
	statsMu   sync.RWMutex
	stopCh    chan struct{}
}

// NewEngine creates a new remediation engine.
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	e := &Engine{
		config: cfg,
		rules:  make(map[string]*GeneratedRule),
		stopCh: make(chan struct{}),
	}

	// Ensure storage directory exists
	if cfg.StoragePath != "" {
		os.MkdirAll(cfg.StoragePath, 0755)
	}

	// Start background tasks
	go e.cleanupLoop()

	return e, nil
}

// ProcessAnalysis processes AI analysis results and generates rules.
func (e *Engine) ProcessAnalysis(result *AnalysisResult) (*GeneratedRule, error) {
	if !e.config.Enabled {
		return nil, nil
	}

	// Check if we should exclude this path
	if e.isExcludedPath(result.Path) {
		return nil, nil
	}

	// Check confidence threshold
	if result.Confidence < float64(e.config.ConfidenceThreshold) {
		return nil, nil
	}

	// Check daily rule limit
	if e.isDailyLimitReached() {
		log.Printf("[remediation] Daily rule limit reached (%d rules)", e.config.MaxRulesPerDay)
		return nil, nil
	}

	// Generate rule from analysis
	rule, err := e.generateRule(result)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rule: %w", err)
	}

	// Store the rule
	e.rulesMu.Lock()
	e.rules[rule.ID] = rule
	e.rulesMu.Unlock()

	// Update stats
	e.statsMu.Lock()
	e.stats.TotalGenerated++
	e.stats.LastRuleTime = time.Now()
	e.stats.RulesToday++
	e.statsMu.Unlock()

	// Auto-apply if enabled and confidence is high enough
	if e.config.AutoApply && result.Confidence >= 90 {
		if err := e.ApplyRule(rule.ID); err != nil {
			log.Printf("[remediation] Failed to auto-apply rule %s: %v", rule.ID, err)
		} else {
			rule.AutoApplied = true
			e.statsMu.Lock()
			e.stats.TotalAutoApplied++
			e.statsMu.Unlock()
			log.Printf("[remediation] Auto-applied rule %s for %s attack", rule.ID, result.AttackType)
		}
	}

	// Persist rule to disk
	if err := e.saveRule(rule); err != nil {
		log.Printf("[remediation] Failed to save rule: %v", err)
	}

	return rule, nil
}

// generateRule creates a rule from analysis results.
func (e *Engine) generateRule(analysis *AnalysisResult) (*GeneratedRule, error) {
	ruleType := e.determineRuleType(analysis)
	if ruleType == "" {
		return nil, fmt.Errorf("cannot determine rule type for attack: %s", analysis.AttackType)
	}

	rule := &GeneratedRule{
		ID:          generateRuleID(),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(e.config.RuleTTL),
		AnalysisID:  analysis.ID,
		RuleType:    ruleType,
		Name:        fmt.Sprintf("AI-%s-%s", analysis.AttackType, analysis.SourceIP),
		Description: fmt.Sprintf("Auto-generated rule for %s attack from %s", analysis.AttackType, analysis.SourceIP),
		Pattern:     e.generatePattern(analysis),
		Action:      e.determineAction(analysis),
		Confidence:  analysis.Confidence,
		Applied:     false,
	}

	return rule, nil
}

// determineRuleType maps attack types to rule types.
func (e *Engine) determineRuleType(analysis *AnalysisResult) string {
	switch analysis.AttackType {
	case "sqli", "sql_injection":
		return "sqli_block"
	case "xss", "cross_site_scripting":
		return "xss_block"
	case "lfi", "local_file_inclusion":
		return "lfi_block"
	case "rfi", "remote_file_inclusion":
		return "rfi_block"
	case "cmdi", "command_injection":
		return "cmdi_block"
	case "xxe", "xml_external_entity":
		return "xxe_block"
	case "ssrf", "server_side_request_forgery":
		return "ssrf_block"
	case "nosql_injection":
		return "nosql_block"
	case "ldap_injection":
		return "ldap_block"
	case "xpath_injection":
		return "xpath_block"
	case "path_traversal":
		return "path_traversal_block"
	case "brute_force":
		return "rate_limit"
	case "bot", "bot_attack":
		return "bot_block"
	case "ip_reputation":
		return "ip_block"
	default:
		return "custom_block"
	}
}

// generatePattern creates a matching pattern from analysis.
func (e *Engine) generatePattern(analysis *AnalysisResult) string {
	// Generate pattern based on attack characteristics
	if analysis.Payload != "" {
		// Extract the dangerous payload pattern
		return e.sanitizePattern(analysis.Payload)
	}

	// Fallback to path-based pattern
	if analysis.Path != "" {
		return fmt.Sprintf("^%s$", analysis.Path)
	}

	return ""
}

// sanitizePattern creates a safe regex pattern from payload.
func (e *Engine) sanitizePattern(payload string) string {
	// Escape special regex characters
	specialChars := []string{`\`, `.`, `*`, `+`, `?`, `^`, `$`, `|`, `[`, `]`, `(`, `)`, `{`, `}`}
	result := payload
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, `\`+char)
	}
	return result
}

// determineAction decides the action based on severity.
func (e *Engine) determineAction(analysis *AnalysisResult) string {
	switch analysis.Severity {
	case "critical", "high":
		return "block"
	case "medium":
		return "challenge"
	case "low":
		return "log"
	default:
		return "log"
	}
}

// ApplyRule applies a generated rule to the WAF.
func (e *Engine) ApplyRule(ruleID string) error {
	e.rulesMu.Lock()
	rule, exists := e.rules[ruleID]
	e.rulesMu.Unlock()

	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	if rule.Applied {
		return nil // Already applied
	}

	// Mark as applied
	e.rulesMu.Lock()
	rule.Applied = true
	e.rulesMu.Unlock()

	// Update stats
	e.statsMu.Lock()
	e.stats.TotalApplied++
	e.statsMu.Unlock()

	log.Printf("[remediation] Applied rule %s: %s", ruleID, rule.Name)
	return nil
}

// RevokeRule revokes an applied rule.
func (e *Engine) RevokeRule(ruleID string) error {
	e.rulesMu.Lock()
	rule, exists := e.rules[ruleID]
	if !exists {
		e.rulesMu.Unlock()
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	rule.Applied = false
	e.rulesMu.Unlock()

	log.Printf("[remediation] Revoked rule %s", ruleID)
	return nil
}

// DeleteRule permanently deletes a rule.
func (e *Engine) DeleteRule(ruleID string) error {
	e.rulesMu.Lock()
	delete(e.rules, ruleID)
	e.rulesMu.Unlock()

	// Delete from disk
	filename := filepath.Join(e.config.StoragePath, fmt.Sprintf("rule-%s.json", ruleID))
	os.Remove(filename)

	log.Printf("[remediation] Deleted rule %s", ruleID)
	return nil
}

// GetRule returns a specific rule.
func (e *Engine) GetRule(ruleID string) *GeneratedRule {
	e.rulesMu.RLock()
	rule := e.rules[ruleID]
	e.rulesMu.RUnlock()
	return rule
}

// GetAllRules returns all rules.
func (e *Engine) GetAllRules() []*GeneratedRule {
	e.rulesMu.RLock()
	rules := make([]*GeneratedRule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	e.rulesMu.RUnlock()
	return rules
}

// GetActiveRules returns only active (applied and not expired) rules.
func (e *Engine) GetActiveRules() []*GeneratedRule {
	now := time.Now()
	e.rulesMu.RLock()
	rules := make([]*GeneratedRule, 0)
	for _, rule := range e.rules {
		if rule.Applied && rule.ExpiresAt.After(now) {
			rules = append(rules, rule)
		}
	}
	e.rulesMu.RUnlock()
	return rules
}

// GetStats returns current statistics.
func (e *Engine) GetStats() Stats {
	e.statsMu.RLock()
	stats := e.stats
	e.statsMu.RUnlock()
	return stats
}

// isExcludedPath checks if a path should be excluded.
func (e *Engine) isExcludedPath(path string) bool {
	for _, excluded := range e.config.ExcludedPaths {
		if path == excluded || strings.HasPrefix(path, excluded+"/") {
			return true
		}
	}
	return false
}

// isDailyLimitReached checks if we've hit the daily rule limit.
func (e *Engine) isDailyLimitReached() bool {
	e.statsMu.RLock()
	lastRuleTime := e.stats.LastRuleTime
	rulesToday := e.stats.RulesToday
	e.statsMu.RUnlock()

	// Reset counter if it's a new day
	if !isSameDay(lastRuleTime, time.Now()) {
		e.statsMu.Lock()
		e.stats.RulesToday = 0
		e.statsMu.Unlock()
		return false
	}

	return rulesToday >= e.config.MaxRulesPerDay
}

// cleanupLoop periodically cleans up expired rules.
func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.cleanupExpiredRules()
		case <-e.stopCh:
			return
		}
	}
}

// cleanupExpiredRules removes expired rules.
func (e *Engine) cleanupExpiredRules() {
	now := time.Now()
	e.rulesMu.Lock()
	expiredCount := 0
	for id, rule := range e.rules {
		if rule.ExpiresAt.Before(now) {
			delete(e.rules, id)
			expiredCount++
			// Delete from disk
			filename := filepath.Join(e.config.StoragePath, fmt.Sprintf("rule-%s.json", id))
			os.Remove(filename)
		}
	}
	e.rulesMu.Unlock()

	if expiredCount > 0 {
		e.statsMu.Lock()
		e.stats.ExpiredRules += expiredCount
		e.statsMu.Unlock()
		log.Printf("[remediation] Cleaned up %d expired rules", expiredCount)
	}
}

// saveRule persists a rule to disk.
func (e *Engine) saveRule(rule *GeneratedRule) error {
	if e.config.StoragePath == "" {
		return nil
	}

	filename := filepath.Join(e.config.StoragePath, fmt.Sprintf("rule-%s.json", rule.ID))
	data, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// Stop stops the remediation engine.
func (e *Engine) Stop() {
	close(e.stopCh)
}

// Helper functions
func generateRuleID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isSameDay(t1, t2 time.Time) bool {
	y1, m1, d1 := t1.Date()
	y2, m2, d2 := t2.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}
