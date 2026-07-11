package crs

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/logging"
)

// Layer implements the OWASP Core Rule Set WAF layer.
type Layer struct {
	config *Config
	log    *slog.Logger
	rules  []*Rule
	parser *Parser

	// Rule lookup maps
	rulesByPhase map[int][]*Rule
	rulesByID    map[string]*Rule

	// Disabled rules
	disabledRules map[string]bool
	absPath       func(string) (string, error)
	relPath       func(string, string) (string, error)
	walkDir       func(string, fs.WalkDirFunc) error

	// loadErr records a non-nil error if rule loading failed during
	// construction. The serve binary checks LoadError() and refuses to start a
	// CRS layer that could not load its ruleset (fail-closed), rather than
	// running an empty, silently-ineffective ruleset.
	loadErr error

	mu sync.RWMutex
}

// NewLayer creates a new CRS layer.
func NewLayer(config *Config) *Layer {
	if config == nil {
		config = DefaultConfig()
	}

	layer := &Layer{
		config:        config,
		log:           logging.NewLogger("crs"),
		rules:         []*Rule{},
		parser:        NewParser(),
		rulesByPhase:  make(map[int][]*Rule),
		rulesByID:     make(map[string]*Rule),
		disabledRules: make(map[string]bool),
		absPath:       filepath.Abs,
		relPath:       filepath.Rel,
		walkDir:       filepath.WalkDir,
	}

	// Mark disabled rules
	for _, id := range config.DisabledRules {
		layer.disabledRules[id] = true
	}

	// Load rules if path specified
	if config.RulePath != "" {
		if err := layer.LoadRules(config.RulePath); err != nil {
			layer.log.Warn("failed to load CRS rules", "path", config.RulePath, "error", err)
			layer.loadErr = err
		}
	}

	return layer
}

// LoadError returns any error encountered while loading rules during
// construction (nil if rules loaded cleanly or no rule path was configured).
// Callers that wire CRS into a live pipeline should treat a non-nil result as
// fatal, since an enabled CRS layer with no rules enforces nothing.
func (l *Layer) LoadError() error { return l.loadErr }

// Name returns the layer name.
func (l *Layer) Name() string {
	return "crs"
}

// Order returns the execution order.
func (l *Layer) Order() int { return engine.OrderCRS }

// LoadRules loads CRS rules from a directory.
func (l *Layer) LoadRules(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	cleanPath, err := cleanCRSRulePath(path, false)
	if err != nil {
		return err
	}

	// Check if path is a file or directory
	info, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("accessing rule path: %w", err)
	}

	if info.IsDir() {
		// Resolve the root path to detect symlink escapes
		rootAbs, absErr := l.absPath(cleanPath)
		if absErr != nil {
			return fmt.Errorf("resolving rule path: %w", absErr)
		}
		rootAbs = filepath.Clean(rootAbs)
		// Load all .conf files from directory, skipping symlinks
		err = l.walkDir(cleanPath, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Skip symlinks to prevent following links outside intended directory
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			// Verify path stays within root directory
			pAbs, absErr := l.absPath(p)
			if absErr != nil {
				return nil
			}
			rel, relErr := l.relPath(rootAbs, filepath.Clean(pAbs))
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(p, ".conf") {
				if err := l.loadRuleFile(p); err != nil {
					// Log error but continue loading other files
					return fmt.Errorf("loading %s: %w", p, err)
				}
			}
			return nil
		})
	} else {
		// Single file
		err = l.loadRuleFile(cleanPath)
	}

	if err != nil {
		return err
	}

	// Build lookup maps
	l.buildRuleMaps()

	return nil
}

// loadRuleFile loads rules from a single file.
func (l *Layer) loadRuleFile(path string) error {
	cleanPath, err := cleanCRSRulePath(path, false)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(cleanPath) // #nosec G304 -- rule files are operator-selected CRS inputs, rejected on NUL and cleaned before use.
	if err != nil {
		return err
	}

	rules, err := l.parser.ParseFile(string(content))
	if err != nil {
		return err
	}

	for _, rule := range rules {
		// Skip disabled rules
		if l.disabledRules[rule.ID] {
			continue
		}

		// Skip rules above paranoia level
		if rule.ParanoiaLevel > l.config.ParanoiaLevel {
			continue
		}

		l.rules = append(l.rules, rule)
	}

	return nil
}

func cleanCRSRulePath(path string, allowEmpty bool) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("CRS rule path contains NUL byte")
	}
	if path == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("CRS rule path must not be empty")
	}
	return filepath.Clean(path), nil
}

// buildRuleMaps builds lookup maps for rules.
func (l *Layer) buildRuleMaps() {
	l.rulesByPhase = make(map[int][]*Rule)
	l.rulesByID = make(map[string]*Rule)

	for _, rule := range l.rules {
		l.rulesByPhase[rule.Phase] = append(l.rulesByPhase[rule.Phase], rule)
		if rule.ID != "" {
			l.rulesByID[rule.ID] = rule
		}
	}
}

// Process implements the engine.Layer interface.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	l.mu.RLock()
	enabled := l.config.Enabled
	l.mu.RUnlock()
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.CRS.Enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Create transaction from context
	tx := l.createTransaction(ctx)

	// Process rules by phase
	// Phase 1: Request headers
	// Phase 2: Request body
	anomalyScore := 0
	blockingScore := 0
	findings := []engine.Finding{}

	l.mu.RLock()
	defer l.mu.RUnlock()

	// Phase 1: Request headers (after receiving request headers)
	for _, rule := range l.rulesByPhase[1] {
		matched, score, finding := l.evaluateRule(rule, tx)
		if matched {
			anomalyScore += score
			if rule.Actions.Severity == "CRITICAL" || rule.Actions.Severity == "ERROR" {
				blockingScore += score
			}
			if finding != nil {
				findings = append(findings, *finding)
			}

			// Execute actions
			if l.shouldBlock(rule, anomalyScore, blockingScore) {
				return engine.LayerResult{
					Action:   engine.ActionBlock,
					Findings: findings,
					Score:    anomalyScore,
				}
			}
		}
	}

	// Phase 2: Request body (after receiving request body)
	for _, rule := range l.rulesByPhase[2] {
		matched, score, finding := l.evaluateRule(rule, tx)
		if matched {
			anomalyScore += score
			if rule.Actions.Severity == "CRITICAL" || rule.Actions.Severity == "ERROR" {
				blockingScore += score
			}
			if finding != nil {
				findings = append(findings, *finding)
			}

			if l.shouldBlock(rule, anomalyScore, blockingScore) {
				return engine.LayerResult{
					Action:   engine.ActionBlock,
					Findings: findings,
					Score:    anomalyScore,
				}
			}
		}
	}

	return engine.LayerResult{
		Action:   engine.ActionPass,
		Findings: findings,
		Score:    anomalyScore,
	}
}

// createTransaction creates a transaction from request context.
func (l *Layer) createTransaction(ctx *engine.RequestContext) *Transaction {
	tx := NewTransaction()

	// Request line
	tx.Method = ctx.Method
	tx.URI = ctx.Path
	if ctx.Request != nil && ctx.Request.URL != nil {
		tx.URI = ctx.Request.URL.RequestURI()
		tx.Query = ctx.Request.URL.RawQuery
		tx.Path = ctx.Request.URL.Path
	}
	tx.Protocol = "HTTP/1.1"
	if ctx.Request != nil {
		tx.Protocol = ctx.Request.Proto
	}

	// Headers
	if ctx.Headers != nil {
		tx.RequestHeaders = ctx.Headers
	}

	// Client info
	if ctx.ClientIP != nil {
		tx.ClientIP = ctx.ClientIP.String()
	}

	// Body
	if ctx.Body != nil {
		tx.RequestBody = ctx.Body
	}

	tx.resolver = NewVariableResolver(tx)
	tx.evaluator = NewOperatorEvaluator()
	return tx
}

// evaluateRule evaluates a single rule against transaction.
func (l *Layer) evaluateRule(rule *Rule, tx *Transaction) (bool, int, *engine.Finding) {
	resolver := tx.resolver
	evaluator := tx.evaluator
	resolver.transaction = tx
	evaluator.captureGroups = evaluator.captureGroups[:0]

	// Evaluate variables
	matched := false
	matchedValues := []string{}

	for _, variable := range rule.Variables {
		// Skip if variable is excluded
		if variable.Exclude {
			continue
		}

		values, _ := resolver.Resolve(variable)

		// Apply transformations
		for _, value := range values {
			transformed := Transform(value, rule.Actions.Transformations)

			// Evaluate operator
			result, err := evaluator.Evaluate(rule.Operator, transformed)
			if err != nil {
				continue
			}

			if result {
				matched = true
				matchedValues = append(matchedValues, transformed)

				// If not chaining, we can stop at first match
				if rule.Chain == nil {
					break
				}
			}
		}

		if matched && rule.Chain == nil {
			break
		}
	}

	// If no match, rule doesn't apply
	if !matched {
		return false, 0, nil
	}

	// Evaluate chain if present (AND logic)
	if rule.Chain != nil {
		chainMatched, _, _ := l.evaluateRule(rule.Chain, tx)
		if !chainMatched {
			return false, 0, nil
		}
	}

	// Rule matched - determine score
	score := 0
	switch rule.Actions.Severity {
	case "CRITICAL":
		score = 10
	case "ERROR":
		score = 8
	case "WARNING":
		score = 5
	case "NOTICE":
		score = 2
	default:
		score = 1
	}

	// Create finding
	data := strings.Join(matchedValues, ", ")
	if len(data) > 200 {
		data = data[:200]
	}
	finding := &engine.Finding{
		DetectorName: l.Name(),
		Category:     rule.ID,
		Description:  rule.Msg,
		MatchedValue: data,
		Score:        score,
		Location:     "crs",
	}

	// Set transaction variables if specified
	for _, varAction := range rule.Actions.SetVar {
		switch varAction.Operation {
		case "=":
			tx.SetVar(varAction.Variable, varAction.Value)
		case "+=":
			// For anomaly score, add numeric value
			tx.AddAnomalyScore(score)
		}
	}

	return true, score, finding
}

// shouldBlock determines if rule actions should cause immediate blocking.
func (l *Layer) shouldBlock(rule *Rule, anomalyScore, _ int) bool {
	// Check for explicit block action
	switch rule.Actions.Action {
	case "block", "deny", "drop":
		return true
	}

	// Check anomaly threshold
	if anomalyScore >= l.config.AnomalyThreshold {
		return true
	}

	return false
}

// GetRule returns a rule by ID.
func (l *Layer) GetRule(id string) *Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rulesByID[id]
}

// GetRulesByPhase returns all rules for a given phase.
func (l *Layer) GetRulesByPhase(phase int) []*Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rulesByPhase[phase]
}

// GetAllRules returns all loaded rules.
func (l *Layer) GetAllRules() []*Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*Rule, len(l.rules))
	copy(result, l.rules)
	return result
}

// DisableRule disables a rule by ID.
func (l *Layer) DisableRule(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.disabledRules[id] = true
}

// EnableRule enables a previously disabled rule.
func (l *Layer) EnableRule(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.disabledRules, id)
}

// SetParanoiaLevel sets the paranoia level and rebuilds rule maps.
func (l *Layer) SetParanoiaLevel(level int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.config.ParanoiaLevel = level
	l.buildRuleMaps()
}

// IsRuleEnabled checks if a rule is enabled.
func (l *Layer) IsRuleEnabled(id string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return !l.disabledRules[id]
}

// RuleSet provides a default set of CRS rules for embedded use.
type RuleSet struct {
	Rules []*Rule
}

// Stats returns statistics about loaded rules.
func (l *Layer) Stats() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := map[string]int{
		"total":    len(l.rules),
		"phase_1":  len(l.rulesByPhase[1]),
		"phase_2":  len(l.rulesByPhase[2]),
		"phase_3":  len(l.rulesByPhase[3]),
		"phase_4":  len(l.rulesByPhase[4]),
		"phase_5":  len(l.rulesByPhase[5]),
		"disabled": len(l.disabledRules),
	}

	return stats
}
