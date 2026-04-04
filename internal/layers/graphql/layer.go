// Package graphql provides GraphQL security detection and protection.
// Layer order: 450 (between API Security and Sanitizer)
package graphql

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer is the GraphQL security layer.
type Layer struct {
	mu sync.RWMutex

	enabled bool
	config  Config

	// Metrics
	queriesAnalyzed   int64
	queriesBlocked    int64
	queriesChallenged int64
}

// Config for GraphQL security.
type Config struct {
	Enabled           bool `json:"enabled" yaml:"enabled"`
	MaxDepth          int  `json:"max_depth" yaml:"max_depth"`                // Default: 10
	MaxComplexity     int  `json:"max_complexity" yaml:"max_complexity"`      // Default: 1000
	BlockIntrospection bool `json:"block_introspection" yaml:"block_introspection"` // Default: false
	AllowListEnabled  bool `json:"allow_list_enabled" yaml:"allow_list_enabled"`   // Default: false
	MaxAliases        int  `json:"max_aliases" yaml:"max_aliases"`            // Default: 10
	MaxBatchSize      int  `json:"max_batch_size" yaml:"max_batch_size"`      // Default: 5
}

// DefaultConfig returns default GraphQL security configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:            true,
		MaxDepth:           10,
		MaxComplexity:      1000,
		BlockIntrospection: false,
		AllowListEnabled:   false,
		MaxAliases:         10,
		MaxBatchSize:       5,
	}
}

// New creates a new GraphQL security layer.
func New(cfg Config) (*Layer, error) {
	return &Layer{
		enabled: cfg.Enabled,
		config:  cfg,
	}, nil
}

// Analyze analyzes an HTTP request for GraphQL security issues.
func (l *Layer) Analyze(req *http.Request) (*Result, error) {
	if !l.Enabled() {
		return &Result{Score: 0, Blocked: false}, nil
	}

	// Check if this is a GraphQL request
	if !isGraphQLRequest(req) {
		return &Result{Score: 0, Blocked: false}, nil
	}

	// Parse GraphQL query
	queries, err := extractQueries(req)
	if err != nil {
		return &Result{
			Score:   25,
			Blocked: false,
			Issues:  []Issue{{Type: "parse_error", Description: err.Error()}},
		}, nil
	}

	// Check batch size
	if len(queries) > l.config.MaxBatchSize {
		return &Result{
			Score:   80,
			Blocked: true,
			Issues: []Issue{{
				Type:        "batch_too_large",
				Description: fmt.Sprintf("Batch size %d exceeds maximum %d", len(queries), l.config.MaxBatchSize),
			}},
		}, nil
	}

	var allIssues []Issue
	totalScore := 0

	for _, query := range queries {
		// Parse query AST
		ast, err := ParseQuery(query)
		if err != nil {
			allIssues = append(allIssues, Issue{
				Type:        "parse_error",
				Description: err.Error(),
			})
			totalScore += 25
			continue
		}

		// Analyze query
		analysis := l.analyzeQuery(ast)
		allIssues = append(allIssues, analysis.Issues...)
		totalScore += analysis.Score
	}

	// Normalize score
	if len(queries) > 0 {
		totalScore = totalScore / len(queries)
	}

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}

	result := &Result{
		Score:   totalScore,
		Blocked: totalScore >= 50,
		Issues:  allIssues,
	}

	// Update metrics
	l.updateMetrics(result)

	return result, nil
}

// analyzeQuery analyzes a single GraphQL query.
func (l *Layer) analyzeQuery(ast *AST) *Analysis {
	issues := []Issue{}
	score := 0

	// Check depth
	depth := calculateDepth(ast)
	if depth > l.config.MaxDepth {
		issues = append(issues, Issue{
			Type:        "depth_exceeded",
			Description: fmt.Sprintf("Query depth %d exceeds maximum %d", depth, l.config.MaxDepth),
			Severity:    "high",
		})
		score += 40
	}

	// Check complexity
	complexity := calculateComplexity(ast)
	if complexity > l.config.MaxComplexity {
		issues = append(issues, Issue{
			Type:        "complexity_exceeded",
			Description: fmt.Sprintf("Query complexity %d exceeds maximum %d", complexity, l.config.MaxComplexity),
			Severity:    "high",
		})
		score += 40
	}

	// Check introspection
	if l.config.BlockIntrospection && hasIntrospection(ast) {
		issues = append(issues, Issue{
			Type:        "introspection_blocked",
			Description: "Introspection queries are not allowed",
			Severity:    "medium",
		})
		score += 30
	}

	// Check aliases
	aliases := countAliases(ast)
	if aliases > l.config.MaxAliases {
		issues = append(issues, Issue{
			Type:        "too_many_aliases",
			Description: fmt.Sprintf("Query has %d aliases, maximum is %d", aliases, l.config.MaxAliases),
			Severity:    "medium",
		})
		score += 25
	}

	// Check for directive injection
	if hasDirectiveInjection(ast) {
		issues = append(issues, Issue{
			Type:        "directive_injection",
			Description: "Potentially malicious directive usage detected",
			Severity:    "high",
		})
		score += 50
	}

	return &Analysis{
		Score:  score,
		Issues: issues,
		Depth:  depth,
		Complexity: complexity,
	}
}

// Result contains the GraphQL security analysis result.
type Result struct {
	Score    int     // 0-100
	Blocked  bool
	Issues   []Issue
	Metadata Metadata
}

// Metadata contains additional analysis metadata.
type Metadata struct {
	QueryCount  int
	MaxDepth    int
	MaxComplexity int
	IsBatch     bool
}

// Issue represents a security issue found in the query.
type Issue struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // low, medium, high
	Field       string `json:"field,omitempty"`
}

// Analysis contains query analysis results.
type Analysis struct {
	Score      int
	Issues     []Issue
	Depth      int
	Complexity int
}

// Enabled returns whether the layer is enabled.
func (l *Layer) Enabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.enabled
}

// SetEnabled enables or disables the layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// Config returns the current configuration.
func (l *Layer) Config() Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// UpdateConfig updates the configuration.
func (l *Layer) UpdateConfig(cfg Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = cfg
}

// Stats returns layer statistics.
func (l *Layer) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return Stats{
		QueriesAnalyzed:   l.queriesAnalyzed,
		QueriesBlocked:    l.queriesBlocked,
		QueriesChallenged: l.queriesChallenged,
	}
}

// Stats contains layer statistics.
type Stats struct {
	QueriesAnalyzed   int64
	QueriesBlocked    int64
	QueriesChallenged int64
}

// updateMetrics updates internal metrics.
func (l *Layer) updateMetrics(result *Result) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.queriesAnalyzed++
	if result.Blocked {
		l.queriesBlocked++
	} else if result.Score > 0 {
		l.queriesChallenged++
	}
}

// Name returns the layer name for the WAF pipeline.
func (l *Layer) Name() string {
	return "graphql-security"
}

// Process implements the engine.Layer interface.
// It analyzes the request for GraphQL security issues and returns a LayerResult.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.Enabled() {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	start := time.Now()

	// Use the existing Analyze method
	result, err := l.Analyze(ctx.Request)
	if err != nil {
		return engine.LayerResult{
			Action: engine.ActionPass,
			Score:  0,
		}
	}

	// Determine action based on result
	action := engine.ActionPass
	if result.Blocked {
		action = engine.ActionBlock
	} else if result.Score >= 50 {
		action = engine.ActionChallenge
	} else if result.Score > 0 {
		action = engine.ActionLog
	}

	// Convert issues to findings
	var findings []engine.Finding
	for _, issue := range result.Issues {
		severity := engine.SeverityMedium
		switch issue.Severity {
		case "high":
			severity = engine.SeverityHigh
		case "low":
			severity = engine.SeverityLow
		}

		finding := engine.Finding{
			DetectorName: "graphql-security",
			Category:     "graphql",
			Severity:     severity,
			Score:        result.Score,
			Description:  issue.Description,
			Location:     issue.Field,
		}
		findings = append(findings, finding)
		ctx.Accumulator.Add(&finding)
	}

	return engine.LayerResult{
		Action:   action,
		Score:    result.Score,
		Findings: findings,
		Duration: time.Since(start),
	}
}

// isGraphQLRequest checks if the request is a GraphQL request.
func isGraphQLRequest(req *http.Request) bool {
	// Check URL path
	if strings.Contains(req.URL.Path, "/graphql") {
		return true
	}

	// Check Content-Type header
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/graphql") {
		return true
	}

	// Check for GraphQL-specific query parameter
	if req.URL.Query().Get("query") != "" {
		return true
	}

	return false
}

// extractQueries extracts GraphQL queries from the request.
func extractQueries(req *http.Request) ([]string, error) {
	// GET request with query parameter
	if req.Method == "GET" {
		query := req.URL.Query().Get("query")
		if query != "" {
			return []string{query}, nil
		}
		return nil, fmt.Errorf("no query found")
	}

	// POST request with JSON body
	if req.Method == "POST" {
		// Try to read from request context or body
		// For now, return empty (actual implementation would read body)
		return []string{}, nil
	}

	return nil, fmt.Errorf("unsupported method: %s", req.Method)
}

// calculateDepth calculates the maximum depth of a GraphQL query.
func calculateDepth(ast *AST) int {
	if ast == nil || ast.Document == nil {
		return 0
	}

	maxDepth := 0
	for _, op := range ast.Document.Operations {
		depth := calculateSelectionDepth(op.SelectionSet, 0)
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth
}

// calculateSelectionDepth recursively calculates selection depth.
func calculateSelectionDepth(selections []Selection, currentDepth int) int {
	if len(selections) == 0 {
		return currentDepth
	}

	maxDepth := currentDepth
	for _, sel := range selections {
		if field, ok := sel.(Field); ok {
			if len(field.SelectionSet) > 0 {
				depth := calculateSelectionDepth(field.SelectionSet, currentDepth+1)
				if depth > maxDepth {
					maxDepth = depth
				}
			}
		}
	}
	return maxDepth
}

// calculateComplexity calculates the complexity score of a query.
func calculateComplexity(ast *AST) int {
	if ast == nil || ast.Document == nil {
		return 0
	}

	complexity := 0
	for _, op := range ast.Document.Operations {
		complexity += calculateSelectionComplexity(op.SelectionSet)
	}
	return complexity
}

// calculateSelectionComplexity recursively calculates complexity.
func calculateSelectionComplexity(selections []Selection) int {
	if len(selections) == 0 {
		return 0
	}

	complexity := 0
	for _, sel := range selections {
		if field, ok := sel.(Field); ok {
			// Base complexity for field
			complexity += 1

			// Add complexity for arguments
			complexity += len(field.Arguments)

			// Recurse into sub-selections
			complexity += calculateSelectionComplexity(field.SelectionSet)
		}
	}
	return complexity
}

// hasIntrospection checks if the query contains introspection fields.
func hasIntrospection(ast *AST) bool {
	if ast == nil || ast.Document == nil {
		return false
	}

	introspectionFields := []string{
		"__schema", "__type", "__typename",
		"__fields", "__args", "__inputFields",
	}

	for _, op := range ast.Document.Operations {
		if containsFields(op.SelectionSet, introspectionFields) {
			return true
		}
	}
	return false
}

// containsFields checks if selection contains any of the specified fields.
func containsFields(selections []Selection, fieldNames []string) bool {
	for _, sel := range selections {
		if field, ok := sel.(Field); ok {
			for _, name := range fieldNames {
				if field.Name == name {
					return true
				}
			}
			if containsFields(field.SelectionSet, fieldNames) {
				return true
			}
		}
	}
	return false
}

// countAliases counts the number of aliases in a query.
func countAliases(ast *AST) int {
	if ast == nil || ast.Document == nil {
		return 0
	}

	count := 0
	for _, op := range ast.Document.Operations {
		count += countAliasesInSelection(op.SelectionSet)
	}
	return count
}

// countAliasesInSelection counts aliases in selections.
func countAliasesInSelection(selections []Selection) int {
	count := 0
	for _, sel := range selections {
		if field, ok := sel.(Field); ok {
			if field.Alias != "" && field.Alias != field.Name {
				count++
			}
			count += countAliasesInSelection(field.SelectionSet)
		}
	}
	return count
}

// hasDirectiveInjection checks for potentially malicious directive usage.
func hasDirectiveInjection(ast *AST) bool {
	if ast == nil || ast.Document == nil {
		return false
	}

	// Check for suspicious directive patterns
	suspiciousDirectives := []string{
		"skip", "include", "deprecated",
		// Add any custom directives that could be abused
	}

	// Simple regex check for now
	queryStr := ast.Raw
	for _, dir := range suspiciousDirectives {
		if strings.Contains(queryStr, "@"+dir) {
			// Check if usage is suspicious (multiple directives, etc.)
			re := regexp.MustCompile(`@` + dir + `\s*\(`)
			if len(re.FindAllString(queryStr, -1)) > 5 {
				return true
			}
		}
	}

	return false
}
