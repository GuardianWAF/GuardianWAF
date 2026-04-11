// Package crs provides OWASP Core Rule Set (CRS) integration for GuardianWAF.
// Supports SecRule syntax with paranoia levels and exclusions.
package crs

import (
	"sync"
	"time"
)

// Config holds CRS layer configuration.
type Config struct {
	Enabled          bool     `yaml:"enabled"`
	RulePath         string   `yaml:"rule_path"`          // Path to CRS rules directory
	ParanoiaLevel    int      `yaml:"paranoia_level"`     // 1-4 (default: 1)
	AnomalyThreshold int      `yaml:"anomaly_threshold"`  // Block threshold (default: 5)
	Exclusions       []string `yaml:"exclusions"`         // Rule exclusions
	DisabledRules    []string `yaml:"disabled_rules"`     // Rule IDs to disable
}

// DefaultConfig returns default CRS configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          false,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
		Exclusions:       []string{},
		DisabledRules:    []string{},
	}
}

// Rule represents a parsed CRS SecRule.
type Rule struct {
	ID        string         // Rule ID (e.g., "911100")
	Phase     int            // Processing phase (1=request headers, 2=request body, 3=response headers, 4=response body, 5=logging)
	Severity   string         // CRITICAL, ERROR, WARNING, NOTICE
	Msg        string         // Human-readable message
	Rev        string         // Rule revision
	Tags       []string       // Rule tags (e.g., "application-multi", "language-multi")

	// Rule components
	Variables  []RuleVariable // Variables to inspect (e.g., REQUEST_HEADERS)
	Operator   RuleOperator   // Matching operator (e.g., @rx, @eq)
	Actions    RuleActions    // Actions to execute on match

	// Chaining
	Chain      *Rule          // Next rule in chain (AND)
	ChainType  string         // "and" (default) or "or"

	// Metadata
	ParanoiaLevel int       // Minimum paranoia level for this rule
	Maturity      int       // Rule maturity (1-10)
	Accuracy      int       // Rule accuracy (1-10)
}

// RuleVariable represents a SecRule variable specification.
type RuleVariable struct {
	Name          string            // Variable name (e.g., "REQUEST_HEADERS")
	Collection    string            // Collection name if applicable
	Key           string            // Specific key (e.g., ":User-Agent")
	KeyRegex      bool              // Key is a regex
	Count         bool              // Use & to count matches
	Exclude       bool              // Use ! to exclude
}

// RuleOperator represents a SecRule operator.
type RuleOperator struct {
	Type          string            // Operator type (@rx, @eq, @ge, @le, @contains, @beginsWith, @endsWith, @pm, @pmf, @within)
	Negated       bool              // !@ operator (negation)
	Argument      string            // Operator argument (e.g., regex pattern)
}

// RuleActions represents SecRule actions.
type RuleActions struct {
	ID          string            `json:"id"`
	Phase       int               `json:"phase"`

	// Primary action
	Action        string            // deny, pass, block, drop, redirect, proxy, log, auditlog, nolog

	// Status and redirect
	Status        int               // HTTP status code
	Redirect      string            // Redirect URL

	// Scoring
	SetVar        []VarAction       // Set TX variable
	Severity      string            // Rule severity

	// Logging
	Msg           string            // Log message
	LogData       string            // Additional log data
	Tag           []string          // Tags to add

	// Transformation
	Transformations []string        // t:lowercase, t:urlDecode, t:htmlEntityDecode, etc.

	// Execution control
	Skip          int               // Skip next N rules
	SkipAfter     string            // Skip until marker
	Chain         bool              // Continue to chained rule
}

// VarAction represents a variable assignment action.
type VarAction struct {
	Collection string
	Variable   string
	Operation  string // =, +, -, =+
	Value      string
}

// Transaction holds request/response data for rule evaluation.
type Transaction struct {
	// Request data
	Method        string
	URI           string
	Path          string
	Query         string
	Protocol      string
	RequestHeaders map[string][]string
	RequestBody   []byte
	RequestArgs   map[string][]string
	RequestCookies map[string]string

	// Response data
	StatusCode    int
	ResponseHeaders map[string][]string
	ResponseBody  []byte

	// Metadata
	ClientIP      string
	ClientPort    int
	ServerIP      string
	ServerPort    int
	Timestamp     time.Time

	// Variables (TX collection)
	Variables     map[string]string
	AnomalyScore  int
	BlockingScore int

	// Matched rules
	MatchedRules  []*Rule

	// Cached string conversions of body byte slices
	requestBodyStr string
	requestBodyOnce sync.Once
	responseBodyStr string
	responseBodyOnce sync.Once

	// Reusable resolver and evaluator to avoid per-rule allocation
	resolver *VariableResolver
	evaluator *OperatorEvaluator
}

// NewTransaction creates a new transaction for rule evaluation.
func NewTransaction() *Transaction {
	return &Transaction{
		RequestHeaders:  make(map[string][]string),
		RequestArgs:     make(map[string][]string),
		RequestCookies:  make(map[string]string),
		ResponseHeaders: make(map[string][]string),
		Variables:       make(map[string]string),
		MatchedRules:    []*Rule{},
		Timestamp:       time.Now(),
	}
}

// RequestBodyString returns the request body as a string, cached after first conversion.
func (tx *Transaction) RequestBodyString() string {
	tx.requestBodyOnce.Do(func() {
		tx.requestBodyStr = string(tx.RequestBody)
	})
	return tx.requestBodyStr
}

// ResponseBodyString returns the response body as a string, cached after first conversion.
func (tx *Transaction) ResponseBodyString() string {
	tx.responseBodyOnce.Do(func() {
		tx.responseBodyStr = string(tx.ResponseBody)
	})
	return tx.responseBodyStr
}

// SetVar sets a transaction variable.
func (tx *Transaction) SetVar(name, value string) {
	tx.Variables[name] = value
}

// GetVar gets a transaction variable.
func (tx *Transaction) GetVar(name string) string {
	return tx.Variables[name]
}

// AddAnomalyScore adds to the anomaly score.
func (tx *Transaction) AddAnomalyScore(score int) {
	tx.AnomalyScore += score
}
