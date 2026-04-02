// Package rules implements a custom rule-based WAF layer.
// Users can define rules with conditions (field + operator + value)
// and actions (block, log, challenge, pass) via config or dashboard API.
package rules

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
)

// Rule defines a custom WAF rule with conditions and an action.
type Rule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Enabled    bool        `json:"enabled"`
	Priority   int         `json:"priority"`   // lower = evaluated first
	Conditions []Condition `json:"conditions"` // all must match (AND logic)
	Action     string      `json:"action"`     // "block", "log", "challenge", "pass"
	Score      int         `json:"score"`      // score to add when matched
}

// Condition defines a single match condition within a rule.
type Condition struct {
	Field string `json:"field"` // "path", "method", "ip", "country", "header:X-Name", "user_agent", "query", "body_size", "host", "score"
	Op    string `json:"op"`    // "equals", "not_equals", "contains", "not_contains", "starts_with", "ends_with", "matches", "in", "not_in", "in_cidr", "greater_than", "less_than"
	Value any    `json:"value"` // string, []string, float64 depending on op
}

// Config holds the custom rules layer configuration.
type Config struct {
	Enabled bool   `json:"enabled"`
	Rules   []Rule `json:"rules"`
}

// Layer implements engine.Layer for custom rule evaluation.
type Layer struct {
	mu    sync.RWMutex
	rules []Rule
	geodb *geoip.DB
	// compiled regex cache
	regexCache map[string]*regexp.Regexp
}

// NewLayer creates a new custom rules layer.
func NewLayer(cfg Config, geodb *geoip.DB) *Layer {
	l := &Layer{
		geodb:      geodb,
		regexCache: make(map[string]*regexp.Regexp),
	}
	l.SetRules(cfg.Rules)
	return l
}

// Name returns the layer name.
func (l *Layer) Name() string { return "rules" }

// SetRules replaces all rules (thread-safe, for hot-reload).
func (l *Layer) SetRules(rules []Rule) {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules = sorted
	// Clear regex cache
	l.regexCache = make(map[string]*regexp.Regexp)
}

// Rules returns a copy of all rules.
func (l *Layer) Rules() []Rule {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Rule, len(l.rules))
	copy(out, l.rules)
	return out
}

// AddRule adds a rule (thread-safe).
func (l *Layer) AddRule(rule Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rules = append(l.rules, rule)
	sort.Slice(l.rules, func(i, j int) bool {
		return l.rules[i].Priority < l.rules[j].Priority
	})
}

// RemoveRule removes a rule by ID.
func (l *Layer) RemoveRule(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, r := range l.rules {
		if r.ID == id {
			l.rules = append(l.rules[:i], l.rules[i+1:]...)
			return true
		}
	}
	return false
}

// ToggleRule enables/disables a rule by ID.
func (l *Layer) ToggleRule(id string, enabled bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.rules {
		if l.rules[i].ID == id {
			l.rules[i].Enabled = enabled
			return true
		}
	}
	return false
}

// UpdateRule replaces a rule by ID.
func (l *Layer) UpdateRule(rule Rule) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.rules {
		if l.rules[i].ID == rule.ID {
			l.rules[i] = rule
			sort.Slice(l.rules, func(a, b int) bool {
				return l.rules[a].Priority < l.rules[b].Priority
			})
			return true
		}
	}
	return false
}

// Process evaluates all enabled rules against the request.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	l.mu.RLock()
	rules := l.rules
	l.mu.RUnlock()

	start := time.Now()
	var findings []engine.Finding
	resultAction := engine.ActionPass
	totalScore := 0

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if l.matchAll(rule.Conditions, ctx) {
			action := parseAction(rule.Action)

			findings = append(findings, engine.Finding{
				DetectorName: "rule:" + rule.ID,
				Category:     "custom-rule",
				Severity:     actionToSeverity(action),
				Score:        rule.Score,
				Description:  rule.Name,
				Location:     "rule",
				Confidence:   1.0,
			})
			totalScore += rule.Score

			// pass = whitelist (skip further rules)
			if action == engine.ActionPass {
				return engine.LayerResult{
					Action:   engine.ActionPass,
					Duration: time.Since(start),
				}
			}

			// Promote action (block > challenge > log)
			switch {
			case action == engine.ActionBlock:
				resultAction = engine.ActionBlock
			case action == engine.ActionChallenge && resultAction != engine.ActionBlock:
				resultAction = engine.ActionChallenge
			case action == engine.ActionLog && resultAction == engine.ActionPass:
				resultAction = engine.ActionLog
			}
		}
	}

	return engine.LayerResult{
		Action:   resultAction,
		Findings: findings,
		Score:    totalScore,
		Duration: time.Since(start),
	}
}

// --- Condition Evaluation ---

func (l *Layer) matchAll(conditions []Condition, ctx *engine.RequestContext) bool {
	for _, cond := range conditions {
		if !l.matchCondition(cond, ctx) {
			return false
		}
	}
	return true
}

func (l *Layer) matchCondition(cond Condition, ctx *engine.RequestContext) bool {
	fieldValue := l.getFieldValue(cond.Field, ctx)

	switch cond.Op {
	case "equals":
		return fieldValue == toString(cond.Value)
	case "not_equals":
		return fieldValue != toString(cond.Value)
	case "contains":
		return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(toString(cond.Value)))
	case "not_contains":
		return !strings.Contains(strings.ToLower(fieldValue), strings.ToLower(toString(cond.Value)))
	case "starts_with":
		return strings.HasPrefix(fieldValue, toString(cond.Value))
	case "ends_with":
		return strings.HasSuffix(fieldValue, toString(cond.Value))
	case "matches":
		return l.regexMatch(toString(cond.Value), fieldValue)
	case "in":
		return l.inList(cond.Value, fieldValue)
	case "not_in":
		return !l.inList(cond.Value, fieldValue)
	case "in_cidr":
		return l.inCIDR(toString(cond.Value), ctx.ClientIP)
	case "greater_than":
		return toFloat(fieldValue) > toFloat(toString(cond.Value))
	case "less_than":
		return toFloat(fieldValue) < toFloat(toString(cond.Value))
	default:
		return false
	}
}

func (l *Layer) getFieldValue(field string, ctx *engine.RequestContext) string {
	switch {
	case field == "path":
		return ctx.Path
	case field == "method":
		return ctx.Method
	case field == "ip":
		if ctx.ClientIP != nil {
			return ctx.ClientIP.String()
		}
		return ""
	case field == "country":
		if l.geodb != nil && ctx.ClientIP != nil {
			return l.geodb.Lookup(ctx.ClientIP)
		}
		return ""
	case field == "user_agent":
		if ua, ok := ctx.Headers["User-Agent"]; ok && len(ua) > 0 {
			return ua[0]
		}
		return ""
	case field == "query":
		if ctx.Request != nil {
			return ctx.Request.URL.RawQuery
		}
		return ""
	case field == "body_size":
		return fmt.Sprintf("%d", len(ctx.Body))
	case field == "host":
		if ctx.Request != nil {
			return ctx.Request.Host
		}
		return ""
	case field == "content_type":
		return ctx.ContentType
	case field == "score":
		if ctx.Accumulator != nil {
			return fmt.Sprintf("%d", ctx.Accumulator.Total())
		}
		return "0"
	case strings.HasPrefix(field, "header:"):
		headerName := field[7:]
		if vals, ok := ctx.Headers[headerName]; ok && len(vals) > 0 {
			return vals[0]
		}
		return ""
	case strings.HasPrefix(field, "cookie:"):
		cookieName := field[7:]
		if val, ok := ctx.Cookies[cookieName]; ok {
			return val
		}
		return ""
	default:
		return ""
	}
}

func (l *Layer) regexMatch(pattern, value string) bool {
	l.mu.RLock()
	re, ok := l.regexCache[pattern]
	l.mu.RUnlock()

	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		l.mu.Lock()
		l.regexCache[pattern] = re
		l.mu.Unlock()
	}

	return re.MatchString(value)
}

func (l *Layer) inList(value any, target string) bool {
	switch v := value.(type) {
	case []string:
		for _, s := range v {
			if strings.EqualFold(s, target) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if strings.EqualFold(toString(item), target) {
				return true
			}
		}
	case string:
		return strings.EqualFold(v, target)
	}
	return false
}

func (l *Layer) inCIDR(cidr string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as plain IP
		parsed := net.ParseIP(cidr)
		return parsed != nil && parsed.Equal(ip)
	}
	return network.Contains(ip)
}

// --- Helpers ---

func parseAction(s string) engine.Action {
	switch strings.ToLower(s) {
	case "block":
		return engine.ActionBlock
	case "log":
		return engine.ActionLog
	case "challenge":
		return engine.ActionChallenge
	case "pass":
		return engine.ActionPass
	default:
		return engine.ActionLog
	}
}

func actionToSeverity(a engine.Action) engine.Severity {
	switch a {
	case engine.ActionBlock:
		return engine.SeverityHigh
	case engine.ActionChallenge:
		return engine.SeverityMedium
	case engine.ActionLog:
		return engine.SeverityLow
	default:
		return engine.SeverityInfo
	}
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toFloat(s string) float64 {
	var f float64
	_, _ = fmt.Sscanf(s, "%f", &f)
	return f
}
