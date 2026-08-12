// Package rules implements a custom rule-based WAF layer.
// Users can define rules with conditions (field + operator + value)
// and actions (block, log, challenge, pass) via config or dashboard API.
package rules

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
	"github.com/guardianwaf/guardianwaf/internal/logging"
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
	log        *slog.Logger
	mu         sync.RWMutex
	rules      []Rule
	geodb      *geoip.DB
	regexCache map[string]*regexp.Regexp
}

// NewLayer creates a new custom rules layer.
func NewLayer(cfg *Config, geodb *geoip.DB) *Layer {
	l := &Layer{
		log:        logging.NewLogger("rules"),
		geodb:      geodb,
		regexCache: make(map[string]*regexp.Regexp),
	}
	l.SetRules(cfg.Rules)
	return l
}

// Name returns the layer name.
func (l *Layer) Name() string { return "rules" }
func (l *Layer) Order() int   { return engine.OrderRules }

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
			// Copy to new slice to avoid mutating shared backing array
			newRules := make([]Rule, len(l.rules)-1)
			copy(newRules, l.rules[:i])
			copy(newRules[i:], l.rules[i+1:])
			l.rules = newRules
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
	globalRules := make([]Rule, len(l.rules))
	copy(globalRules, l.rules)
	l.mu.RUnlock()

	// Get all rules (global + tenant-specific)
	allRules := globalRules
	if ctx.TenantWAFConfig != nil && len(ctx.TenantWAFConfig.CustomRules.Rules) > 0 {
		tenantRules := convertConfigRules(ctx.TenantWAFConfig.CustomRules.Rules)
		// Append tenant rules to global rules
		allRules = make([]Rule, len(globalRules), len(globalRules)+len(tenantRules))
		copy(allRules, globalRules)
		allRules = append(allRules, tenantRules...)
		sort.Slice(allRules, func(i, j int) bool {
			return allRules[i].Priority < allRules[j].Priority
		})
	}

	start := time.Now()
	deadline := newRegexDeadline()
	var findings []engine.Finding
	resultAction := engine.ActionPass
	totalScore := 0

	for _, rule := range allRules {
		if !rule.Enabled {
			continue
		}

		if l.matchAll(rule.Conditions, ctx, deadline) {
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

func (l *Layer) matchAll(conditions []Condition, ctx *engine.RequestContext, deadline *regexDeadline) bool {
	for _, cond := range conditions {
		if !l.matchCondition(cond, ctx, deadline) {
			return false
		}
	}
	return true
}

func (l *Layer) matchCondition(cond Condition, ctx *engine.RequestContext, deadline *regexDeadline) bool {
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
		return l.regexMatch(toString(cond.Value), fieldValue, deadline)
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
		return strconv.Itoa(len(ctx.Body))
	case field == "host":
		if ctx.Request != nil {
			return ctx.Request.Host
		}
		return ""
	case field == "content_type":
		return ctx.ContentType
	case field == "score":
		if ctx.Accumulator != nil {
			return strconv.Itoa(ctx.Accumulator.Total())
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

// regexMatchTimeout limits individual regex execution to prevent ReDoS.
// Go's regexp engine cannot be cancelled mid-match, so a timed-out goroutine
// keeps burning CPU until the engine finishes. 500 ms (down from 5 s) limits
// the worst-case CPU waste per goroutine while remaining far above the
// sub-millisecond latency of legitimate matches.
const regexMatchTimeout = 500 * time.Millisecond

// regexTotalBudget caps the cumulative wall-clock time a single request may
// spend on regex evaluation. Once exhausted, regexMatch fails closed (returns
// true) instead of spawning more uncancellable goroutines. This bounds the
// total CPU drain: with a 2 s budget and 500 ms per-regex timeout, at most
// ~4 timed-out goroutines per request can accumulate.
const regexTotalBudget = 2 * time.Second

const maxConcurrentRegex = 500

// regexSem is a counting semaphore that bounds simultaneous regex goroutines.
// Unlike a counter-and-skip approach, callers queue-and-wait for a slot so
// detection is never silently bypassed.
var regexSem = make(chan struct{}, maxConcurrentRegex)

var regexTimeoutAfter = time.After

// regexDeadline tracks the remaining per-request regex evaluation budget.
// A nil deadline means "no budget tracking" (used by tests that call
// regexMatch directly without going through Process).
type regexDeadline struct {
	deadline time.Time
}

// newRegexDeadline creates a deadline for a fresh request.
func newRegexDeadline() *regexDeadline {
	return &regexDeadline{deadline: time.Now().Add(regexTotalBudget)}
}

// exhausted reports whether the per-request regex budget is spent.
// When true, the caller must fail closed instead of spawning goroutines.
func (d *regexDeadline) exhausted() bool {
	if d == nil {
		return false
	}
	return time.Now().After(d.deadline)
}

// remaining returns the time left until the deadline, clamped to >= 0.
// Returns a large duration when d is nil (no limit).
func (d *regexDeadline) remaining() time.Duration {
	if d == nil {
		return regexMatchTimeout
	}
	r := time.Until(d.deadline)
	if r < 0 {
		return 0
	}
	return r
}

// isRegexSafe performs basic static analysis to reject pathological regex patterns.
func isRegexSafe(pattern string) error {
	nesting := 0
	maxNesting := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '(':
			nesting++
			if nesting > maxNesting {
				maxNesting = nesting
			}
		case ')':
			if nesting > 0 {
				nesting--
			}
		}
	}
	if maxNesting > 6 {
		return fmt.Errorf("regex too complex: nesting depth %d exceeds limit 6", maxNesting)
	}
	if len(pattern) > 2000 {
		return fmt.Errorf("regex too long: %d bytes exceeds limit 2000", len(pattern))
	}
	return nil
}

func (l *Layer) regexMatch(pattern, value string, deadline *regexDeadline) bool {
	// If the per-request regex budget is already exhausted, fail closed
	// instead of spawning more uncancellable goroutines.
	if deadline.exhausted() {
		return true
	}

	l.mu.RLock()
	re, ok := l.regexCache[pattern]
	l.mu.RUnlock()

	if !ok {
		if err := isRegexSafe(pattern); err != nil {
			l.log.Warn("rejecting unsafe regex", "error", err)
			return false
		}
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		l.mu.Lock()
		if len(l.regexCache) >= 10000 {
			// Evict a random entry to make room
			for k := range l.regexCache {
				delete(l.regexCache, k)
				break
			}
		}
		l.regexCache[pattern] = re
		l.mu.Unlock()
	}

	return regexMatchWithTimeout(re, value, deadline)
}

// regexMatchWithTimeout runs re.MatchString in a goroutine with a timeout.
// It bounds concurrent regex goroutines via a counting semaphore so that
// callers queue-and-wait for a slot instead of being silently dropped.
//
// The per-request deadline (regexDeadline) clamps both the semaphore wait
// and the per-regex execution timeout. When the budget is exhausted the
// caller (regexMatch) already fails closed without calling this function;
// the clamping here ensures the last regex within budget doesn't overrun.
func regexMatchWithTimeout(re *regexp.Regexp, s string, deadline *regexDeadline) bool {
	// Clamp the semaphore-wait timeout to the remaining per-request budget.
	semWait := deadline.remaining()
	if semWait == 0 {
		return true // budget exhausted while waiting
	}

	// Acquire a semaphore slot, queueing if necessary.
	select {
	case regexSem <- struct{}{}:
		defer func() { <-regexSem }()
	default:
		// Fast path missed; wait up to the remaining budget.
		select {
		case regexSem <- struct{}{}:
			defer func() { <-regexSem }()
		case <-regexTimeoutAfter(semWait):
			// Extreme overload: every slot is held by a long-running regex.
			// Failing open would let attackers disable detection by flooding.
			return true
		}
	}

	// Clamp the per-regex timeout to the remaining budget, but never exceed
	// the per-regex ceiling (regexMatchTimeout).
	perRegex := regexMatchTimeout
	if remaining := deadline.remaining(); remaining < perRegex {
		perRegex = remaining
	}
	if perRegex == 0 {
		return true // budget exhausted after acquiring slot
	}

	done := make(chan bool, 1)
	go func() {
		done <- re.MatchString(s)
	}()
	select {
	case matched := <-done:
		return matched
	case <-regexTimeoutAfter(perRegex):
		return false
	}
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

// --- Config Conversion ---

// convertConfigRules converts config.CustomRule slice to []Rule,
// properly mapping conditions from config.RuleCondition to Condition.
func convertConfigRules(cfgRules []config.CustomRule) []Rule {
	rules := make([]Rule, len(cfgRules))
	for i, r := range cfgRules {
		conditions := make([]Condition, len(r.Conditions))
		for j, c := range r.Conditions {
			conditions[j] = Condition{
				Field: c.Field,
				Op:    c.Op,
				Value: c.Value,
			}
		}
		rules[i] = Rule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Enabled,
			Priority:   r.Priority,
			Conditions: conditions,
			Action:     r.Action,
			Score:      r.Score,
		}
	}
	return rules
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
