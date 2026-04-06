package crs

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser parses SecRule directives from CRS rule files.
type Parser struct {
	rules    []*Rule
	lineNum  int
}

// NewParser creates a new SecRule parser.
func NewParser() *Parser {
	return &Parser{
		rules: []*Rule{},
	}
}

// ParseFile parses a CRS rule file and returns the extracted rules.
func (p *Parser) ParseFile(content string) ([]*Rule, error) {
	lines := strings.Split(content, "\n")
	var pendingChainRule *Rule

	for i, line := range lines {
		p.lineNum = i + 1
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse SecRule
		if strings.HasPrefix(line, "SecRule") {
			rule, err := p.parseSecRule(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", p.lineNum, err)
			}
			if rule != nil {
				// If we have a pending chain rule, this rule is part of the chain
				if pendingChainRule != nil {
					pendingChainRule.Chain = rule
					pendingChainRule = nil
				} else {
					p.rules = append(p.rules, rule)
					// Check if this rule has chain flag
					if rule.Actions.Chain {
						pendingChainRule = rule
					}
				}
			}
		}

		// Parse SecAction (unconditional action)
		if strings.HasPrefix(line, "SecAction") {
			rule, err := p.parseSecAction(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", p.lineNum, err)
			}
			if rule != nil {
				p.rules = append(p.rules, rule)
			}
		}
	}

	return p.rules, nil
}

// parseSecRule parses a SecRule directive.
// Format: SecRule VARIABLES "OPERATOR" "ACTIONS"
// Or:     SecRule VARIABLES "OPERATOR" "ACTIONS" "CHAINED_VARIABLES" "CHAINED_OPERATOR" "CHAINED_ACTIONS"
func (p *Parser) parseSecRule(line string) (*Rule, error) {
	// Remove SecRule prefix
	content := strings.TrimPrefix(line, "SecRule")
	content = strings.TrimSpace(content)

	// Parse quoted sections
	parts := p.splitQuoted(content)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SecRule format: %s", line)
	}

	// First part: variables
	variables, err := p.parseVariables(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing variables: %w", err)
	}

	// Second part: operator
	operator, err := p.parseOperator(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing operator: %w", err)
	}

	// Third part: actions
	actionsStr := parts[2]
	// Remove surrounding quotes
	if strings.HasPrefix(actionsStr, "\"") && strings.HasSuffix(actionsStr, "\"") {
		actionsStr = actionsStr[1:len(actionsStr)-1]
	}
	actions, err := p.parseActions(actionsStr)
	if err != nil {
		return nil, fmt.Errorf("parsing actions: %w", err)
	}

	rule := &Rule{
		Variables:  variables,
		Operator:   operator,
		Actions:    actions,
		ParanoiaLevel: 1, // Default
	}

	// Extract ID from actions
	if actions.ID != "" {
		rule.ID = actions.ID
	}

	// Extract phase from actions
	if actions.Phase > 0 {
		rule.Phase = actions.Phase
	}

	// Extract severity
	if actions.Severity != "" {
		rule.Severity = actions.Severity
	}

	// Extract message
	if actions.Msg != "" {
		rule.Msg = actions.Msg
	}

	// Extract tags
	if len(actions.Tag) > 0 {
		rule.Tags = actions.Tag
	}

	// Parse chain if present
	if actions.Chain && len(parts) >= 6 {
		chainVars, err := p.parseVariables(parts[3])
		if err != nil {
			return nil, fmt.Errorf("parsing chained variables: %w", err)
		}

		chainOp, err := p.parseOperator(parts[4])
		if err != nil {
			return nil, fmt.Errorf("parsing chained operator: %w", err)
		}

		chainActions, err := p.parseActions(parts[5])
		if err != nil {
			return nil, fmt.Errorf("parsing chained actions: %w", err)
		}

		rule.Chain = &Rule{
			Variables: chainVars,
			Operator:  chainOp,
			Actions:   chainActions,
		}
	}

	return rule, nil
}

// parseSecAction parses a SecAction directive (unconditional action).
// Format: SecAction "ACTIONS"
func (p *Parser) parseSecAction(line string) (*Rule, error) {
	content := strings.TrimPrefix(line, "SecAction")
	content = strings.TrimSpace(content)

	// Remove quotes
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1:len(content)-1]
	}

	actions, err := p.parseActions(content)
	if err != nil {
		return nil, fmt.Errorf("parsing actions: %w", err)
	}

	rule := &Rule{
		Variables: []RuleVariable{}, // Empty variables = unconditional
		Actions:   actions,
		Phase:     actions.Phase,
	}

	if actions.ID != "" {
		rule.ID = actions.ID
	}

	return rule, nil
}

// parseVariables parses SecRule variables.
// Format: "REQUEST_HEADERS|ARGS:foo|!REQUEST_COOKIES:bar"
func (p *Parser) parseVariables(s string) ([]RuleVariable, error) {
	vars := []RuleVariable{}

	// Split by | but respect escaped characters
	parts := splitEscaped(s, '|')

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var rv RuleVariable

		// Check for exclusion (!)
		if strings.HasPrefix(part, "!+") {
			rv.Exclude = true
			part = strings.TrimPrefix(part, "!")
		}

		// Check for count operator (&)
		if strings.HasPrefix(part, "&+") {
			rv.Count = true
			part = strings.TrimPrefix(part, "&")
		}

		// Check for collection key (:)
		if idx := strings.Index(part, ":"); idx > 0 {
			rv.Collection = part[:idx]
			rv.Key = part[idx+1:]

			// Check if key is regex (/pattern/)
			if strings.HasPrefix(rv.Key, "/") && strings.HasSuffix(rv.Key, "/") {
				rv.KeyRegex = true
				rv.Key = rv.Key[1:len(rv.Key)-1]
			}
		} else {
			rv.Name = part
		}

		vars = append(vars, rv)
	}

	return vars, nil
}

// parseOperator parses a SecRule operator.
// Format: "@rx pattern" or "@eq value" or "pattern" (default @rx)
func (p *Parser) parseOperator(s string) (RuleOperator, error) {
	s = strings.TrimSpace(s)

	op := RuleOperator{
		Type: "@rx", // Default operator
	}

	// Check for negation
	if strings.HasPrefix(s, "!") {
		op.Negated = true
		s = strings.TrimPrefix(s, "!")
	}

	// Parse operator prefix
	if strings.HasPrefix(s, "@") {
		// Find operator name
		parts := strings.Fields(s)
		if len(parts) == 0 {
			return op, fmt.Errorf("empty operator")
		}

		operatorName := parts[0]
		s = strings.TrimPrefix(s, operatorName)
		s = strings.TrimSpace(s)

		// Handle operator types
		switch operatorName {
		case "@rx":
			op.Type = "@rx"
		case "@eq":
			op.Type = "@eq"
		case "@ge":
			op.Type = "@ge"
		case "@le":
			op.Type = "@le"
		case "@gt":
			op.Type = "@gt"
		case "@lt":
			op.Type = "@lt"
		case "@contains":
			op.Type = "@contains"
		case "@beginsWith":
			op.Type = "@beginsWith"
		case "@endsWith":
			op.Type = "@endsWith"
		case "@pm":
			op.Type = "@pm"
		case "@pmf":
			op.Type = "@pmf"
		case "@within":
			op.Type = "@within"
		case "@streq":
			op.Type = "@streq"
		case "@ipMatch", "@ipMatchF":
			op.Type = "@ipMatch"
		case "@validateByteRange":
			op.Type = "@validateByteRange"
		case "@validateUrlEncoding":
			op.Type = "@validateUrlEncoding"
		case "@validateUtf8Encoding":
			op.Type = "@validateUtf8Encoding"
		default:
			op.Type = operatorName
		}
	}

	// Remove quotes from argument
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1:len(s)-1]
	}

	// Unescape quotes
	s = strings.ReplaceAll(s, "\\\"", "\"")

	op.Argument = s
	return op, nil
}

// parseActions parses SecRule actions.
// Format: "id:911100,phase:2,deny,status:403,msg:'...'"
func (p *Parser) parseActions(s string) (RuleActions, error) {
	actions := RuleActions{
		Transformations: []string{},
		Tag:             []string{},
		SetVar:          []VarAction{},
	}

	// Split by comma but respect quoted strings
	actionList := splitActions(s)

	for _, action := range actionList {
		action = strings.TrimSpace(action)
		if action == "" {
			continue
		}

		// Parse key:value or standalone action
		if idx := strings.Index(action, ":"); idx > 0 {
			key := strings.TrimSpace(action[:idx])
			value := strings.TrimSpace(action[idx+1:])

			// Remove quotes
			if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
				value = value[1:len(value)-1]
			}
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
				value = value[1:len(value)-1]
			}

			switch key {
			case "id":
				actions.ID = value
			case "phase":
				actions.Phase, _ = strconv.Atoi(value)
			case "status":
				actions.Status, _ = strconv.Atoi(value)
			case "redirect":
				actions.Redirect = value
			case "msg":
				actions.Msg = value
			case "logdata":
				actions.LogData = value
			case "severity":
				actions.Severity = value
			case "tag":
				actions.Tag = append(actions.Tag, value)
			case "skip":
				actions.Skip, _ = strconv.Atoi(value)
			case "skipAfter":
				actions.SkipAfter = value
			case "setvar":
				varAction := p.parseVarAction(value)
				actions.SetVar = append(actions.SetVar, varAction)
			case "t":
				actions.Transformations = append(actions.Transformations, value)
			}
		} else {
			// Standalone actions
			switch action {
			case "deny":
				actions.Action = "deny"
			case "pass":
				actions.Action = "pass"
			case "block":
				actions.Action = "block"
			case "drop":
				actions.Action = "drop"
			case "allow":
				actions.Action = "allow"
			case "proxy":
				actions.Action = "proxy"
			case "log":
				actions.Action = "log"
			case "nolog":
				actions.Action = "nolog"
			case "auditlog":
				// Audit logging flag
			case "chain":
				actions.Chain = true
			case "capture":
				// Capture data
			}
		}
	}

	return actions, nil
}

// parseVarAction parses a setvar action.
// Format: "tx.anomaly_score=+1" or "tx.blocking_score=5"
func (p *Parser) parseVarAction(s string) VarAction {
	va := VarAction{}

	// Parse collection name
	if idx := strings.Index(s, "."); idx > 0 {
		va.Collection = s[:idx]
		s = s[idx+1:]
	}

	// Parse operation
	if idx := strings.Index(s, "="); idx > 0 {
		va.Variable = s[:idx]
		rest := s[idx+1:]

		// Check for += or -=
		if strings.HasPrefix(rest, "+") {
			va.Operation = "+="
			va.Value = rest[1:]
		} else if strings.HasPrefix(rest, "-") {
			va.Operation = "-="
			va.Value = rest[1:]
		} else {
			va.Operation = "="
			va.Value = rest
		}
	}

	return va
}

// splitQuoted splits a string by whitespace but respects quoted sections.
func (p *Parser) splitQuoted(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	for _, r := range s {
		switch r {
		case '"', '\'':
			if !inQuotes {
				inQuotes = true
				quoteChar = r
				current.WriteRune(r)
			} else if r == quoteChar {
				current.WriteRune(r)
				inQuotes = false
				quoteChar = 0
			} else {
				current.WriteRune(r)
			}
		case ' ', '\t':
			if inQuotes {
				current.WriteRune(r)
			} else {
				if current.Len() > 0 {
					parts = append(parts, current.String())
					current.Reset()
				}
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// splitEscaped splits a string by separator respecting escaped characters.
func splitEscaped(s string, sep byte) []string {
	var parts []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]

		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if c == sep {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}

		current.WriteByte(c)
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// splitActions splits actions by comma but respects quoted strings.
func splitActions(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	for _, r := range s {
		switch r {
		case '\'':
			if !inQuotes {
				inQuotes = true
				quoteChar = r
			} else if r == quoteChar {
				inQuotes = false
				quoteChar = 0
			}
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}
