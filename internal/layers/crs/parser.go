package crs

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser parses SecRule directives from CRS rule files.
type Parser struct {
	rules   []*Rule
	lineNum int
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

		// Dispatch on the first whitespace-delimited token. Only an actual
		// "SecRule"/"SecAction" directive is parsed; directives that merely
		// share the prefix ("SecRuleEngine", "SecRuleUpdateTargetById",
		// "SecRuleUpdateActionById", "SecRuleRemoveById/Tag",
		// "SecRuleScript", ...) are skipped like the other unsupported
		// directives. Prefix matching here made any such line fail
		// parseSecRule with "invalid SecRule format", aborting ParseFile —
		// and via the LoadRules walk, discarding the whole ruleset — instead
		// of just the one unsupported directive.
		directive := line
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			directive = line[:idx]
		}

		switch directive {
		case "SecRule":
			rule, err := p.parseSecRule(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", p.lineNum, err)
			}
			if rule != nil {
				// If we have a pending chain rule, this rule is part of the chain
				if pendingChainRule != nil {
					pendingChainRule.Chain = rule
					pendingChainRule = nil
					// Multi-level chain: the linked rule itself continues the
					// chain, so it becomes the new tail awaiting the next
					// SecRule line. Ignoring its "chain" action leaked the
					// tail of depth-3+ chains as a standalone top-level rule
					// (evaluated both outside the chain's AND-condition and
					// with the chain firing without the tail condition).
					// A single-line chained rule (6-part form) already links
					// its complete inline chain into rule.Chain: pend only when
					// the chain truly continues, else the next unrelated
					// SecRule line overwrites the inline condition and is
					// demoted out of the top-level ruleset.
					if rule.Actions.Chain && (rule.Chain == nil || rule.Chain.Actions.Chain) {
						pendingChainRule = rule
					}
				} else {
					p.rules = append(p.rules, rule)
					// Check if this rule has chain flag (same guard as above:
					// an already-linked single-line chain is complete).
					if rule.Actions.Chain && (rule.Chain == nil || rule.Chain.Actions.Chain) {
						pendingChainRule = rule
					}
				}
			}
		case "SecAction":
			rule, err := p.parseSecAction(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", p.lineNum, err)
			}
			if rule != nil {
				// SecAction participates in rule chains per SecLang ("The
				// following directives can be used in rule chains: SecAction,
				// SecRule, SecRuleScript" — Coraza SecLang reference).
				// Previously every SecAction was appended standalone: a
				// chained SecAction starter's actions (e.g. deny) fired
				// unconditionally and its continuation was demoted to a
				// standalone rule, losing the chain's AND-gate.
				if pendingChainRule != nil {
					pendingChainRule.Chain = rule
					pendingChainRule = nil
				} else {
					p.rules = append(p.rules, rule)
				}
				// SecAction has no inline 6-part form, so Actions.Chain
				// alone signals that the chain continues on the next
				// directive line.
				if rule.Actions.Chain {
					pendingChainRule = rule
				}
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
	// Remove surrounding quotes. The length guard is required: a 1-byte
	// string consisting of just a quote satisfies both HasPrefix and
	// HasSuffix, and stripping it would slice [1:0] and panic (found by
	// FuzzCrsParse — a SecRule line whose actions section is a lone
	// unterminated quote crashed rule loading instead of erroring).
	if len(actionsStr) >= 2 && strings.HasPrefix(actionsStr, "\"") && strings.HasSuffix(actionsStr, "\"") {
		actionsStr = actionsStr[1 : len(actionsStr)-1]
	}
	actions, err := p.parseActions(actionsStr)
	if err != nil {
		return nil, fmt.Errorf("parsing actions: %w", err)
	}

	rule := &Rule{
		Variables:     variables,
		Operator:      operator,
		Actions:       actions,
		ParanoiaLevel: 1, // Default
		Phase:         2, // SecLang default: a rule without a phase action runs in phase 2
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
	rule.Tags = actions.Tag

	// Parse chain if present
	if actions.Chain && len(parts) >= 6 {
		chainVars, err := p.parseVariables(parts[3])
		if err != nil {
			return nil, fmt.Errorf("parsing chain variables: %w", err)
		}
		chainOp, err := p.parseOperator(parts[4])
		if err != nil {
			return nil, fmt.Errorf("parsing chain operator: %w", err)
		}

		// parseActions does not strip the surrounding quotes itself (the
		// starter's actionsStr is unquoted by the caller), so strip them here
		// — otherwise the LAST action keeps a trailing quote and its name is
		// corrupted (t:lowercase" is an unknown transform).
		chainActionsStr := parts[5]
		if len(chainActionsStr) >= 2 && strings.HasPrefix(chainActionsStr, "\"") && strings.HasSuffix(chainActionsStr, "\"") {
			chainActionsStr = chainActionsStr[1 : len(chainActionsStr)-1]
		}
		chainActions, err := p.parseActions(chainActionsStr)
		if err != nil {
			return nil, fmt.Errorf("parsing chain actions: %w", err)
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

	// Remove quotes — with the same length guard as parseSecRule: a lone
	// quote character satisfies both HasPrefix and HasSuffix and would
	// slice [1:0].
	if len(content) >= 2 && strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1 : len(content)-1]
	}

	actions, err := p.parseActions(content)
	if err != nil {
		return nil, fmt.Errorf("parsing actions: %w", err)
	}

	rule := &Rule{
		Variables:     []RuleVariable{}, // Empty variables = unconditional
		Actions:       actions,
		Phase:         2,    // SecLang default: a rule without a phase action runs in phase 2
		Unconditional: true, // SecLang: SecAction unconditionally processes its action list
	}

	// An explicit phase action overrides the SecLang default.
	if actions.Phase > 0 {
		rule.Phase = actions.Phase
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

	// splitQuoted keeps each quoted section's surrounding quotes, so a quoted
	// variables section arrives as "\"ARGS:attack\"". Unquote it BEFORE the
	// collection/key split — otherwise the collection carries a leading quote
	// and the key a trailing one, matching no known collection, and the rule
	// silently resolves nothing (the same family as the operator unquote in
	// parseOperator).
	if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1 : len(s)-1]
		s = strings.TrimSpace(s)
	}

	// Split by | but respect escaped characters
	parts := splitEscaped(s, '|')

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var rv RuleVariable

		// Check for count operator (&X — may combine with negation, &!X)
		if strings.HasPrefix(part, "&") {
			rv.Count = true
			part = strings.TrimPrefix(part, "&")
		}

		// Check for exclusion (!X)
		if strings.HasPrefix(part, "!") {
			rv.Exclude = true
			part = strings.TrimPrefix(part, "!")
		}

		// Check for collection key (:)
		if idx := strings.Index(part, ":"); idx > 0 {
			rv.Collection = part[:idx]
			rv.Key = part[idx+1:]

			// Check if key is regex (/pattern/) — length-guarded: a lone
			// slash key (from a spec like ARGS:/) is its own prefix and
			// suffix and would slice [1:0] and panic rule loading (found
			// by FuzzCrsLayerProcess).
			if len(rv.Key) >= 2 && strings.HasPrefix(rv.Key, "/") && strings.HasSuffix(rv.Key, "/") {
				rv.KeyRegex = true
				rv.Key = rv.Key[1 : len(rv.Key)-1]
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

	// splitQuoted keeps each quoted section's surrounding quotes, so a quoted
	// operator section arrives as "\"@streq TRACE\"". Unquote it BEFORE the
	// negation/@ detection — otherwise the @ branch never fires and every
	// file-loaded rule degrades to the default @rx operator with the raw
	// operator text as its argument (the whole layer goes inert).
	if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1 : len(s)-1]
		s = strings.TrimSpace(s)
	}

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
		operatorName := parts[0]
		s = strings.TrimPrefix(s, operatorName)
		s = strings.TrimSpace(s)

		// Handle operator types — matched case-insensitively so case-variant
		// spellings (@STREQ, @ValidateByteRange) keep working; op.Type is
		// normalized to the canonical CamelCase form the evaluator switches on.
		switch strings.ToLower(operatorName) {
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
		case "@beginswith":
			op.Type = "@beginsWith"
		case "@endswith":
			op.Type = "@endsWith"
		case "@pm":
			op.Type = "@pm"
		case "@pmf":
			op.Type = "@pmf"
		case "@within":
			op.Type = "@within"
		case "@streq":
			op.Type = "@streq"
		case "@ipmatch":
			op.Type = "@ipMatch"
		case "@ipmatchf":
			op.Type = "@ipMatchF"
		case "@validatebyterange":
			op.Type = "@validateByteRange"
		case "@validateurlencoding":
			op.Type = "@validateUrlEncoding"
		case "@validateutf8encoding":
			op.Type = "@validateUtf8Encoding"
		default:
			return RuleOperator{}, fmt.Errorf("unknown operator %q: SecLang fails the rule load on an unrecognized operator", operatorName)
		}
	}

	// Remove quotes from argument
	if len(s) >= 2 && strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1 : len(s)-1]
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
			// Remove quotes — length-guarded: a single quote character is
			// its own prefix and suffix and would slice [1:0].
			if len(value) >= 2 && strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
				value = value[1 : len(value)-1]
			}
			if len(value) >= 2 && strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
				value = value[1 : len(value)-1]
			}

			switch key {
			case "id":
				actions.ID = value
			case "phase":
				n, err := strconv.Atoi(value)
				if err != nil {
					return actions, fmt.Errorf("invalid phase %q: %w", value, err)
				}
				if n < 1 || n > 5 {
					return actions, fmt.Errorf("invalid phase %d: SecLang defines phases 1-5 only, failing the rule load rather than registering a rule that can never run", n)
				}
				actions.Phase = n
			case "status":
				n, err := strconv.Atoi(value)
				if err != nil {
					return actions, fmt.Errorf("invalid status %q: %w", value, err)
				}
				actions.Status = n
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
				n, err := strconv.Atoi(value)
				if err != nil {
					return actions, fmt.Errorf("invalid skip %q: %w", value, err)
				}
				actions.Skip = n
			case "skipAfter":
				actions.SkipAfter = value
			case "setvar":
				varAction := p.parseVarAction(value)
				actions.SetVar = append(actions.SetVar, varAction)
			case "t":
				if !validateTransformation(value) {
					return actions, fmt.Errorf("unsupported transformation %q: SecLang fails the rule load rather than silently skipping its transforms", value)
				}
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
			case "log", "nolog", "auditlog":
				// Logging flags, not the primary action (SecLang: log/nolog
				// toggle per-rule audit logging; all three are
				// non-disruptive). Writing them into RuleActions.Action with
				// last-token-wins made the canonical spelling "deny,log"
				// parse as Action="log", and shouldBlock — which blocks only
				// on block|deny|drop — silently lost the explicit deny,
				// degrading a blocking rule to log-only.
				// Nothing consumes a logging-flag value on Action, so the
				// primary action is left untouched.
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

	// Parse operation. Canonical ModSecurity forms first ("+=N"/"-=N"), then
	// the legacy "=+N"/"=-N" spellings, then plain assignment.
	if idx := strings.Index(s, "+="); idx > 0 {
		va.Variable = s[:idx]
		va.Operation = "+="
		va.Value = s[idx+2:]
	} else if idx := strings.Index(s, "-="); idx > 0 {
		va.Variable = s[:idx]
		va.Operation = "-="
		va.Value = s[idx+2:]
	} else if idx := strings.Index(s, "="); idx > 0 {
		va.Variable = s[:idx]
		rest := s[idx+1:]

		// Legacy "=+N" / "=-N" spellings
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
// A backslash-escaped quote (or backslash) inside a quoted section is kept
// verbatim and does NOT close the section — parseOperator unescapes \" after
// the split, so the escape must survive it intact. Without this, a rule like
// SecRule ARGS "@rx val\"ue more" closed the section at the escaped quote and
// the following unquoted space split the rule mid-token: the operator
// argument was truncated and the real actions section shifted into the
// unused chain position (the rule loaded without error but was inert).
func (p *Parser) splitQuoted(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case inQuotes && r == '\\' && i+1 < len(runes) && (runes[i+1] == quoteChar || runes[i+1] == '\\'):
			// Escaped quote/backslash: emit the pair, skip the state toggle.
			current.WriteRune(r)
			current.WriteRune(runes[i+1])
			i++
		case r == '"' || r == '\'':
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
		case r == ' ' || r == '\t':
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
// Only an escaped separator is unescaped ("\|" -> "|"); every other
// backslash sequence passes through verbatim, so regex key selectors like
// /^id_\d+$/ survive parsing with their metacharacters intact.
func splitEscaped(s string, sep byte) []string {
	var parts []string
	var current strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]

		if c == '\\' && i+1 < len(s) && s[i+1] == sep {
			// Escaped separator: emit the separator, skip the backslash.
			current.WriteByte(sep)
			i++
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
// Values are quoted either with single quotes (msg:'a, b') or, per SecLang's
// outer-double-quote grammar, with escaped double quotes (msg:\"a, b\"): the
// \" pairs toggle an escaped-double-quote span at top level and commas
// inside it do not split. Backslash escape pairs are consumed verbatim
// everywhere — inside single quotes a \" pair stays inert (the value keeps
// it literally, pinned by splitquote_escape_regression_test), and an escaped
// comma or backslash is never a separator. Bare double quotes (invalid
// SecLang — a literal " must be escaped as \") stay plain characters, so
// TestSplitActions' documented 5-part split for a,b,"c,d",e is preserved.
// Previously only single-quote state was tracked, so the comma inside
// msg:\"a, b\" split the action list mid-value: the value truncated at the
// comma and the tail became a stray, silently-dropped token
// (round 2026-09-24-r2-crs-splitactions-dq-comma).
func splitActions(s string) []string {
	var parts []string
	var current strings.Builder
	inSingle := false // '...' value spelling
	inDouble := false // \"...\" escaped-double-quote value spelling

	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\\' && i+1 < len(runes):
			// Backslash escape pair: emit verbatim. A top-level \" pair
			// toggles the escaped-double-quote span; inside single quotes it
			// stays inert, and a pair is never an action separator.
			if !inSingle && runes[i+1] == '"' {
				inDouble = !inDouble
			}
			current.WriteRune(r)
			current.WriteRune(runes[i+1])
			i++
		case r == '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			current.WriteRune(r)
		case r == ',':
			if inSingle || inDouble {
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
