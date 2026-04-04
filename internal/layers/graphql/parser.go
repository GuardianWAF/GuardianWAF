// Package graphql provides GraphQL query parsing and AST representation.
package graphql

import (
	"fmt"
	"regexp"
	"strings"
)

// AST represents a GraphQL Abstract Syntax Tree.
type AST struct {
	Document *Document
	Raw      string
}

// Document represents a GraphQL document.
type Document struct {
	Operations []Operation
	Fragments  []Fragment
}

// Operation represents a GraphQL operation (query, mutation, subscription).
type Operation struct {
	Type         string      // "query", "mutation", "subscription"
	Name         string      // Operation name (optional)
	SelectionSet []Selection
	Variables    []Variable
	Directives   []Directive
}

// Selection is an interface for field, fragment spread, or inline fragment.
type Selection interface {
	selectionNode()
}

// Field represents a GraphQL field.
type Field struct {
	Name         string
	Alias        string
	Arguments    []Argument
	Directives   []Directive
	SelectionSet []Selection
}

// selectionNode implements Selection interface.
func (Field) selectionNode() {}

// FragmentSpread represents a fragment spread (...FragmentName).
type FragmentSpread struct {
	Name       string
	Directives []Directive
}

// selectionNode implements Selection interface.
func (FragmentSpread) selectionNode() {}

// InlineFragment represents an inline fragment.
type InlineFragment struct {
	TypeCondition string
	Directives    []Directive
	SelectionSet  []Selection
}

// selectionNode implements Selection interface.
func (InlineFragment) selectionNode() {}

// Argument represents a field argument.
type Argument struct {
	Name  string
	Value Value
}

// Value represents a GraphQL value.
type Value interface {
	valueNode()
}

// Variable represents a GraphQL variable.
type Variable struct {
	Name         string
	Type         string
	DefaultValue Value
}

// valueNode implements Value interface.
func (Variable) valueNode() {}

// ScalarValue represents a scalar value (string, int, float, boolean, enum).
type ScalarValue struct {
	Value string
	Kind  string // "string", "int", "float", "boolean", "enum", "null"
}

// valueNode implements Value interface.
func (ScalarValue) valueNode() {}

// ListValue represents a list value.
type ListValue struct {
	Values []Value
}

// valueNode implements Value interface.
func (ListValue) valueNode() {}

// ObjectValue represents an object value.
type ObjectValue struct {
	Fields []ObjectField
}

// valueNode implements Value interface.
func (ObjectValue) valueNode() {}

// ObjectField represents a field in an object value.
type ObjectField struct {
	Name  string
	Value Value
}

// Directive represents a GraphQL directive.
type Directive struct {
	Name      string
	Arguments []Argument
}

// Fragment represents a GraphQL fragment definition.
type Fragment struct {
	Name          string
	TypeCondition string
	Directives    []Directive
	SelectionSet  []Selection
}

// ParseQuery parses a GraphQL query string into an AST.
// This is a simplified parser - production version would use a proper lexer/parser.
func ParseQuery(query string) (*AST, error) {
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}

	// Normalize query
	query = strings.TrimSpace(query)

	// Create AST
	ast := &AST{
		Raw: query,
		Document: &Document{
			Operations: []Operation{},
			Fragments:  []Fragment{},
		},
	}

	// Detect operation type
	opType := "query"
	if strings.HasPrefix(query, "mutation") {
		opType = "mutation"
	} else if strings.HasPrefix(query, "subscription") {
		opType = "subscription"
	}

	// Create operation
	op := Operation{
		Type:         opType,
		SelectionSet: []Selection{},
	}

	// Extract selection set
	selections, err := parseSelectionSet(query)
	if err != nil {
		return nil, err
	}
	op.SelectionSet = selections

	ast.Document.Operations = append(ast.Document.Operations, op)

	return ast, nil
}

// parseSelectionSet parses a GraphQL selection set.
func parseSelectionSet(query string) ([]Selection, error) {
	selections := []Selection{}

	// Find the selection set (content between { and })
	start := strings.Index(query, "{")
	if start == -1 {
		// No selection set - might be a fragment or simple query
		return selections, nil
	}

	// Find matching closing brace
	end := findMatchingBrace(query, start)
	if end == -1 {
		return nil, fmt.Errorf("unmatched opening brace")
	}

	content := query[start+1 : end]
	fields := splitFields(content)

	for _, fieldStr := range fields {
		fieldStr = strings.TrimSpace(fieldStr)
		if fieldStr == "" {
			continue
		}

		// Check for fragment spread
		if strings.HasPrefix(fieldStr, "...") {
			spread := FragmentSpread{
				Name: strings.TrimPrefix(fieldStr, "..."),
			}
			selections = append(selections, spread)
			continue
		}

		// Parse field
		field, err := parseField(fieldStr)
		if err != nil {
			continue // Skip malformed fields
		}
		selections = append(selections, *field)
	}

	return selections, nil
}

// parseField parses a single field.
func parseField(fieldStr string) (*Field, error) {
	field := &Field{
		Arguments:    []Argument{},
		Directives:   []Directive{},
		SelectionSet: []Selection{},
	}

	// Check for alias (alias: name)
	if idx := strings.Index(fieldStr, ":"); idx > 0 {
		field.Alias = strings.TrimSpace(fieldStr[:idx])
		fieldStr = strings.TrimSpace(fieldStr[idx+1:])
	}

	// Extract field name (before ( or { or @)
	nameEnd := len(fieldStr)
	for i, c := range fieldStr {
		if c == '(' || c == '{' || c == '@' || c == ' ' {
			nameEnd = i
			break
		}
	}
	field.Name = strings.TrimSpace(fieldStr[:nameEnd])
	fieldStr = strings.TrimSpace(fieldStr[nameEnd:])

	// Parse arguments if present
	if strings.HasPrefix(fieldStr, "(") {
		end := findMatchingParen(fieldStr, 0)
		if end > 0 {
			argsStr := fieldStr[1:end]
			field.Arguments = parseArguments(argsStr)
			fieldStr = strings.TrimSpace(fieldStr[end+1:])
		}
	}

	// Parse directives if present
	for strings.HasPrefix(fieldStr, "@") {
		directive, rest := parseDirective(fieldStr)
		if directive != nil {
			field.Directives = append(field.Directives, *directive)
		}
		fieldStr = strings.TrimSpace(rest)
	}

	// Parse sub-selection if present
	if strings.HasPrefix(fieldStr, "{") {
		subQuery := field.Name + fieldStr // Reconstruct for parsing
		selections, err := parseSelectionSet(subQuery)
		if err == nil {
			field.SelectionSet = selections
		}
	}

	return field, nil
}

// parseArguments parses field arguments.
func parseArguments(argsStr string) []Argument {
	arguments := []Argument{}

	// Split by comma, but be careful of nested objects
	pairs := splitArgs(argsStr)

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split by colon
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}

		arg := Argument{
			Name:  strings.TrimSpace(parts[0]),
			Value: parseValue(strings.TrimSpace(parts[1])),
		}
		arguments = append(arguments, arg)
	}

	return arguments
}

// parseValue parses a GraphQL value.
func parseValue(valStr string) Value {
	valStr = strings.TrimSpace(valStr)

	// Variable
	if strings.HasPrefix(valStr, "$") {
		return Variable{Name: strings.TrimPrefix(valStr, "$")}
	}

	// String
	if strings.HasPrefix(valStr, "\"") && strings.HasSuffix(valStr, "\"") {
		return ScalarValue{
			Value: strings.Trim(valStr, "\""),
			Kind:  "string",
		}
	}

	// Boolean
	if valStr == "true" || valStr == "false" {
		return ScalarValue{
			Value: valStr,
			Kind:  "boolean",
		}
	}

	// Null
	if valStr == "null" {
		return ScalarValue{
			Value: valStr,
			Kind:  "null",
		}
	}

	// Number (int or float)
	if isNumber(valStr) {
		kind := "int"
		if strings.Contains(valStr, ".") {
			kind = "float"
		}
		return ScalarValue{
			Value: valStr,
			Kind:  kind,
		}
	}

	// List
	if strings.HasPrefix(valStr, "[") {
		return parseList(valStr)
	}

	// Object
	if strings.HasPrefix(valStr, "{") {
		return parseObject(valStr)
	}

	// Enum (default)
	return ScalarValue{
		Value: valStr,
		Kind:  "enum",
	}
}

// parseList parses a list value.
func parseList(valStr string) Value {
	if !strings.HasPrefix(valStr, "[") || !strings.HasSuffix(valStr, "]") {
		return nil
	}

	content := valStr[1 : len(valStr)-1]
	items := splitArgs(content)

	values := []Value{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, parseValue(item))
		}
	}

	return ListValue{Values: values}
}

// parseObject parses an object value.
func parseObject(valStr string) Value {
	if !strings.HasPrefix(valStr, "{") || !strings.HasSuffix(valStr, "}") {
		return nil
	}

	content := valStr[1 : len(valStr)-1]
	fields := []ObjectField{}

	pairs := splitArgs(content)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			fields = append(fields, ObjectField{
				Name:  strings.TrimSpace(parts[0]),
				Value: parseValue(strings.TrimSpace(parts[1])),
			})
		}
	}

	return ObjectValue{Fields: fields}
}

// parseDirective parses a directive.
func parseDirective(str string) (*Directive, string) {
	if !strings.HasPrefix(str, "@") {
		return nil, str
	}

	// Find directive name
	end := 1
	for i := 1; i < len(str); i++ {
		c := str[i]
		if c == '(' || c == ' ' || c == '{' || c == '@' {
			end = i
			break
		}
		end = i + 1
	}

	directive := &Directive{
		Name:      str[1:end],
		Arguments: []Argument{},
	}

	rest := strings.TrimSpace(str[end:])

	// Parse arguments if present
	if strings.HasPrefix(rest, "(") {
		closeIdx := findMatchingParen(rest, 0)
		if closeIdx > 0 {
			argsStr := rest[1:closeIdx]
			directive.Arguments = parseArguments(argsStr)
			rest = strings.TrimSpace(rest[closeIdx+1:])
		}
	}

	return directive, rest
}

// Helper functions

// findMatchingBrace finds the matching closing brace.
func findMatchingBrace(str string, start int) int {
	depth := 0
	for i := start; i < len(str); i++ {
		switch str[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// findMatchingParen finds the matching closing parenthesis.
func findMatchingParen(str string, start int) int {
	depth := 0
	for i := start; i < len(str); i++ {
		switch str[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitFields splits fields by comma, respecting braces.
func splitFields(content string) []string {
	fields := []string{}
	start := 0
	depth := 0

	for i, c := range content {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(content[start:i]))
				start = i + 1
			}
		}
	}

	// Add last field
	if start < len(content) {
		fields = append(fields, strings.TrimSpace(content[start:]))
	}

	return fields
}

// splitArgs splits arguments by comma, respecting nested structures.
func splitArgs(content string) []string {
	args := []string{}
	start := 0
	depth := 0

	for i, c := range content {
		switch c {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(content[start:i]))
				start = i + 1
			}
		}
	}

	// Add last arg
	if start < len(content) {
		args = append(args, strings.TrimSpace(content[start:]))
	}

	return args
}

// isNumber checks if a string is a number.
func isNumber(str string) bool {
	match, _ := regexp.MatchString(`^-?\d+(\.\d+)?$`, str)
	return match
}
