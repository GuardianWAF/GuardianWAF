// Package config provides a zero-dependency YAML subset parser for GuardianWAF configuration.
// It handles maps, sequences, scalars (string, int, float, bool, null), block scalars (| and >),
// flow collections ([...] and {...}), comments, and nested structures up to 10 levels deep.
// It does NOT support anchors (&), aliases (*), tags (!!), or multi-document (---/...).
package config

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NodeKind represents the type of a YAML node.
type NodeKind int

const (
	// ScalarNode represents a scalar value (string, int, float, bool, null).
	ScalarNode NodeKind = iota
	// MapNode represents a YAML mapping (key: value pairs).
	MapNode
	// SequenceNode represents a YAML sequence (list of items).
	SequenceNode
)

// String returns the string representation of the NodeKind.
func (k NodeKind) String() string {
	switch k {
	case ScalarNode:
		return "Scalar"
	case MapNode:
		return "Map"
	case SequenceNode:
		return "Sequence"
	default:
		return "Unknown"
	}
}

// Node is the core type of the YAML parser, representing any YAML value.
type Node struct {
	Kind     NodeKind
	Value    string            // raw scalar value (for ScalarNode)
	MapKeys  []string          // ordered keys (for MapNode)
	MapItems map[string]*Node  // key-value pairs (for MapNode)
	Items    []*Node           // items (for SequenceNode)
	IsNull   bool              // true when the value is null/~
	Line     int               // source line number (1-based)
}

// String returns the scalar value as a string.
// For null nodes, returns "". For non-scalar nodes, returns "".
func (n *Node) String() string {
	if n == nil || n.IsNull {
		return ""
	}
	if n.Kind != ScalarNode {
		return ""
	}
	return n.Value
}

// Int parses and returns the scalar value as an int.
func (n *Node) Int() (int, error) {
	if n == nil || n.IsNull {
		return 0, fmt.Errorf("cannot convert null to int")
	}
	if n.Kind != ScalarNode {
		return 0, fmt.Errorf("cannot convert %s node to int", n.Kind)
	}
	return strconv.Atoi(n.Value)
}

// Float64 parses and returns the scalar value as a float64.
func (n *Node) Float64() (float64, error) {
	if n == nil || n.IsNull {
		return 0, fmt.Errorf("cannot convert null to float64")
	}
	if n.Kind != ScalarNode {
		return 0, fmt.Errorf("cannot convert %s node to float64", n.Kind)
	}
	return strconv.ParseFloat(n.Value, 64)
}

// Bool parses and returns the scalar value as a bool.
// Recognizes: true/false, yes/no, on/off (case-insensitive).
func (n *Node) Bool() (bool, error) {
	if n == nil || n.IsNull {
		return false, fmt.Errorf("cannot convert null to bool")
	}
	if n.Kind != ScalarNode {
		return false, fmt.Errorf("cannot convert %s node to bool", n.Kind)
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("cannot convert %q to bool", n.Value)
	}
}

// Slice returns the child items of a sequence node.
// Returns nil for non-sequence nodes.
func (n *Node) Slice() []*Node {
	if n == nil || n.Kind != SequenceNode {
		return nil
	}
	return n.Items
}

// Map returns the key-value pairs of a map node.
// Returns nil for non-map nodes.
func (n *Node) Map() map[string]*Node {
	if n == nil || n.Kind != MapNode {
		return nil
	}
	return n.MapItems
}

// Get returns the child node for the given key in a map node.
// Returns nil if the node is not a map or the key doesn't exist.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != MapNode || n.MapItems == nil {
		return nil
	}
	return n.MapItems[key]
}

// GetPath returns the node at the given path of keys for nested access.
// For example, GetPath("server", "tls", "enabled") navigates through nested maps.
func (n *Node) GetPath(keys ...string) *Node {
	current := n
	for _, key := range keys {
		current = current.Get(key)
		if current == nil {
			return nil
		}
	}
	return current
}

// ParseError represents a YAML parsing error with position information.
type ParseError struct {
	Line    int
	Column  int
	Message string
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Column > 0 {
		return fmt.Sprintf("yaml: line %d, column %d: %s", e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("yaml: line %d: %s", e.Line, e.Message)
}

// parser holds the state for YAML parsing.
type parser struct {
	lines   []string
	pos     int // current line index (0-based)
	maxNest int
}

// Parse parses YAML data and returns the root Node.
func Parse(data []byte) (*Node, error) {
	if !utf8.Valid(data) {
		return nil, &ParseError{Line: 1, Message: "input is not valid UTF-8"}
	}

	// Normalize line endings
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	normalized = bytes.ReplaceAll(normalized, []byte("\r"), []byte("\n"))

	text := string(normalized)
	lines := strings.Split(text, "\n")

	p := &parser{
		lines:   lines,
		pos:     0,
		maxNest: 10,
	}

	node, err := p.parseDocument()
	if err != nil {
		return nil, err
	}

	return node, nil
}

// parseDocument parses the entire document, skipping blanks/comments at top level.
func (p *parser) parseDocument() (*Node, error) {
	p.skipBlankAndComments()
	if p.pos >= len(p.lines) {
		// Empty document
		return &Node{Kind: MapNode, MapItems: make(map[string]*Node), Line: 1}, nil
	}

	// Peek at first non-empty line
	line := p.lines[p.pos]
	trimmed := strings.TrimSpace(line)

	// Check if the document starts with a sequence indicator
	if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
		return p.parseBlockSequence(0, 0)
	}

	// Check for flow collection at top level
	if strings.HasPrefix(trimmed, "[") {
		return p.parseFlowSequenceTopLevel()
	}
	if strings.HasPrefix(trimmed, "{") {
		return p.parseFlowMapTopLevel()
	}

	// Default: parse as a mapping
	return p.parseMapping(0, 0)
}

// parseMapping parses a YAML mapping at the given indentation level.
func (p *parser) parseMapping(indent, depth int) (*Node, error) {
	if depth > p.maxNest {
		return nil, &ParseError{Line: p.lineNum(), Message: "maximum nesting depth exceeded"}
	}

	node := &Node{
		Kind:     MapNode,
		MapKeys:  make([]string, 0),
		MapItems: make(map[string]*Node),
		Line:     p.lineNum(),
	}

	for p.pos < len(p.lines) {
		p.skipBlankAndComments()
		if p.pos >= len(p.lines) {
			break
		}

		line := p.lines[p.pos]
		lineIndent := countIndent(line)
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			p.pos++
			continue
		}

		// If indentation decreased, this mapping is done
		if lineIndent < indent {
			break
		}

		// If we're at the same indent but this isn't a key-value pair, stop
		if lineIndent == indent {
			// Check if this is a sequence item at our level
			if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
				break
			}

			key, val, isKV := parseKeyValue(trimmed)
			if !isKV {
				break
			}

			lineNum := p.lineNum()
			p.pos++

			// Check for duplicate keys
			if _, exists := node.MapItems[key]; exists {
				// Overwrite: last value wins (YAML spec)
			} else {
				node.MapKeys = append(node.MapKeys, key)
			}

			child, err := p.resolveValue(val, indent, lineNum, depth)
			if err != nil {
				return nil, err
			}
			node.MapItems[key] = child

		} else if lineIndent > indent {
			// Indented beyond our level — stop, parent handles this
			break
		}
	}

	return node, nil
}

// resolveValue determines the Node for a given value string, which may be
// a scalar, a block scalar, or a nested structure on subsequent lines.
func (p *parser) resolveValue(val string, parentIndent, lineNum, depth int) (*Node, error) {
	// Block scalar indicators
	if val == "|" || val == "|-" || val == "|+" {
		return p.parseLiteralBlock(parentIndent, lineNum, val)
	}
	if val == ">" || val == ">-" || val == ">+" {
		return p.parseFoldedBlock(parentIndent, lineNum, val)
	}

	// Flow sequence
	if strings.HasPrefix(val, "[") {
		result, err := parseFlowSequence(val, lineNum)
		if err != nil {
			return nil, err
		}
		return result, nil
	}

	// Flow map
	if strings.HasPrefix(val, "{") {
		result, err := parseFlowMap(val, lineNum)
		if err != nil {
			return nil, err
		}
		return result, nil
	}

	// Non-empty scalar value on the same line
	if val != "" {
		return makeScalar(val, lineNum), nil
	}

	// Value is empty — check if there's a nested structure on the next lines
	p.skipBlankAndComments()
	if p.pos >= len(p.lines) {
		return makeScalar("", lineNum), nil
	}

	nextLine := p.lines[p.pos]
	nextTrimmed := strings.TrimSpace(nextLine)
	nextIndent := countIndent(nextLine)

	if nextTrimmed == "" || nextIndent <= parentIndent {
		// No nested structure, it's an empty value
		return makeScalar("", lineNum), nil
	}

	// Nested block sequence
	if strings.HasPrefix(nextTrimmed, "- ") || nextTrimmed == "-" {
		return p.parseBlockSequence(nextIndent, depth+1)
	}

	// Nested mapping
	return p.parseMapping(nextIndent, depth+1)
}

// parseBlockSequence parses a YAML block sequence at the given indentation.
func (p *parser) parseBlockSequence(indent, depth int) (*Node, error) {
	if depth > p.maxNest {
		return nil, &ParseError{Line: p.lineNum(), Message: "maximum nesting depth exceeded"}
	}

	node := &Node{
		Kind:  SequenceNode,
		Items: make([]*Node, 0),
		Line:  p.lineNum(),
	}

	for p.pos < len(p.lines) {
		p.skipBlankAndComments()
		if p.pos >= len(p.lines) {
			break
		}

		line := p.lines[p.pos]
		lineIndent := countIndent(line)
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			p.pos++
			continue
		}

		if lineIndent < indent {
			break
		}

		if lineIndent != indent {
			break
		}

		if !strings.HasPrefix(trimmed, "- ") && trimmed != "-" {
			break
		}

		lineNum := p.lineNum()

		// Extract the value after "- "
		var itemVal string
		if trimmed == "-" {
			itemVal = ""
		} else {
			itemVal = trimmed[2:]
		}

		p.pos++

		// The item content indent is at indent + 2
		contentIndent := indent + 2

		// Check if item value is a key-value pair (nested map under sequence)
		if itemVal != "" {
			key, val, isKV := parseKeyValue(itemVal)
			if isKV {
				// This is a mapping entry as a sequence item.
				// Build the map node from this and subsequent lines at contentIndent
				mapNode := &Node{
					Kind:     MapNode,
					MapKeys:  []string{key},
					MapItems: map[string]*Node{},
					Line:     lineNum,
				}
				child, err := p.resolveValue(val, indent, lineNum, depth+1)
				if err != nil {
					return nil, err
				}
				mapNode.MapItems[key] = child

				// Continue reading additional keys at contentIndent
				for p.pos < len(p.lines) {
					p.skipBlankAndComments()
					if p.pos >= len(p.lines) {
						break
					}
					nextLine := p.lines[p.pos]
					nextIndent := countIndent(nextLine)
					nextTrimmed := strings.TrimSpace(nextLine)
					if nextTrimmed == "" {
						p.pos++
						continue
					}
					if nextIndent < contentIndent {
						break
					}
					if nextIndent != contentIndent {
						break
					}
					nk, nv, nIsKV := parseKeyValue(nextTrimmed)
					if !nIsKV {
						break
					}
					nLineNum := p.lineNum()
					p.pos++
					nChild, err := p.resolveValue(nv, contentIndent, nLineNum, depth+1)
					if err != nil {
						return nil, err
					}
					if _, exists := mapNode.MapItems[nk]; !exists {
						mapNode.MapKeys = append(mapNode.MapKeys, nk)
					}
					mapNode.MapItems[nk] = nChild
				}

				node.Items = append(node.Items, mapNode)
				continue
			}

			// Check for flow collections
			if strings.HasPrefix(itemVal, "[") {
				child, err := parseFlowSequence(itemVal, lineNum)
				if err != nil {
					return nil, err
				}
				node.Items = append(node.Items, child)
				continue
			}
			if strings.HasPrefix(itemVal, "{") {
				child, err := parseFlowMap(itemVal, lineNum)
				if err != nil {
					return nil, err
				}
				node.Items = append(node.Items, child)
				continue
			}

			// Block scalar as sequence item
			if itemVal == "|" || itemVal == "|-" || itemVal == "|+" {
				child, err := p.parseLiteralBlock(indent, lineNum, itemVal)
				if err != nil {
					return nil, err
				}
				node.Items = append(node.Items, child)
				continue
			}
			if itemVal == ">" || itemVal == ">-" || itemVal == ">+" {
				child, err := p.parseFoldedBlock(indent, lineNum, itemVal)
				if err != nil {
					return nil, err
				}
				node.Items = append(node.Items, child)
				continue
			}

			// Plain scalar value
			node.Items = append(node.Items, makeScalar(itemVal, lineNum))
			continue
		}

		// Empty "- " — check for nested content
		p.skipBlankAndComments()
		if p.pos >= len(p.lines) {
			node.Items = append(node.Items, makeScalar("", lineNum))
			continue
		}

		nextLine := p.lines[p.pos]
		nextIndent := countIndent(nextLine)
		nextTrimmed := strings.TrimSpace(nextLine)

		if nextTrimmed == "" || nextIndent <= indent {
			node.Items = append(node.Items, makeScalar("", lineNum))
			continue
		}

		// Nested sequence
		if strings.HasPrefix(nextTrimmed, "- ") || nextTrimmed == "-" {
			child, err := p.parseBlockSequence(nextIndent, depth+1)
			if err != nil {
				return nil, err
			}
			node.Items = append(node.Items, child)
			continue
		}

		// Nested mapping
		child, err := p.parseMapping(nextIndent, depth+1)
		if err != nil {
			return nil, err
		}
		node.Items = append(node.Items, child)
	}

	return node, nil
}

// parseLiteralBlock parses a literal block scalar (|).
func (p *parser) parseLiteralBlock(parentIndent, lineNum int, indicator string) (*Node, error) {
	// Determine chomping mode
	chomp := "clip" // default
	if strings.HasSuffix(indicator, "-") {
		chomp = "strip"
	} else if strings.HasSuffix(indicator, "+") {
		chomp = "keep"
	}

	// Collect block lines — they must be indented more than parentIndent
	var blockLines []string
	var blockIndent int = -1

	for p.pos < len(p.lines) {
		line := p.lines[p.pos]

		// Completely blank lines are part of the block
		if strings.TrimSpace(line) == "" {
			blockLines = append(blockLines, "")
			p.pos++
			continue
		}

		ind := countIndent(line)
		if ind <= parentIndent {
			break
		}

		if blockIndent == -1 {
			blockIndent = ind
		}

		// Lines must be at the block indent level or more
		if ind < blockIndent {
			break
		}

		// Strip the block indent prefix
		if len(line) >= blockIndent {
			blockLines = append(blockLines, line[blockIndent:])
		} else {
			blockLines = append(blockLines, "")
		}
		p.pos++
	}

	if len(blockLines) == 0 {
		return makeScalar("", lineNum), nil
	}

	// Build the content — literal block keeps newlines
	var buf strings.Builder
	for i, l := range blockLines {
		buf.WriteString(l)
		if i < len(blockLines)-1 {
			buf.WriteByte('\n')
		}
	}

	result := buf.String()

	// Apply chomping
	switch chomp {
	case "strip":
		result = strings.TrimRight(result, "\n")
	case "clip":
		result = strings.TrimRight(result, "\n")
		result += "\n"
	case "keep":
		// Keep trailing newlines, just add a final one
		if !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
	}

	return &Node{Kind: ScalarNode, Value: result, Line: lineNum}, nil
}

// parseFoldedBlock parses a folded block scalar (>).
func (p *parser) parseFoldedBlock(parentIndent, lineNum int, indicator string) (*Node, error) {
	// Determine chomping mode
	chomp := "clip"
	if strings.HasSuffix(indicator, "-") {
		chomp = "strip"
	} else if strings.HasSuffix(indicator, "+") {
		chomp = "keep"
	}

	var blockLines []string
	var blockIndent int = -1

	for p.pos < len(p.lines) {
		line := p.lines[p.pos]

		if strings.TrimSpace(line) == "" {
			blockLines = append(blockLines, "")
			p.pos++
			continue
		}

		ind := countIndent(line)
		if ind <= parentIndent {
			break
		}

		if blockIndent == -1 {
			blockIndent = ind
		}

		if ind < blockIndent {
			break
		}

		if len(line) >= blockIndent {
			blockLines = append(blockLines, line[blockIndent:])
		} else {
			blockLines = append(blockLines, "")
		}
		p.pos++
	}

	if len(blockLines) == 0 {
		return makeScalar("", lineNum), nil
	}

	// Remove trailing empty lines for processing
	trailingEmpties := 0
	for i := len(blockLines) - 1; i >= 0; i-- {
		if blockLines[i] == "" {
			trailingEmpties++
		} else {
			break
		}
	}
	contentLines := blockLines[:len(blockLines)-trailingEmpties]

	// Folded block: single newlines become spaces, blank lines become newlines
	var buf strings.Builder
	for i, l := range contentLines {
		if l == "" {
			buf.WriteByte('\n')
		} else {
			if i > 0 && contentLines[i-1] != "" {
				buf.WriteByte(' ')
			}
			buf.WriteString(l)
		}
	}

	result := buf.String()

	switch chomp {
	case "strip":
		result = strings.TrimRight(result, "\n")
	case "clip":
		result = strings.TrimRight(result, "\n")
		result += "\n"
	case "keep":
		if !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
		// Add back trailing empty lines
		for range trailingEmpties {
			result += "\n"
		}
	}

	return &Node{Kind: ScalarNode, Value: result, Line: lineNum}, nil
}

// parseFlowSequenceTopLevel parses a flow sequence at the top level of the document.
func (p *parser) parseFlowSequenceTopLevel() (*Node, error) {
	line := strings.TrimSpace(p.lines[p.pos])
	lineNum := p.lineNum()
	p.pos++
	return parseFlowSequence(line, lineNum)
}

// parseFlowMapTopLevel parses a flow map at the top level of the document.
func (p *parser) parseFlowMapTopLevel() (*Node, error) {
	line := strings.TrimSpace(p.lines[p.pos])
	lineNum := p.lineNum()
	p.pos++
	return parseFlowMap(line, lineNum)
}

// parseFlowSequence parses a flow sequence like [a, b, c].
func parseFlowSequence(s string, lineNum int) (*Node, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, &ParseError{Line: lineNum, Message: "invalid flow sequence"}
	}

	inner := s[1 : len(s)-1]
	items := splitFlowItems(inner)

	node := &Node{
		Kind:  SequenceNode,
		Items: make([]*Node, 0, len(items)),
		Line:  lineNum,
	}

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// Nested flow sequence
		if strings.HasPrefix(item, "[") {
			child, err := parseFlowSequence(item, lineNum)
			if err != nil {
				return nil, err
			}
			node.Items = append(node.Items, child)
			continue
		}
		// Nested flow map
		if strings.HasPrefix(item, "{") {
			child, err := parseFlowMap(item, lineNum)
			if err != nil {
				return nil, err
			}
			node.Items = append(node.Items, child)
			continue
		}
		node.Items = append(node.Items, makeScalar(item, lineNum))
	}

	return node, nil
}

// parseFlowMap parses a flow map like {key: val, key2: val2}.
func parseFlowMap(s string, lineNum int) (*Node, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, &ParseError{Line: lineNum, Message: "invalid flow map"}
	}

	inner := s[1 : len(s)-1]
	items := splitFlowItems(inner)

	node := &Node{
		Kind:     MapNode,
		MapKeys:  make([]string, 0, len(items)),
		MapItems: make(map[string]*Node, len(items)),
		Line:     lineNum,
	}

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, val, ok := parseKeyValue(item)
		if !ok {
			return nil, &ParseError{Line: lineNum, Message: fmt.Sprintf("invalid flow map entry: %q", item)}
		}
		if _, exists := node.MapItems[key]; !exists {
			node.MapKeys = append(node.MapKeys, key)
		}
		node.MapItems[key] = makeScalar(val, lineNum)
	}

	return node, nil
}

// splitFlowItems splits a flow collection's inner content by commas,
// respecting nested brackets and quotes.
func splitFlowItems(s string) []string {
	var items []string
	depth := 0
	var current strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]

		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' && (inSingle || inDouble) {
			current.WriteByte(ch)
			escaped = true
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			current.WriteByte(ch)
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			current.WriteByte(ch)
			continue
		}

		if !inSingle && !inDouble {
			if ch == '[' || ch == '{' {
				depth++
			} else if ch == ']' || ch == '}' {
				depth--
			}

			if ch == ',' && depth == 0 {
				items = append(items, current.String())
				current.Reset()
				continue
			}
		}

		current.WriteByte(ch)
	}

	final := current.String()
	if strings.TrimSpace(final) != "" {
		items = append(items, final)
	}

	return items
}

// parseKeyValue splits a line into key and value parts.
// Returns key, value, and whether it was a valid key: value pair.
func parseKeyValue(line string) (key, value string, ok bool) {
	// Find the colon that separates key from value.
	// The colon must be followed by a space, end of line, or is the last char.
	// Must handle quoted keys.

	i := 0
	inSingle := false
	inDouble := false
	escaped := false

	for i < len(line) {
		ch := line[i]

		if escaped {
			escaped = false
			i++
			continue
		}

		if ch == '\\' {
			escaped = true
			i++
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			i++
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			i++
			continue
		}

		if ch == ':' && !inSingle && !inDouble {
			// Colon must be followed by space, end of string, or nothing
			if i+1 >= len(line) || line[i+1] == ' ' || line[i+1] == '\t' {
				key := strings.TrimSpace(line[:i])
				val := ""
				if i+1 < len(line) {
					val = strings.TrimSpace(line[i+1:])
				}
				// Strip surrounding quotes from key
				key = unquoteKey(key)
				// Strip inline comments from value
				val = stripInlineComment(val)
				return key, val, true
			}
		}

		i++
	}

	return "", "", false
}

// unquoteKey removes surrounding quotes from a key.
func unquoteKey(key string) string {
	if len(key) >= 2 {
		if (key[0] == '"' && key[len(key)-1] == '"') ||
			(key[0] == '\'' && key[len(key)-1] == '\'') {
			return key[1 : len(key)-1]
		}
	}
	return key
}

// stripInlineComment removes an inline comment from a value.
// Comments start with " #" (space + hash) outside of quotes.
func stripInlineComment(val string) string {
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(val); i++ {
		ch := val[i]

		if escaped {
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}

		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}

		if ch == '#' && !inSingle && !inDouble {
			// Must be preceded by a space (or be at the start)
			if i > 0 && val[i-1] == ' ' {
				return strings.TrimSpace(val[:i-1])
			}
			if i == 0 {
				return ""
			}
		}
	}

	return val
}

// makeScalar creates a scalar Node from a raw value string.
// It handles unquoting, type detection, etc.
func makeScalar(val string, lineNum int) *Node {
	val = strings.TrimSpace(val)

	n := &Node{
		Kind: ScalarNode,
		Line: lineNum,
	}

	// Null
	if val == "" || val == "null" || val == "~" || val == "Null" || val == "NULL" {
		n.IsNull = true
		n.Value = ""
		return n
	}

	// Quoted strings
	if len(val) >= 2 {
		if val[0] == '"' && val[len(val)-1] == '"' {
			n.Value = unescapeDoubleQuoted(val[1 : len(val)-1])
			return n
		}
		if val[0] == '\'' && val[len(val)-1] == '\'' {
			n.Value = unescapeSingleQuoted(val[1 : len(val)-1])
			return n
		}
	}

	// Booleans — store the canonical form
	switch strings.ToLower(val) {
	case "true", "yes", "on":
		n.Value = strings.ToLower(val)
		return n
	case "false", "no", "off":
		n.Value = strings.ToLower(val)
		return n
	}

	// Numbers: leave as-is in string form
	n.Value = val
	return n
}

// unescapeDoubleQuoted processes escape sequences in a double-quoted string.
func unescapeDoubleQuoted(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case 'n':
				buf.WriteByte('\n')
			case 't':
				buf.WriteByte('\t')
			case '\\':
				buf.WriteByte('\\')
			case '"':
				buf.WriteByte('"')
			case '\'':
				buf.WriteByte('\'')
			case 'r':
				buf.WriteByte('\r')
			case '0':
				buf.WriteByte(0)
			case 'a':
				buf.WriteByte('\a')
			case 'b':
				buf.WriteByte('\b')
			case 'f':
				buf.WriteByte('\f')
			case 'v':
				buf.WriteByte('\v')
			default:
				buf.WriteByte('\\')
				buf.WriteByte(next)
			}
			i++
		} else {
			buf.WriteByte(s[i])
		}
	}

	return buf.String()
}

// unescapeSingleQuoted processes single-quoted strings.
// In YAML, single-quoted strings only escape '' as '.
func unescapeSingleQuoted(s string) string {
	return strings.ReplaceAll(s, "''", "'")
}

// countIndent returns the number of leading spaces in a line.
func countIndent(line string) int {
	count := 0
	for _, r := range line {
		switch r {
		case ' ':
			count++
		case '\t':
			// Tabs are not recommended in YAML, but count as 1
			count++
		default:
			return count
		}
	}
	return count
}

// skipBlankAndComments advances past blank lines and comment-only lines.
func (p *parser) skipBlankAndComments() {
	for p.pos < len(p.lines) {
		trimmed := strings.TrimSpace(p.lines[p.pos])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			p.pos++
			continue
		}
		break
	}
}

// lineNum returns the current 1-based line number.
func (p *parser) lineNum() int {
	return p.pos + 1
}


