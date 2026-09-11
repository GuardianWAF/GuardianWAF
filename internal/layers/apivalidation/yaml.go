package apivalidation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// YAMLToJSON converts a simple YAML document to JSON.
// This is a basic implementation that handles common OpenAPI YAML structures.
func YAMLToJSON(yamlData []byte) ([]byte, error) {
	// Parse YAML into intermediate map structure
	data, err := parseYAML(yamlData)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Convert to JSON
	return json.Marshal(data)
}

// parseYAML parses YAML data into Go native structures.
func parseYAML(data []byte) (any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	root := make(map[string]any)
	var currentMap map[string]any
	var currentArray []any
	var stack []map[string]any
	var indentStack []int
	var currentKey string
	var inArray bool
	var arrayOwner map[string]any // the map the current array hangs under
	var arrayKey string           // the key currentArray is stored under
	var lastItemIndent int        // the indent of the most recent "- " array-item line

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Calculate indent level
		indent := countIndent(line)

		// Handle document separator
		if trimmed == "---" {
			continue
		}

		// Parse the line
		key, value, isArrayItem := parseYAMLLine(trimmed)

		// Pop from stack if indent decreased
		for len(indentStack) > 0 && indent <= indentStack[len(indentStack)-1] {
			if len(stack) > 0 {
				currentMap = stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			if len(indentStack) > 0 {
				indentStack = indentStack[:len(indentStack)-1]
			}
		}

		if isArrayItem {
			// Handle array item
			// This line's indent bounds the item: continuation keys are deeper,
			// a key at or above this indent exits the item.
			lastItemIndent = indent
			if !inArray || currentArray == nil {
				currentArray = []any{}
				inArray = true
				// The array replaces the placeholder map the new-nested branch
				// stored under currentKey in the PARENT map — so the array's
				// owner is that parent, not the placeholder itself.
				if len(stack) > 0 {
					arrayOwner = stack[len(stack)-1]
				} else {
					arrayOwner = currentMap
				}
				arrayKey = currentKey
			}

			if value == "" {
				// Nested object in array
				nestedMap := make(map[string]any)
				currentArray = append(currentArray, nestedMap)
				if arrayOwner != nil && arrayKey != "" {
					arrayOwner[arrayKey] = currentArray
				}
				stack = append(stack, currentMap)
				indentStack = append(indentStack, indent)
				currentMap = nestedMap
			} else if key != "" {
				// Object array item ("- key: value") — its sibling keys (the
				// continuation lines at a deeper indent) must land in the same
				// item object, so append the item and descend into it.
				itemMap := map[string]any{key: parseYAMLValue(value)}
				currentArray = append(currentArray, itemMap)
				if arrayOwner != nil && arrayKey != "" {
					arrayOwner[arrayKey] = currentArray
				}
				stack = append(stack, currentMap)
				indentStack = append(indentStack, indent)
				currentMap = itemMap
			} else {
				parsedValue := parseYAMLValue(value)
				currentArray = append(currentArray, parsedValue)
				if arrayOwner != nil && arrayKey != "" {
					arrayOwner[arrayKey] = currentArray
				}
			}
		} else if value == "" {
			// New nested object
			if currentMap == nil {
				currentMap = root
			}

			newMap := make(map[string]any)
			if currentMap != nil {
				currentMap[key] = newMap
			}
			stack = append(stack, currentMap)
			indentStack = append(indentStack, indent)
			currentMap = newMap
			currentKey = key
			// A nested map inside the current array item (deeper than the item
			// marker) must not end the item; only a line at or above the item
			// marker's indent exits it.
			if inArray && indent <= lastItemIndent {
				inArray = false
				currentArray = nil
				arrayOwner = nil
				arrayKey = ""
			}
		} else {
			// Key-value pair
			if currentMap == nil {
				currentMap = root
			}
			parsedValue := parseYAMLValue(value)
			currentMap[key] = parsedValue
			currentKey = key
			// Same continuation rule as above: deeper-than-item lines are
			// part of the current array item, not an exit from it.
			if inArray && indent <= lastItemIndent {
				inArray = false
				currentArray = nil
				arrayOwner = nil
				arrayKey = ""
			}
		}
	}

	// If root is empty but we have a simple value, return that
	if len(root) == 0 {
		return nil, fmt.Errorf("empty YAML document")
	}

	return root, nil
}

// parseYAMLLine parses a single YAML line into key and value.
func parseYAMLLine(line string) (key, value string, isArrayItem bool) {
	// Check for array item
	if strings.HasPrefix(line, "- ") {
		isArrayItem = true
		content := strings.TrimPrefix(line, "- ")
		// Check if there's a key-value pair in the array item
		if idx := strings.Index(content, ": "); idx > 0 {
			key = strings.TrimSpace(content[:idx])
			value = strings.TrimSpace(content[idx+2:])
		} else if strings.HasSuffix(content, ":") {
			key = strings.TrimSuffix(content, ":")
			value = ""
		} else {
			key = ""
			value = content
		}
		return
	}

	// Regular key-value pair
	if idx := strings.Index(line, ": "); idx > 0 {
		key = strings.TrimSpace(line[:idx])
		value = strings.TrimSpace(line[idx+2:])
	} else if strings.HasSuffix(line, ":") {
		key = strings.TrimSuffix(line, ":")
		value = ""
	}

	return
}

// parseYAMLValue parses a YAML value into appropriate Go type.
func parseYAMLValue(value string) any {
	// Empty value
	if value == "" {
		return ""
	}

	// Handle quoted strings
	if (strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`)) ||
		(strings.HasPrefix(value, `'`) && strings.HasSuffix(value, `'`)) {
		return value[1 : len(value)-1]
	}

	// Handle special values
	switch strings.ToLower(value) {
	case "true", "yes", "on":
		return true
	case "false", "no", "off":
		return false
	case "null", "~", "":
		return nil
	}

	// Try integer
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i
	}

	// Try float
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f
	}

	// Handle multiline strings (| or >)
	if strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
		return ""
	}

	// Return as string
	return value
}

// countIndent counts leading spaces in a line.
func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2 // Treat tab as 2 spaces
		} else {
			break
		}
	}
	return count
}

// LoadYAMLSpec loads an OpenAPI spec from YAML data.
func LoadYAMLSpec(yamlData []byte) (*OpenAPISpec, error) {
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		return nil, err
	}

	var spec OpenAPISpec
	if err := json.Unmarshal(jsonData, &spec); err != nil {
		return nil, fmt.Errorf("unmarshaling spec: %w", err)
	}

	return &spec, nil
}

// IsYAML checks if data appears to be YAML format.
func IsYAML(data []byte) bool {
	content := string(data)

	// A document opening with a JSON object/array bracket is JSON — the JSON
	// load path parses it natively. Pretty-printed JSON is full of ": " and
	// would otherwise be misclassified here, then mangled by the naive YAML
	// parser into an empty spec.
	if trimmedContent := strings.TrimSpace(content); strings.HasPrefix(trimmedContent, "{") || strings.HasPrefix(trimmedContent, "[") {
		return false
	}

	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Check for YAML indicators
		if strings.Contains(line, ": ") || strings.HasSuffix(line, ":") {
			return true
		}
		if strings.HasPrefix(trimmed, "- ") {
			return true
		}
		if trimmed == "---" {
			return true
		}
	}

	return false
}

// SimpleYAMLUnmarshal is a simple YAML unmarshaller for common patterns.
func SimpleYAMLUnmarshal(data []byte, v any) error {
	jsonData, err := YAMLToJSON(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(jsonData, v)
}
