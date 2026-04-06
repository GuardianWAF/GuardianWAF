package apivalidation

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
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
			if !inArray || currentArray == nil {
				currentArray = []any{}
				inArray = true
			}

			if value == "" {
				// Nested object in array
				nestedMap := make(map[string]any)
				currentArray = append(currentArray, nestedMap)
				if currentMap != nil && currentKey != "" {
					currentMap[currentKey] = currentArray
				}
				stack = append(stack, currentMap)
				indentStack = append(indentStack, indent)
				currentMap = nestedMap
			} else {
				// Simple value in array
				parsedValue := parseYAMLValue(value)
				currentArray = append(currentArray, parsedValue)
				if currentMap != nil && currentKey != "" {
					currentMap[currentKey] = currentArray
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
			inArray = false
			currentArray = nil
		} else {
			// Key-value pair
			if currentMap == nil {
				currentMap = root
			}
			parsedValue := parseYAMLValue(value)
			currentMap[key] = parsedValue
			currentKey = key
			inArray = false
			currentArray = nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
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

// resolveJSONRefs resolves JSON references ($ref) in a schema.
func resolveJSONRefs(schema *Schema, components *Components) *Schema {
	if schema == nil {
		return nil
	}

	// Resolve $ref
	if schema.Ref != "" && components != nil {
		refName := extractRefName(schema.Ref)
		if refSchema, ok := components.Schemas[refName]; ok {
			return resolveJSONRefs(refSchema, components)
		}
	}

	// Recursively resolve nested schemas
	for key, prop := range schema.Properties {
		schema.Properties[key] = resolveJSONRefs(prop, components)
	}

	if schema.Items != nil {
		schema.Items = resolveJSONRefs(schema.Items, components)
	}

	for i, subSchema := range schema.AllOf {
		schema.AllOf[i] = resolveJSONRefs(subSchema, components)
	}

	for i, subSchema := range schema.AnyOf {
		schema.AnyOf[i] = resolveJSONRefs(subSchema, components)
	}

	for i, subSchema := range schema.OneOf {
		schema.OneOf[i] = resolveJSONRefs(subSchema, components)
	}

	return schema
}

// extractRefName extracts the schema name from a $ref path.
func extractRefName(ref string) string {
	// Handle #/components/schemas/SchemaName
	re := regexp.MustCompile(`#/components/schemas/(\w+)`)
	matches := re.FindStringSubmatch(ref)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
