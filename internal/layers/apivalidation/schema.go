// Package apivalidation provides OpenAPI schema validation for requests and responses.
// Validates incoming requests against OpenAPI 3.0 schemas.
package apivalidation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Pre-compiled regex patterns for format validation (avoids recompilation per request).
var (
	reEmail     = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	reUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reDateTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`)
	reDate     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reIPv4     = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	// userPatternCache caches user-defined regex patterns from API schemas.
	userPatternCache     sync.Map       // string → *regexp.Regexp
	userPatternCacheSize atomic.Int64   // track cache size for cap enforcement
)

// Config holds API validation configuration.
type Config struct {
	Enabled           bool           `yaml:"enabled"`
	ValidateRequest   bool           `yaml:"validate_request"`
	ValidateResponse  bool           `yaml:"validate_response"`
	StrictMode        bool           `yaml:"strict_mode"`       // Reject unknown fields
	BlockOnViolation  bool           `yaml:"block_on_violation"`
	ViolationScore    int            `yaml:"violation_score"`
	Schemas           []SchemaSource `yaml:"schemas"`
	CacheSize         int            `yaml:"cache_size"`        // Compiled schema cache size
}

// DefaultConfig returns default API validation configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          false,
		ValidateRequest:  true,
		ValidateResponse: false,
		StrictMode:       true,
		BlockOnViolation: true,
		ViolationScore:   40,
		CacheSize:        100,
	}
}

// SchemaSource represents a schema source configuration.
type SchemaSource struct {
	Path      string `yaml:"path"`       // File path or URL
	Type      string `yaml:"type"`       // "openapi", "jsonschema"
	AutoLearn bool   `yaml:"auto_learn"` // Learn from traffic
}

// OpenAPISpec represents an OpenAPI 3.0 specification.
type OpenAPISpec struct {
	OpenAPI    string                 `json:"openapi" yaml:"openapi"`
	Info       Info                   `json:"info" yaml:"info"`
	Servers    []Server               `json:"servers,omitempty" yaml:"servers,omitempty"`
	Paths      map[string]PathItem    `json:"paths" yaml:"paths"`
	Components *Components            `json:"components,omitempty" yaml:"components,omitempty"`
}

// Info represents API information.
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string `json:"version" yaml:"version"`
}

// Server represents an API server.
type Server struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// PathItem represents a path item in OpenAPI.
type PathItem struct {
	Summary     string     `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Get         *Operation `json:"get,omitempty" yaml:"get,omitempty"`
	Post        *Operation `json:"post,omitempty" yaml:"post,omitempty"`
	Put         *Operation `json:"put,omitempty" yaml:"put,omitempty"`
	Delete      *Operation `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch       *Operation `json:"patch,omitempty" yaml:"patch,omitempty"`
	Head        *Operation `json:"head,omitempty" yaml:"head,omitempty"`
	Options     *Operation `json:"options,omitempty" yaml:"options,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// Operation represents an API operation.
type Operation struct {
	Summary     string              `json:"summary" yaml:"summary"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	OperationID string              `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Tags        []string            `json:"tags,omitempty" yaml:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses" yaml:"responses"`
}

// Parameter represents an operation parameter.
type Parameter struct {
	Name        string `json:"name" yaml:"name"`
	In          string `json:"in" yaml:"in"` // query, header, path, cookie
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool   `json:"required,omitempty" yaml:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// RequestBody represents a request body.
type RequestBody struct {
	Description string                `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool                  `json:"required,omitempty" yaml:"required,omitempty"`
	Content     map[string]MediaType  `json:"content" yaml:"content"`
}

// Response represents an API response.
type Response struct {
	Description string               `json:"description" yaml:"description"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
}

// MediaType represents a media type definition.
type MediaType struct {
	Schema   *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example  any     `json:"example,omitempty" yaml:"example,omitempty"`
}

// Components holds reusable components.
type Components struct {
	Schemas map[string]*Schema `json:"schemas,omitempty" yaml:"schemas,omitempty"`
}

// Schema represents a JSON Schema.
type Schema struct {
	Type                 string             `json:"type,omitempty" yaml:"type,omitempty"`
	Format               string             `json:"format,omitempty" yaml:"format,omitempty"`
	Description          string             `json:"description,omitempty" yaml:"description,omitempty"`
	Default              any                `json:"default,omitempty" yaml:"default,omitempty"`
	Enum                 []any              `json:"enum,omitempty" yaml:"enum,omitempty"`
	Pattern              string             `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Minimum              *float64           `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	Maximum              *float64           `json:"maximum,omitempty" yaml:"maximum,omitempty"`
	ExclusiveMinimum     bool               `json:"exclusiveMinimum,omitempty" yaml:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum     bool               `json:"exclusiveMaximum,omitempty" yaml:"exclusiveMaximum,omitempty"`
	MinLength            *int               `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	MinItems             *int               `json:"minItems,omitempty" yaml:"minItems,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty" yaml:"maxItems,omitempty"`
	UniqueItems          bool               `json:"uniqueItems,omitempty" yaml:"uniqueItems,omitempty"`
	Required             []string           `json:"required,omitempty" yaml:"required,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	AdditionalProperties *bool              `json:"additionalProperties,omitempty" yaml:"additionalProperties,omitempty"`
	Items                *Schema            `json:"items,omitempty" yaml:"items,omitempty"`
	OneOf                []*Schema          `json:"oneOf,omitempty" yaml:"oneOf,omitempty"`
	AnyOf                []*Schema          `json:"anyOf,omitempty" yaml:"anyOf,omitempty"`
	AllOf                []*Schema          `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	Ref                  string             `json:"$ref,omitempty" yaml:"$ref,omitempty"`
}

// ValidationError represents a schema validation error.
type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Type        string `json:"type"`        // "type", "format", "required", "pattern", etc.
	Expected    string `json:"expected,omitempty"`
	Got         string `json:"got,omitempty"`
}

// ValidationResult holds the result of schema validation.
type ValidationResult struct {
	Valid   bool              `json:"valid"`
	Errors  []ValidationError `json:"errors"`
	Score   int               `json:"score"`
}

// CompiledSchema holds a compiled schema for fast validation.
type CompiledSchema struct {
	Path        string
	Method      string
	ContentType string
	Parameters  []CompiledParameter
	BodySchema  *CompiledBodySchema
	StrictMode  bool
}

// CompiledParameter holds a compiled parameter schema.
type CompiledParameter struct {
	Name     string
	In       string // query, header, path, cookie
	Required bool
	Schema   *Schema
}

// CompiledBodySchema holds a compiled request body schema.
type CompiledBodySchema struct {
	Required            bool
	Schema              *Schema
	AdditionalProperties bool
}

// SchemaCache caches compiled schemas.
type SchemaCache struct {
	schemas map[string]*CompiledSchema
	order   []string // LRU order
	maxSize int
	mu      sync.RWMutex
}

// NewSchemaCache creates a new schema cache.
func NewSchemaCache(maxSize int) *SchemaCache {
	if maxSize <= 0 {
		maxSize = 100
	}
	return &SchemaCache{
		schemas: make(map[string]*CompiledSchema),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

// Get retrieves a compiled schema from cache.
func (c *SchemaCache) Get(key string) *CompiledSchema {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.schemas[key]
}

// Put adds a compiled schema to cache.
func (c *SchemaCache) Put(key string, schema *CompiledSchema) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If key exists, update and move to end
	if _, exists := c.schemas[key]; exists {
		c.schemas[key] = schema
		c.moveToEnd(key)
		return
	}

	// If cache is full, evict oldest
	if len(c.schemas) >= c.maxSize {
		oldest := c.order[0]
		delete(c.schemas, oldest)
		c.order = c.order[1:]
	}

	c.schemas[key] = schema
	c.order = append(c.order, key)
}

// moveToEnd moves a key to the end of the order slice (most recently used).
func (c *SchemaCache) moveToEnd(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, key)
			return
		}
	}
}

// SchemaValidator validates data against JSON Schema.
type SchemaValidator struct {
	strictMode bool
}

// NewSchemaValidator creates a new schema validator.
func NewSchemaValidator(strictMode bool) *SchemaValidator {
	return &SchemaValidator{
		strictMode: strictMode,
	}
}

// Validate validates data against a schema.
func (v *SchemaValidator) Validate(data any, schema *Schema, path string) ValidationResult {
	result := ValidationResult{
		Valid:  true,
		Errors: []ValidationError{},
	}

	// Handle nil schema
	if schema == nil {
		return result
	}

	// Handle $ref (reference to components)
	if schema.Ref != "" {
		// For now, skip reference resolution
		// In production, this would resolve the reference
		return result
	}

	// Type validation
	if schema.Type != "" {
		if !v.validateType(data, schema.Type, path, &result) {
			return result
		}
	}

	// Type-specific validation
	switch schema.Type {
	case "string":
		v.validateString(data, schema, path, &result)
	case "integer", "number":
		v.validateNumber(data, schema, path, &result)
	case "boolean":
		v.validateBoolean(data, path, &result)
	case "array":
		v.validateArray(data, schema, path, &result)
	case "object":
		v.validateObject(data, schema, path, &result)
	}

	// Enum validation
	if len(schema.Enum) > 0 {
		v.validateEnum(data, schema.Enum, path, &result)
	}

	// Calculate score based on errors
	result.Score = len(result.Errors) * 10

	return result
}

// validateType validates the type of data.
func (v *SchemaValidator) validateType(data any, expectedType, path string, result *ValidationResult) bool {
	actualType := getJSONType(data)

	// Special handling for integer vs number
	if expectedType == "integer" && actualType == "number" {
		// Check if it's actually an integer
		if isInteger(data) {
			return true
		}
	}

	if expectedType == "number" && actualType == "integer" {
		return true
	}

	if actualType != expectedType {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    path,
			Type:     "type",
			Message:  fmt.Sprintf("expected %s, got %s", expectedType, actualType),
			Expected: expectedType,
			Got:      actualType,
		})
		return false
	}

	return true
}

// validateString validates string constraints.
func (v *SchemaValidator) validateString(data any, schema *Schema, path string, result *ValidationResult) {
	str, ok := data.(string)
	if !ok {
		return
	}

	// MinLength
	if schema.MinLength != nil && len(str) < *schema.MinLength {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    path,
			Type:     "minLength",
			Message:  fmt.Sprintf("string length %d is less than minimum %d", len(str), *schema.MinLength),
			Expected: strconv.Itoa(*schema.MinLength),
			Got:      strconv.Itoa(len(str)),
		})
	}

	// MaxLength
	if schema.MaxLength != nil && len(str) > *schema.MaxLength {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    path,
			Type:     "maxLength",
			Message:  fmt.Sprintf("string length %d exceeds maximum %d", len(str), *schema.MaxLength),
			Expected: strconv.Itoa(*schema.MaxLength),
			Got:      strconv.Itoa(len(str)),
		})
	}

	// Pattern
	if schema.Pattern != "" {
		re, err := getCachedPattern(schema.Pattern)
		if err == nil && !re.MatchString(str) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:    path,
				Type:     "pattern",
				Message:  fmt.Sprintf("string does not match pattern %s", schema.Pattern),
				Expected: schema.Pattern,
				Got:      str,
			})
		}
	}

	// Format validation
	if schema.Format != "" {
		if !v.validateFormat(str, schema.Format) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:    path,
				Type:     "format",
				Message:  fmt.Sprintf("string is not valid %s format", schema.Format),
				Expected: schema.Format,
				Got:      str,
			})
		}
	}
}

// validateNumber validates number constraints.
func (v *SchemaValidator) validateNumber(data any, schema *Schema, path string, result *ValidationResult) {
	num := toFloat64(data)
	if num == nil {
		return
	}

	val := *num

	// Minimum
	if schema.Minimum != nil {
		if (schema.ExclusiveMinimum && val <= *schema.Minimum) ||
			(!schema.ExclusiveMinimum && val < *schema.Minimum) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:    path,
				Type:     "minimum",
				Message:  fmt.Sprintf("value %v is less than minimum %v", val, *schema.Minimum),
				Expected: fmt.Sprintf(">= %v", *schema.Minimum),
				Got:      fmt.Sprintf("%v", val),
			})
		}
	}

	// Maximum
	if schema.Maximum != nil {
		if (schema.ExclusiveMaximum && val >= *schema.Maximum) ||
			(!schema.ExclusiveMaximum && val > *schema.Maximum) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:    path,
				Type:     "maximum",
				Message:  fmt.Sprintf("value %v exceeds maximum %v", val, *schema.Maximum),
				Expected: fmt.Sprintf("<= %v", *schema.Maximum),
				Got:      fmt.Sprintf("%v", val),
			})
		}
	}
}

// validateBoolean validates boolean (no additional constraints).
func (v *SchemaValidator) validateBoolean(data any, path string, result *ValidationResult) {
	// No additional constraints for boolean
}

// validateArray validates array constraints.
func (v *SchemaValidator) validateArray(data any, schema *Schema, path string, result *ValidationResult) {
	arr, ok := data.([]any)
	if !ok {
		return
	}

	// MinItems
	if schema.MinItems != nil && len(arr) < *schema.MinItems {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    path,
			Type:     "minItems",
			Message:  fmt.Sprintf("array length %d is less than minimum %d", len(arr), *schema.MinItems),
			Expected: strconv.Itoa(*schema.MinItems),
			Got:      strconv.Itoa(len(arr)),
		})
	}

	// MaxItems
	if schema.MaxItems != nil && len(arr) > *schema.MaxItems {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:    path,
			Type:     "maxItems",
			Message:  fmt.Sprintf("array length %d exceeds maximum %d", len(arr), *schema.MaxItems),
			Expected: strconv.Itoa(*schema.MaxItems),
			Got:      strconv.Itoa(len(arr)),
		})
	}

	// Validate items
	if schema.Items != nil {
		for i, item := range arr {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			itemResult := v.Validate(item, schema.Items, itemPath)
			if !itemResult.Valid {
				result.Valid = false
				result.Errors = append(result.Errors, itemResult.Errors...)
			}
		}
	}
}

// validateObject validates object constraints.
func (v *SchemaValidator) validateObject(data any, schema *Schema, path string, result *ValidationResult) {
	obj, ok := data.(map[string]any)
	if !ok {
		return
	}

	// Check required fields
	for _, req := range schema.Required {
		if _, exists := obj[req]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("%s.%s", path, req),
				Type:    "required",
				Message: fmt.Sprintf("required field '%s' is missing", req),
			})
		}
	}

	// Validate properties
	for key, value := range obj {
		propPath := fmt.Sprintf("%s.%s", path, key)

		// Check if property is defined
		if schema.Properties != nil {
			if propSchema, exists := schema.Properties[key]; exists {
				propResult := v.Validate(value, propSchema, propPath)
				if !propResult.Valid {
					result.Valid = false
					result.Errors = append(result.Errors, propResult.Errors...)
				}
			} else if v.strictMode || (schema.AdditionalProperties != nil && !*schema.AdditionalProperties) {
				// Unknown field in strict mode or additionalProperties: false
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   propPath,
					Type:    "additionalProperties",
					Message: fmt.Sprintf("additional property '%s' is not allowed", key),
				})
			}
		}
	}

	// Validate allOf (must match all schemas)
	for i, subSchema := range schema.AllOf {
		allOfPath := fmt.Sprintf("%s[allOf:%d]", path, i)
		subResult := v.Validate(data, subSchema, allOfPath)
		if !subResult.Valid {
			result.Valid = false
			result.Errors = append(result.Errors, subResult.Errors...)
		}
	}

	// Validate anyOf (must match at least one)
	if len(schema.AnyOf) > 0 {
		anyValid := false
		for i, subSchema := range schema.AnyOf {
			anyOfPath := fmt.Sprintf("%s[anyOf:%d]", path, i)
			subResult := v.Validate(data, subSchema, anyOfPath)
			if subResult.Valid {
				anyValid = true
				break
			}
		}
		if !anyValid {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   path,
				Type:    "anyOf",
				Message: "data does not match any of the required schemas",
			})
		}
	}

	// Validate oneOf (must match exactly one)
	if len(schema.OneOf) > 0 {
		matchCount := 0
		for i, subSchema := range schema.OneOf {
			oneOfPath := fmt.Sprintf("%s[oneOf:%d]", path, i)
			subResult := v.Validate(data, subSchema, oneOfPath)
			if subResult.Valid {
				matchCount++
			}
		}
		if matchCount != 1 {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   path,
				Type:    "oneOf",
				Message: fmt.Sprintf("data matches %d schemas, expected exactly 1", matchCount),
			})
		}
	}
}

// validateEnum validates enum constraints.
func (v *SchemaValidator) validateEnum(data any, enum []any, path string, result *ValidationResult) {
	for _, allowed := range enum {
		if data == allowed {
			return
		}
	}

	result.Valid = false
	result.Errors = append(result.Errors, ValidationError{
		Field:    path,
		Type:     "enum",
		Message:  fmt.Sprintf("value %v is not in enum %v", data, enum),
		Expected: fmt.Sprintf("%v", enum),
		Got:      fmt.Sprintf("%v", data),
	})
}

// validateFormat validates string format.
func (v *SchemaValidator) validateFormat(value, format string) bool {
	switch format {
	case "email":
		return validateEmail(value)
	case "uri", "url":
		return validateURL(value)
	case "uuid":
		return validateUUID(value)
	case "date-time":
		return validateDateTime(value)
	case "date":
		return validateDate(value)
	case "ipv4":
		return validateIPv4(value)
	case "ipv6":
		return validateIPv6(value)
	case "hostname":
		return validateHostname(value)
	default:
		return true // Unknown formats pass
	}
}

// Helper functions

func getJSONType(data any) string {
	switch data.(type) {
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case int, int64:
		return "integer"
	default:
		return "unknown"
	}
}

func isInteger(data any) bool {
	switch v := data.(type) {
	case int, int64:
		return true
	case float64:
		return v == float64(int64(v))
	default:
		return false
	}
}

func toFloat64(data any) *float64 {
	switch v := data.(type) {
	case float64:
		return &v
	case int:
		f := float64(v)
		return &f
	case int64:
		f := float64(v)
		return &f
	default:
		return nil
	}
}

func validateEmail(email string) bool {
	return reEmail.MatchString(email)
}

func validateURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

func validateUUID(uuid string) bool {
	return reUUID.MatchString(uuid)
}

func validateDateTime(dt string) bool {
	return reDateTime.MatchString(dt)
}

func validateDate(date string) bool {
	return reDate.MatchString(date)
}

func validateIPv4(ip string) bool {
	if !reIPv4.MatchString(ip) {
		return false
	}
	parts := strings.Split(ip, ".")
	for _, part := range parts {
		n, _ := strconv.Atoi(part)
		if n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func validateIPv6(ip string) bool {
	// Simplified IPv6 validation
	return strings.Contains(ip, ":")
}

func validateHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	return reHostname.MatchString(host)
}

// getCachedPattern returns a cached compiled regex, compiling on first use.
func getCachedPattern(pattern string) (*regexp.Regexp, error) {
	if v, ok := userPatternCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// Enforce cache cap — return compiled regex without caching if over limit
	if userPatternCacheSize.Load() < 10000 {
		if _, loaded := userPatternCache.LoadOrStore(pattern, re); !loaded {
			userPatternCacheSize.Add(1)
		}
	}
	return re, nil
}
