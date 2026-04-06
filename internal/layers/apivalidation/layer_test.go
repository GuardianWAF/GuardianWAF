package apivalidation

import (
	"regexp"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	layer := NewLayer(cfg)

	if layer.Name() != "apivalidation" {
		t.Errorf("Expected layer name 'apivalidation', got '%s'", layer.Name())
	}

	if !layer.enabled {
		t.Error("Expected layer to be enabled")
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/api/users",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass when disabled, got %v", result.Action)
	}

	if result.Score != 0 {
		t.Errorf("Expected score 0 when disabled, got %d", result.Score)
	}
}

func TestPathRouter(t *testing.T) {
	router := NewPathRouter()

	// Add routes
	router.AddRoute("GET", "/api/users", &RouteInfo{Path: "/api/users", Method: "GET"})
	router.AddRoute("POST", "/api/users", &RouteInfo{Path: "/api/users", Method: "POST"})
	router.AddRoute("GET", "/api/users/{id}", &RouteInfo{
		Path:    "/api/users/{id}",
		Method:  "GET",
		Pattern: regexp.MustCompile("^/api/users/([^/]+)$"),
	})

	// Test exact match
	route := router.Match("GET", "/api/users")
	if route == nil {
		t.Error("Expected to find /api/users route")
	}

	// Test method mismatch
	route = router.Match("POST", "/api/users")
	if route == nil {
		t.Error("Expected to find POST /api/users route")
	}

	// Test pattern match
	route = router.Match("GET", "/api/users/123")
	if route == nil {
		t.Error("Expected to find /api/users/{id} route")
	}

	// Test no match
	route = router.Match("DELETE", "/api/users")
	if route != nil {
		t.Error("Should not find DELETE /api/users route")
	}
}

func TestSchemaValidator_ValidateString(t *testing.T) {
	validator := NewSchemaValidator(true)

	// Test valid string
	schema := &Schema{Type: "string"}
	result := validator.Validate("hello", schema, "test")
	if !result.Valid {
		t.Errorf("Expected valid string, got errors: %v", result.Errors)
	}

	// Test invalid type
	result = validator.Validate(123, schema, "test")
	if result.Valid {
		t.Error("Expected invalid for number as string")
	}

	// Test minLength
	schema = &Schema{Type: "string", MinLength: ptrInt(5)}
	result = validator.Validate("hi", schema, "test")
	if result.Valid {
		t.Error("Expected invalid for string shorter than minLength")
	}

	// Test maxLength
	schema = &Schema{Type: "string", MaxLength: ptrInt(3)}
	result = validator.Validate("hello", schema, "test")
	if result.Valid {
		t.Error("Expected invalid for string longer than maxLength")
	}

	// Test pattern
	schema = &Schema{Type: "string", Pattern: "^[a-z]+$"}
	result = validator.Validate("Hello123", schema, "test")
	if result.Valid {
		t.Error("Expected invalid for pattern mismatch")
	}

	result = validator.Validate("hello", schema, "test")
	if !result.Valid {
		t.Errorf("Expected valid for pattern match, got errors: %v", result.Errors)
	}
}

func TestSchemaValidator_ValidateNumber(t *testing.T) {
	validator := NewSchemaValidator(true)

	// Test integer
	schema := &Schema{Type: "integer"}
	result := validator.Validate(42, schema, "test")
	if !result.Valid {
		t.Errorf("Expected valid integer, got errors: %v", result.Errors)
	}

	// Test number (float)
	schema = &Schema{Type: "number"}
	result = validator.Validate(3.14, schema, "test")
	if !result.Valid {
		t.Errorf("Expected valid number, got errors: %v", result.Errors)
	}

	// Test minimum
	min := 10.0
	schema = &Schema{Type: "number", Minimum: &min}
	result = validator.Validate(5, schema, "test")
	if result.Valid {
		t.Error("Expected invalid for number below minimum")
	}

	// Test maximum
	max := 100.0
	schema = &Schema{Type: "number", Maximum: &max}
	result = validator.Validate(150, schema, "test")
	if result.Valid {
		t.Error("Expected invalid for number above maximum")
	}
}

func TestSchemaValidator_ValidateObject(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{
		Type:     "object",
		Required: []string{"name", "email"},
		Properties: map[string]*Schema{
			"name":  {Type: "string"},
			"email": {Type: "string", Format: "email"},
			"age":   {Type: "integer"},
		},
	}

	// Valid object
	data := map[string]any{
		"name":  "John",
		"email": "john@example.com",
		"age":   30,
	}
	result := validator.Validate(data, schema, "user")
	if !result.Valid {
		t.Errorf("Expected valid object, got errors: %v", result.Errors)
	}

	// Missing required field
	data = map[string]any{
		"name": "John",
	}
	result = validator.Validate(data, schema, "user")
	if result.Valid {
		t.Error("Expected invalid for missing required field")
	}

	// Invalid email format
	data = map[string]any{
		"name":  "John",
		"email": "not-an-email",
	}
	result = validator.Validate(data, schema, "user")
	if result.Valid {
		t.Error("Expected invalid for bad email format")
	}
}

func TestSchemaValidator_ValidateArray(t *testing.T) {
	validator := NewSchemaValidator(true)

	itemSchema := &Schema{Type: "string"}
	schema := &Schema{
		Type:     "array",
		MinItems: ptrInt(2),
		MaxItems: ptrInt(5),
		Items:    itemSchema,
	}

	// Valid array
	data := []any{"a", "b", "c"}
	result := validator.Validate(data, schema, "items")
	if !result.Valid {
		t.Errorf("Expected valid array, got errors: %v", result.Errors)
	}

	// Too few items
	data = []any{"a"}
	result = validator.Validate(data, schema, "items")
	if result.Valid {
		t.Error("Expected invalid for array below minItems")
	}

	// Too many items
	data = []any{"a", "b", "c", "d", "e", "f"}
	result = validator.Validate(data, schema, "items")
	if result.Valid {
		t.Error("Expected invalid for array above maxItems")
	}
}

func TestSchemaValidator_ValidateEnum(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{
		Type: "string",
		Enum: []any{"active", "inactive", "pending"},
	}

	// Valid enum value
	result := validator.Validate("active", schema, "status")
	if !result.Valid {
		t.Errorf("Expected valid enum value, got errors: %v", result.Errors)
	}

	// Invalid enum value
	result = validator.Validate("deleted", schema, "status")
	if result.Valid {
		t.Error("Expected invalid for enum value not in set")
	}
}

func TestSchemaValidator_ValidateFormat(t *testing.T) {
	validator := NewSchemaValidator(true)

	formats := []struct {
		format  string
		valid   string
		invalid string
	}{
		{"email", "user@example.com", "not-an-email"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "not-a-uuid"},
		{"ipv4", "192.168.1.1", "not-an-ip"},
		{"date", "2024-01-15", "not-a-date"},
	}

	for _, tc := range formats {
		schema := &Schema{Type: "string", Format: tc.format}

		result := validator.Validate(tc.valid, schema, "field")
		if !result.Valid {
			t.Errorf("Expected valid %s for '%s', got errors: %v", tc.format, tc.valid, result.Errors)
		}

		result = validator.Validate(tc.invalid, schema, "field")
		if result.Valid {
			t.Errorf("Expected invalid %s for '%s'", tc.format, tc.invalid)
		}
	}
}

func TestSchemaCache(t *testing.T) {
	cache := NewSchemaCache(2)

	schema1 := &CompiledSchema{Path: "/api/users", Method: "GET"}
	schema2 := &CompiledSchema{Path: "/api/users", Method: "POST"}
	schema3 := &CompiledSchema{Path: "/api/items", Method: "GET"}

	// Put schemas
	cache.Put("key1", schema1)
	cache.Put("key2", schema2)

	// Get existing
	if cache.Get("key1") == nil {
		t.Error("Expected to get key1")
	}

	// Add third (should evict oldest)
	cache.Put("key3", schema3)

	// key2 should still exist (more recent than key1)
	if cache.Get("key2") == nil {
		t.Error("Expected key2 to still exist")
	}
}

func TestCompilePathPattern(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	tests := []struct {
		path    string
		request string
		match   bool
	}{
		{"/api/users", "/api/users", true},
		{"/api/users/{id}", "/api/users/123", true},
		{"/api/users/{id}", "/api/users/abc", true},
		{"/api/users/{id}", "/api/users/123/extra", false},
		{"/api/users/{userId}/posts/{postId}", "/api/users/42/posts/99", true},
	}

	for _, tc := range tests {
		pattern := layer.compilePathPattern(tc.path)
		if pattern == nil {
			t.Errorf("Failed to compile pattern for %s", tc.path)
			continue
		}

		matches := pattern.MatchString(tc.request)
		if matches != tc.match {
			t.Errorf("Path %s against %s: expected match=%v, got match=%v",
				tc.request, tc.path, tc.match, matches)
		}
	}
}

func TestExtractPathParam(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	tests := []struct {
		requestPath string
		routePath   string
		paramName   string
		expected    string
	}{
		{"/api/users/123", "/api/users/{id}", "id", "123"},
		{"/api/users/abc/posts/456", "/api/users/{userId}/posts/{postId}", "userId", "abc"},
		{"/api/users/abc/posts/456", "/api/users/{userId}/posts/{postId}", "postId", "456"},
		{"/api/users", "/api/users", "id", ""},
		{"/api/items/789", "/api/users/{id}", "id", ""},
	}

	for _, tc := range tests {
		result := layer.extractPathParam(tc.requestPath, tc.routePath, tc.paramName)
		if result != tc.expected {
			t.Errorf("extractPathParam(%s, %s, %s): expected '%s', got '%s'",
				tc.requestPath, tc.routePath, tc.paramName, tc.expected, result)
		}
	}
}

func TestLayer_Process_NoSchema(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = false // Allow unknown endpoints

	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/unknown/path",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for unknown path in non-strict mode, got %v", result.Action)
	}
}

func TestLayer_Process_StrictMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = true // Reject unknown endpoints
	cfg.ViolationScore = 40
	cfg.BlockOnViolation = true

	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/unknown/path",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock for unknown path in strict mode, got %v", result.Action)
	}

	if result.Score != 40 {
		t.Errorf("Expected score 40, got %d", result.Score)
	}
}

func TestLayer_GetStats(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	stats := layer.GetStats()

	if stats.SpecsLoaded != 0 {
		t.Errorf("Expected 0 specs, got %d", stats.SpecsLoaded)
	}
}

// Helper function
func ptrInt(i int) *int {
	return &i
}
