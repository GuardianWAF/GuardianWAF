package apivalidation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// testDir creates a temp subdirectory inside CWD so readFile's path confinement check passes.
func testDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(".", ".test_tmp", t.Name())
	os.MkdirAll(dir, 0755)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeTestFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := testDir(t)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

// ============================================================================
// Schema Validator: comprehensive type validation
// ============================================================================

func TestValidate_BooleanType(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "boolean"}
	result := validator.Validate(true, schema, "flag")
	if !result.Valid {
		t.Errorf("Expected valid boolean true, got errors: %v", result.Errors)
	}

	result = validator.Validate(false, schema, "flag")
	if !result.Valid {
		t.Errorf("Expected valid boolean false, got errors: %v", result.Errors)
	}

	result = validator.Validate("true", schema, "flag")
	if result.Valid {
		t.Error("Expected invalid for string as boolean")
	}
}

func TestValidate_NilSchema(t *testing.T) {
	validator := NewSchemaValidator(true)
	result := validator.Validate("anything", nil, "field")
	if !result.Valid {
		t.Error("Expected valid when schema is nil")
	}
}

func TestValidate_Ref(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Ref: "#/components/schemas/User"}
	result := validator.Validate("anything", schema, "field")
	if !result.Valid {
		t.Error("Expected valid when schema has a $ref (skipped)")
	}
}

func TestValidate_UnknownType(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "unknown"}
	result := validator.Validate("hello", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for unknown type")
	}
}

func TestValidate_NullType(t *testing.T) {
	validator := NewSchemaValidator(false)
	schema := &Schema{Type: "null"}
	result := validator.Validate(nil, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for nil as null type, got errors: %v", result.Errors)
	}
}

func TestValidate_NoType(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Enum: []any{"a", "b"}}
	result := validator.Validate("a", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for enum match with no type, got errors: %v", result.Errors)
	}
}

// ============================================================================
// String validation: boundary and edge cases
// ============================================================================

func TestValidate_StringExactLength(t *testing.T) {
	validator := NewSchemaValidator(true)

	five := 5
	schema := &Schema{Type: "string", MinLength: &five}
	result := validator.Validate("hello", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for string at exact minLength, got errors: %v", result.Errors)
	}

	three := 3
	schema = &Schema{Type: "string", MaxLength: &three}
	result = validator.Validate("abc", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for string at exact maxLength, got errors: %v", result.Errors)
	}
}

func TestValidate_StringEmpty(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string"}
	result := validator.Validate("", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for empty string with no constraints, got errors: %v", result.Errors)
	}

	zero := 0
	schema = &Schema{Type: "string", MinLength: &zero}
	result = validator.Validate("", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for empty string with MinLength=0, got errors: %v", result.Errors)
	}
}

// ============================================================================
// Number validation: exclusive boundaries
// ============================================================================

func TestValidate_NumberExclusiveMin(t *testing.T) {
	validator := NewSchemaValidator(true)

	min := 10.0
	schema := &Schema{Type: "number", Minimum: &min, ExclusiveMinimum: true}

	result := validator.Validate(10.0, schema, "field")
	if result.Valid {
		t.Error("Expected invalid for number equal to exclusive minimum")
	}

	result = validator.Validate(10.1, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for number above exclusive minimum, got errors: %v", result.Errors)
	}
}

func TestValidate_NumberExclusiveMax(t *testing.T) {
	validator := NewSchemaValidator(true)

	max := 100.0
	schema := &Schema{Type: "number", Maximum: &max, ExclusiveMaximum: true}

	result := validator.Validate(100.0, schema, "field")
	if result.Valid {
		t.Error("Expected invalid for number equal to exclusive maximum")
	}

	result = validator.Validate(99.9, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for number below exclusive maximum, got errors: %v", result.Errors)
	}
}

func TestValidate_NumberAtBoundary(t *testing.T) {
	validator := NewSchemaValidator(true)

	min := 10.0
	max := 100.0
	schema := &Schema{Type: "number", Minimum: &min, Maximum: &max}

	result := validator.Validate(10.0, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid at minimum boundary, got errors: %v", result.Errors)
	}

	result = validator.Validate(100.0, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid at maximum boundary, got errors: %v", result.Errors)
	}
}

func TestValidate_NumberIntTypes(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "number"}
	result := validator.Validate(42, schema, "field")
	if !result.Valid {
		t.Errorf("Expected int to be valid as number type, got errors: %v", result.Errors)
	}

	var v int64 = 99
	result = validator.Validate(v, schema, "field")
	if !result.Valid {
		t.Errorf("Expected int64 to be valid as number type, got errors: %v", result.Errors)
	}
}

func TestValidate_IntegerWithFloat(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "integer"}
	result := validator.Validate(float64(42), schema, "field")
	if !result.Valid {
		t.Errorf("Expected float64(42) to be valid as integer, got errors: %v", result.Errors)
	}

	result = validator.Validate(42.5, schema, "field")
	if result.Valid {
		t.Error("Expected float64(42.5) to be invalid as integer")
	}
}

func TestValidate_IntegerWithInt64(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "integer"}
	var v int64 = 42
	result := validator.Validate(v, schema, "field")
	if !result.Valid {
		t.Errorf("Expected int64 to be valid as integer, got errors: %v", result.Errors)
	}
}

func TestValidate_NumberWithNonNumeric(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "number"}
	result := validator.Validate("not-a-number", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for string as number")
	}
}

// ============================================================================
// Array validation
// ============================================================================

func TestValidate_ArrayNoItemsSchema(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "array"}
	data := []any{1, "two", true}
	result := validator.Validate(data, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid array with no items schema, got errors: %v", result.Errors)
	}
}

func TestValidate_ArrayWithNestedItems(t *testing.T) {
	validator := NewSchemaValidator(true)

	itemSchema := &Schema{Type: "integer"}
	schema := &Schema{Type: "array", Items: itemSchema}

	data := []any{1, 2, "three"}
	result := validator.Validate(data, schema, "field")
	if result.Valid {
		t.Error("Expected invalid for array with non-integer item")
	}

	found := false
	for _, e := range result.Errors {
		if strings.Contains(e.Field, "[2]") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected error at index [2], got errors: %v", result.Errors)
	}
}

func TestValidate_ArrayValidItems(t *testing.T) {
	validator := NewSchemaValidator(true)

	itemSchema := &Schema{Type: "string"}
	schema := &Schema{Type: "array", Items: itemSchema}

	data := []any{"a", "b", "c"}
	result := validator.Validate(data, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid array items, got errors: %v", result.Errors)
	}
}

// ============================================================================
// Object validation: additionalProperties, allOf, anyOf, oneOf
// ============================================================================

func TestValidate_ObjectAdditionalProperties_Strict(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
	}

	data := map[string]any{
		"name":    "Alice",
		"unknown": "value",
	}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid for additional property in strict mode")
	}
}

func TestValidate_ObjectAdditionalProperties_Lenient(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
	}

	data := map[string]any{
		"name":    "Alice",
		"unknown": "value",
	}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid for additional property in lenient mode, got errors: %v", result.Errors)
	}
}

func TestValidate_ObjectAdditionalPropertiesExplicitlyFalse(t *testing.T) {
	validator := NewSchemaValidator(false)
	apFalse := false

	schema := &Schema{
		Type:                 "object",
		AdditionalProperties: &apFalse,
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
	}

	data := map[string]any{
		"name":    "Alice",
		"unknown": "value",
	}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid for additional property when additionalProperties=false")
	}
}

func TestValidate_ObjectAdditionalPropertiesExplicitlyTrue(t *testing.T) {
	validator := NewSchemaValidator(false) // use lenient so strictMode doesn't interfere
	apTrue := true

	schema := &Schema{
		Type:                 "object",
		AdditionalProperties: &apTrue,
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
	}

	data := map[string]any{
		"name":    "Alice",
		"unknown": "value",
	}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid for additional property when additionalProperties=true, got errors: %v", result.Errors)
	}
}

func TestValidate_ObjectNoProperties(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "object"}
	data := map[string]any{"key": "value"}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid for object with no properties defined, got errors: %v", result.Errors)
	}
}

func TestValidate_ObjectAllOf(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		AllOf: []*Schema{
			{Type: "object", Required: []string{"name"}},
			{Type: "object", Required: []string{"age"}},
		},
	}

	data := map[string]any{"name": "Alice"}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid when allOf schema fails (missing age)")
	}

	data = map[string]any{"name": "Alice", "age": 30}
	result = validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid when allOf schemas match, got errors: %v", result.Errors)
	}
}

func TestValidate_ObjectAnyOf(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		AnyOf: []*Schema{
			{Type: "object", Required: []string{"email"}},
			{Type: "object", Required: []string{"phone"}},
		},
	}

	data := map[string]any{"email": "a@b.com"}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid when matching first anyOf, got errors: %v", result.Errors)
	}

	data = map[string]any{"phone": "123"}
	result = validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid when matching second anyOf, got errors: %v", result.Errors)
	}

	data = map[string]any{"name": "Alice"}
	result = validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid when matching no anyOf schemas")
	}
}

func TestValidate_ObjectOneOf(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		OneOf: []*Schema{
			{
				Type: "object",
				Properties: map[string]*Schema{
					"type": {Type: "string", Enum: []any{"cat"}},
				},
			},
			{
				Type: "object",
				Properties: map[string]*Schema{
					"type": {Type: "string", Enum: []any{"dog"}},
				},
			},
		},
	}

	data := map[string]any{"type": "cat"}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Errorf("Expected valid for matching exactly one oneOf, got errors: %v", result.Errors)
	}
}

func TestValidate_ObjectOneOf_Multiple(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		OneOf: []*Schema{
			{Type: "object"},
			{Type: "object"},
		},
	}

	data := map[string]any{}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid for matching multiple oneOf schemas")
	}
}

func TestValidate_ObjectOneOf_None(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		OneOf: []*Schema{
			{Type: "object", Required: []string{"x"}},
		},
	}

	data := map[string]any{}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid for matching zero oneOf schemas")
	}
}

func TestValidate_ObjectInvalidPropType(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"age": {Type: "integer"},
		},
	}

	data := map[string]any{"age": "not-int"}
	result := validator.Validate(data, schema, "obj")
	if result.Valid {
		t.Error("Expected invalid for wrong property type")
	}
}

// ============================================================================
// Enum validation
// ============================================================================

func TestValidate_EnumNumbers(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{
		Type: "integer",
		Enum: []any{1, 2, 3, 4, 5},
	}

	result := validator.Validate(3, schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid for integer enum match, got errors: %v", result.Errors)
	}

	result = validator.Validate(99, schema, "field")
	if result.Valid {
		t.Error("Expected invalid for integer not in enum")
	}
}

// ============================================================================
// Format validation: exhaustive coverage
// ============================================================================

func TestValidate_Format_URL(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "uri"}

	for _, u := range []string{"http://example.com", "https://example.com/path?q=1"} {
		result := validator.Validate(u, schema, "field")
		if !result.Valid {
			t.Errorf("Expected valid URI for '%s', got errors: %v", u, result.Errors)
		}
	}

	result := validator.Validate("ftp://example.com", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for ftp:// URL with 'uri' format")
	}

	schema = &Schema{Type: "string", Format: "url"}
	result = validator.Validate("https://example.com", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid URL for 'url' format, got errors: %v", result.Errors)
	}
}

func TestValidate_Format_DateTime(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "date-time"}

	validDates := []string{
		"2024-01-15T10:30:00Z",
		"2024-01-15T10:30:00+03:00",
		"2024-01-15T10:30:00.123Z",
	}
	for _, d := range validDates {
		result := validator.Validate(d, schema, "field")
		if !result.Valid {
			t.Errorf("Expected valid date-time for '%s', got errors: %v", d, result.Errors)
		}
	}

	result := validator.Validate("not-a-datetime", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for bad date-time")
	}
}

func TestValidate_Format_IPv4(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "ipv4"}

	result := validator.Validate("192.168.1.1", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid IPv4, got errors: %v", result.Errors)
	}

	result = validator.Validate("256.1.1.1", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for out-of-range IPv4 octet")
	}

	result = validator.Validate("not-an-ip", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for non-IPv4 string")
	}
}

func TestValidate_Format_IPv6(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "ipv6"}

	result := validator.Validate("::1", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid IPv6 '::1', got errors: %v", result.Errors)
	}

	result = validator.Validate("2001:db8::1", schema, "field")
	if !result.Valid {
		t.Errorf("Expected valid IPv6 '2001:db8::1', got errors: %v", result.Errors)
	}

	result = validator.Validate("not-an-ipv6", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for non-IPv6 string")
	}

	result = validator.Validate("192.168.1.1", schema, "field")
	if result.Valid {
		t.Error("Expected IPv4 to be invalid for ipv6 format")
	}
}

func TestValidate_Format_Hostname(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "hostname"}

	for _, h := range []string{"example.com", "sub.example.com", "localhost", "a"} {
		result := validator.Validate(h, schema, "field")
		if !result.Valid {
			t.Errorf("Expected valid hostname for '%s', got errors: %v", h, result.Errors)
		}
	}

	longHost := strings.Repeat("a", 254)
	result := validator.Validate(longHost, schema, "field")
	if result.Valid {
		t.Error("Expected invalid for hostname exceeding 253 chars")
	}

	result = validator.Validate("-invalid.com", schema, "field")
	if result.Valid {
		t.Error("Expected invalid for hostname starting with dash")
	}
}

func TestValidate_Format_Unknown(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{Type: "string", Format: "custom-unknown-format"}
	result := validator.Validate("anything", schema, "field")
	if !result.Valid {
		t.Errorf("Expected unknown format to pass, got errors: %v", result.Errors)
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func TestGetJSONType_AllTypes(t *testing.T) {
	tests := []struct {
		value    any
		expected string
	}{
		{"hello", "string"},
		{float64(3.14), "number"},
		{true, "boolean"},
		{nil, "null"},
		{[]any{1, 2}, "array"},
		{map[string]any{"a": 1}, "object"},
		{42, "integer"},
		{int64(42), "integer"},
	}

	for _, tc := range tests {
		got := getJSONType(tc.value)
		if got != tc.expected {
			t.Errorf("getJSONType(%v) = %q, want %q", tc.value, got, tc.expected)
		}
	}
}

func TestIsInteger(t *testing.T) {
	tests := []struct {
		value any
		want  bool
	}{
		{42, true},
		{int64(42), true},
		{float64(42.0), true},
		{float64(42.5), false},
		{"42", false},
	}
	for _, tc := range tests {
		got := isInteger(tc.value)
		if got != tc.want {
			t.Errorf("isInteger(%v) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		value any
		want  float64
		ok    bool
	}{
		{float64(3.14), 3.14, true},
		{42, 42.0, true},
		{int64(99), 99.0, true},
		{"nope", 0, false},
	}
	for _, tc := range tests {
		got := toFloat64(tc.value)
		if tc.ok {
			if got == nil || *got != tc.want {
				t.Errorf("toFloat64(%v) = %v, want %v", tc.value, got, tc.want)
			}
		} else {
			if got != nil {
				t.Errorf("toFloat64(%v) = %v, want nil", tc.value, got)
			}
		}
	}
}

func TestValidateEmail(t *testing.T) {
	valid := []string{"user@example.com", "a+b@c.co", "x@y.zw"}
	for _, e := range valid {
		if !validateEmail(e) {
			t.Errorf("Expected '%s' to be valid email", e)
		}
	}
	invalid := []string{"no-at", "@no-local", "no-domain@"}
	for _, e := range invalid {
		if validateEmail(e) {
			t.Errorf("Expected '%s' to be invalid email", e)
		}
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://example.com", true},
		{"https://example.com/path", true},
		{"ftp://example.com", false},
		{"not-a-url", false},
	}
	for _, tc := range tests {
		got := validateURL(tc.url)
		if got != tc.want {
			t.Errorf("validateURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestValidateIPv4(t *testing.T) {
	valid := []string{"0.0.0.0", "255.255.255.255", "192.168.1.1"}
	for _, ip := range valid {
		if !validateIPv4(ip) {
			t.Errorf("Expected '%s' to be valid IPv4", ip)
		}
	}
	invalid := []string{"256.0.0.1", "not-an-ip", "1.2.3.4.5"}
	for _, ip := range invalid {
		if validateIPv4(ip) {
			t.Errorf("Expected '%s' to be invalid IPv4", ip)
		}
	}
}

func TestValidateIPv6(t *testing.T) {
	valid := []string{"::1", "2001:db8::1"}
	for _, ip := range valid {
		if !validateIPv6(ip) {
			t.Errorf("Expected '%s' to be valid IPv6", ip)
		}
	}
	invalid := []string{"not-an-ip", "192.168.1.1"}
	for _, ip := range invalid {
		if validateIPv6(ip) {
			t.Errorf("Expected '%s' to be invalid IPv6", ip)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	valid := []string{"example.com", "sub.domain.org", "localhost"}
	for _, h := range valid {
		if !validateHostname(h) {
			t.Errorf("Expected '%s' to be valid hostname", h)
		}
	}
	if validateHostname(strings.Repeat("a", 254)) {
		t.Error("Expected too-long hostname to be invalid")
	}
}

// ============================================================================
// Schema cache
// ============================================================================

func TestSchemaCache_PutExistingKey(t *testing.T) {
	cache := NewSchemaCache(5)

	cache.Put("key1", &CompiledSchema{Path: "/a", Method: "GET"})
	cache.Put("key1", &CompiledSchema{Path: "/a", Method: "POST"})

	got := cache.Get("key1")
	if got == nil || got.Method != "POST" {
		t.Errorf("Expected updated schema, got %v", got)
	}
}

func TestSchemaCache_MoveToEnd(t *testing.T) {
	cache := NewSchemaCache(5)

	cache.Put("a", &CompiledSchema{})
	cache.Put("b", &CompiledSchema{})
	cache.Put("c", &CompiledSchema{})

	cache.Put("a", &CompiledSchema{Path: "/updated"})

	got := cache.Get("a")
	if got == nil || got.Path != "/updated" {
		t.Error("Expected 'a' to be updated")
	}
}

func TestSchemaCache_DefaultSize(t *testing.T) {
	cache := NewSchemaCache(0)
	if cache.maxSize != 100 {
		t.Errorf("Expected default maxSize 100, got %d", cache.maxSize)
	}
	cache = NewSchemaCache(-1)
	if cache.maxSize != 100 {
		t.Errorf("Expected default maxSize 100, got %d", cache.maxSize)
	}
}

func TestSchemaCache_GetMiss(t *testing.T) {
	cache := NewSchemaCache(5)
	if cache.Get("nonexistent") != nil {
		t.Error("Expected nil for cache miss")
	}
}

// ============================================================================
// getCachedPattern
// ============================================================================

func TestGetCachedPattern_Valid(t *testing.T) {
	re, err := getCachedPattern("^[a-z]+$")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !re.MatchString("hello") {
		t.Error("Expected pattern to match 'hello'")
	}
}

func TestGetCachedPattern_Invalid(t *testing.T) {
	_, err := getCachedPattern("[invalid regex(")
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}
}

// ============================================================================
// Layer: SetEnabled, GetSpecs, RemoveSchema, GetRoute
// ============================================================================

func TestLayer_SetEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer := NewLayer(cfg)
	if !layer.enabled {
		t.Error("Expected enabled when cfg.Enabled=true")
	}
	layer.SetEnabled(false)
	if layer.enabled {
		t.Error("Expected disabled after SetEnabled(false)")
	}
	layer.SetEnabled(true)
	if !layer.enabled {
		t.Error("Expected enabled after SetEnabled(true)")
	}
}

func TestLayer_GetSpecs(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	specs := layer.GetSpecs()
	if len(specs) != 0 {
		t.Errorf("Expected 0 specs initially, got %d", len(specs))
	}
}

func TestLayer_RemoveSchema(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/test": {
				Get: &Operation{Summary: "Test endpoint"},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "test.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	if len(layer.GetSpecs()) != 1 {
		t.Fatalf("Expected 1 spec after loading, got %d", len(layer.GetSpecs()))
	}

	removed := layer.RemoveSchema(specPath)
	if !removed {
		t.Error("Expected RemoveSchema to return true")
	}
	if len(layer.GetSpecs()) != 0 {
		t.Errorf("Expected 0 specs after removal, got %d", len(layer.GetSpecs()))
	}

	removed = layer.RemoveSchema("nonexistent")
	if removed {
		t.Error("Expected RemoveSchema to return false for nonexistent")
	}
}

func TestLayer_GetRoute(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/users/{id}": {
				Get: &Operation{
					Summary: "Get user",
					Parameters: []Parameter{
						{Name: "id", In: "path", Required: true, Schema: &Schema{Type: "string"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "test.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	route := layer.GetRoute("GET", "/users/123")
	if route == nil {
		t.Error("Expected to find route for GET /users/123")
	}

	route = layer.GetRoute("POST", "/users/123")
	if route != nil {
		t.Error("Expected no route for POST /users/123")
	}
}

// ============================================================================
// Layer: LoadSchema with OpenAPI JSON, YAML, JSONSchema
// ============================================================================

func TestLayer_LoadSchema_OpenAPI_JSON(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test API", Version: "1.0"},
		Paths: map[string]PathItem{
			"/users": {
				Get: &Operation{
					Summary: "List users",
					Parameters: []Parameter{
						{Name: "limit", In: "query", Schema: &Schema{Type: "integer"}},
					},
				},
				Post: &Operation{
					Summary: "Create user",
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type:     "object",
									Required: []string{"name"},
									Properties: map[string]*Schema{
										"name":  {Type: "string"},
										"email": {Type: "string", Format: "email"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "openapi.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load OpenAPI JSON schema: %v", err)
	}

	stats := layer.GetStats()
	if stats.SpecsLoaded != 1 {
		t.Errorf("Expected 1 spec loaded, got %d", stats.SpecsLoaded)
	}
}

func TestLayer_LoadSchema_OpenAPI_YAML(t *testing.T) {
	yamlContent := `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /items:
    get:
      summary: List items
`
	specPath := writeTestFile(t, "openapi.yaml", []byte(yamlContent))

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load OpenAPI YAML schema: %v", err)
	}
}

func TestLayer_LoadSchema_JSONSchema(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
		},
		"required": []any{"name"},
	}
	data, _ := json.Marshal(schema)
	specPath := writeTestFile(t, "schema.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "jsonschema"})
	if err != nil {
		t.Fatalf("Failed to load JSON Schema: %v", err)
	}
}

func TestLayer_LoadSchema_UnknownType(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: "test", Type: "unknown"})
	if err == nil {
		t.Error("Expected error for unknown schema type")
	}
}

func TestLayer_LoadSchema_InvalidPath(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: "/nonexistent/path/spec.json", Type: "openapi"})
	if err == nil {
		t.Error("Expected error for nonexistent file path")
	}
}

func TestLayer_LoadSchema_InvalidJSON(t *testing.T) {
	specPath := writeTestFile(t, "bad.json", []byte("not valid json {{{"))

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestLayer_LoadSchema_PathOutsideCWD(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: "/etc/passwd", Type: "openapi"})
	if err == nil {
		t.Error("Expected error for path outside allowed directory")
	}
}

func TestLayer_LoadSchema_InvalidJSONSchema(t *testing.T) {
	specPath := writeTestFile(t, "bad-schema.json", []byte("not valid json {{{"))

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "jsonschema"})
	if err == nil {
		t.Error("Expected error for invalid JSON in jsonschema type")
	}
}

// ============================================================================
// Layer: Process with loaded schema -- full pipeline
// ============================================================================

func setupLayerWithSpec(t *testing.T) *Layer {
	t.Helper()

	apFalse := false

	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test API", Version: "1.0"},
		Paths: map[string]PathItem{
			"/users/{id}": {
				Get: &Operation{
					Summary: "Get user",
					Parameters: []Parameter{
						{Name: "id", In: "path", Required: true, Schema: &Schema{Type: "string", MinLength: ptrInt(1)}},
						{Name: "fields", In: "query", Schema: &Schema{Type: "string"}},
						{Name: "X-Request-ID", In: "header", Required: true, Schema: &Schema{Type: "string", Format: "uuid"}},
					},
				},
				Put: &Operation{
					Summary: "Update user",
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type:     "object",
									Required: []string{"name", "email"},
									Properties: map[string]*Schema{
										"name":  {Type: "string"},
										"email": {Type: "string", Format: "email"},
									},
									AdditionalProperties: &apFalse,
								},
							},
						},
					},
				},
				Delete: &Operation{
					Summary: "Delete user",
				},
			},
			"/items": {
				Post: &Operation{
					Summary: "Create item",
					Parameters: []Parameter{
						{Name: "category", In: "query", Required: true, Schema: &Schema{Type: "string"}},
					},
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type: "object",
									Properties: map[string]*Schema{
										"name": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "test.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = false
	cfg.BlockOnViolation = true
	cfg.ViolationScore = 40

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	return layer
}

func TestLayer_Process_ValidGETRequest(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/users/123",
		Headers: map[string][]string{
			"X-Request-Id": {"550e8400-e29b-41d4-a716-446655440000"},
		},
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass/log, got block. Findings: %v", result.Findings)
	}
}

func TestLayer_Process_MissingRequiredHeader(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/users/123",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for missing required header, got %v", result.Action)
	}
}

func TestLayer_Process_InvalidHeaderFormat(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/users/123",
		Headers: map[string][]string{
			"X-Request-Id": {"not-a-uuid"},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for invalid header format, got %v", result.Action)
	}
}

func TestLayer_Process_ValidPUTWithBody(t *testing.T) {
	layer := setupLayerWithSpec(t)

	body := `{"name":"Alice","email":"alice@example.com"}`
	ctx := &engine.RequestContext{
		Method: "PUT",
		Path:   "/users/42",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(body),
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid PUT body, got block. Findings: %v", result.Findings)
	}
}

func TestLayer_Process_InvalidBodyJSON(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "PUT",
		Path:   "/users/42",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte("{invalid json}"),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for invalid JSON body, got %v", result.Action)
	}
}

func TestLayer_Process_BodyMissingRequired(t *testing.T) {
	layer := setupLayerWithSpec(t)

	body := `{"name":"Alice"}`
	ctx := &engine.RequestContext{
		Method: "PUT",
		Path:   "/users/42",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(body),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for missing required field in body, got %v. Findings: %v", result.Action, result.Findings)
	}
}

func TestLayer_Process_BodyRequiredButEmpty(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method:  "PUT",
		Path:    "/users/42",
		Headers: map[string][]string{},
		Body:    []byte{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for missing required body, got %v", result.Action)
	}
}

func TestLayer_Process_FormData(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/items",
		Headers: map[string][]string{
			"Content-Type": {"application/x-www-form-urlencoded"},
		},
		QueryParams: map[string][]string{
			"category": {"books"},
			"name":     {"test item"},
		},
		Body: []byte("category=books&name=test+item"),
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid form data, got block. Findings: %v", result.Findings)
	}
}

func TestLayer_Process_MultipartFormData(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/items",
		Headers: map[string][]string{
			"Content-Type": {"multipart/form-data; boundary=---abc"},
		},
		QueryParams: map[string][]string{
			"category": {"books"},
		},
		Body: []byte("some body"),
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass/log for multipart form data, got block. Findings: %v", result.Findings)
	}
}

func TestLayer_Process_MissingRequiredQuery(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method:      "POST",
		Path:        "/items",
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
		Body:        []byte(`{}`),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for missing required query param, got %v. Findings: %v", result.Action, result.Findings)
	}
}

func TestLayer_Process_DeleteNoParams(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method:  "DELETE",
		Path:    "/users/42",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for simple DELETE, got block. Findings: %v", result.Findings)
	}
}

func TestLayer_Process_LogOnViolation(t *testing.T) {
	layer := setupLayerWithSpec(t)
	layer.config.BlockOnViolation = false
	layer.config.ViolationScore = 30

	ctx := &engine.RequestContext{
		Method:      "POST",
		Path:        "/items",
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{},
		Body:        []byte(`{}`),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionLog {
		t.Errorf("Expected ActionLog when BlockOnViolation=false, got %v", result.Action)
	}
}

// ============================================================================
// Layer: Process with ValidateRequest disabled
// ============================================================================

func TestLayer_Process_ValidateRequestDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = false

	layer := NewLayer(cfg)
	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/anything",
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass when ValidateRequest=false, got %v", result.Action)
	}
}

// ============================================================================
// Layer: Process with tenant config override
// ============================================================================

func TestLayer_Process_TenantNil(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/users/123",
		Headers: map[string][]string{
			"X-Request-Id": {"550e8400-e29b-41d4-a716-446655440000"},
		},
	}

	result := layer.Process(ctx)
	_ = result
}

// ============================================================================
// PathRouter
// ============================================================================

func TestPathRouter_NoMethod(t *testing.T) {
	router := NewPathRouter()
	router.AddRoute("GET", "/test", &RouteInfo{Path: "/test", Method: "GET"})

	result := router.Match("PUT", "/test")
	if result != nil {
		t.Error("Expected nil for unregistered method")
	}
}

func TestPathRouter_PatternMatch(t *testing.T) {
	router := NewPathRouter()
	pattern := regexp.MustCompile("^/api/users/([^/]+)$")
	router.AddRoute("GET", "/api/users/{id}", &RouteInfo{
		Path: "/api/users/{id}", Method: "GET", Pattern: pattern,
	})

	result := router.Match("GET", "/api/users/abc")
	if result == nil {
		t.Error("Expected to match pattern")
	}
}

// ============================================================================
// compilePathPattern
// ============================================================================

func TestCompilePathPattern_NoParams(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	pattern := layer.compilePathPattern("/api/users")
	if pattern == nil {
		t.Fatal("Expected non-nil pattern")
	}
	if !pattern.MatchString("/api/users") {
		t.Error("Expected pattern to match /api/users")
	}
	if pattern.MatchString("/api/users/extra") {
		t.Error("Expected pattern not to match /api/users/extra")
	}
}

func TestCompilePathPattern_MultipleParams(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	pattern := layer.compilePathPattern("/api/{version}/users/{id}/posts/{postId}")
	if pattern == nil {
		t.Fatal("Expected non-nil pattern")
	}
	if !pattern.MatchString("/api/v2/users/42/posts/99") {
		t.Error("Expected pattern to match with multiple params")
	}
}

func TestCompilePathPattern_PlainPath(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	pattern := layer.compilePathPattern("/api/v1.0/data")
	if pattern == nil {
		t.Fatal("Expected pattern to compile")
	}
	if !pattern.MatchString("/api/v1.0/data") {
		t.Error("Expected pattern to match /api/v1.0/data")
	}
}

// ============================================================================
// getAdditionalProperties
// ============================================================================

func TestGetAdditionalProperties_ExplicitTrue(t *testing.T) {
	apTrue := true
	cfg := DefaultConfig()
	cfg.StrictMode = false
	layer := NewLayer(cfg)

	result := layer.getAdditionalProperties(&Schema{AdditionalProperties: &apTrue})
	if !result {
		t.Error("Expected true for explicit additionalProperties: true")
	}
}

func TestGetAdditionalProperties_NilNonStrict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StrictMode = false
	layer := NewLayer(cfg)

	result := layer.getAdditionalProperties(&Schema{})
	if !result {
		t.Error("Expected true for nil additionalProperties in non-strict mode")
	}
}

func TestGetAdditionalProperties_NilStrict(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StrictMode = true
	layer := NewLayer(cfg)

	result := layer.getAdditionalProperties(&Schema{})
	if result {
		t.Error("Expected false for nil additionalProperties in strict mode")
	}
}

// ============================================================================
// YAML functions
// ============================================================================

func TestYAMLToJSON_Simple(t *testing.T) {
	yamlData := []byte("key: value\nnumber: 42\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if result["key"] != "value" {
		t.Errorf("Expected key='value', got %v", result["key"])
	}
	// Our YAML parser may return int as int64 or float64 depending on value
	numVal := result["number"]
	if numVal != int64(42) && numVal != float64(42) {
		t.Errorf("Expected number=42, got %v (%T)", numVal, numVal)
	}
}

func TestYAMLToJSON_NestedObject(t *testing.T) {
	yamlData := []byte("parent:\n  child: value\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	parent, ok := result["parent"].(map[string]any)
	if !ok {
		t.Fatal("Expected parent to be a map")
	}
	if parent["child"] != "value" {
		t.Errorf("Expected child='value', got %v", parent["child"])
	}
}

func TestYAMLToJSON_BooleanValues(t *testing.T) {
	yamlData := []byte("yes_val: yes\nno_val: no\ntrue_val: true\nfalse_val: false\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if result["yes_val"] != true {
		t.Errorf("Expected yes_val=true, got %v", result["yes_val"])
	}
	if result["no_val"] != false {
		t.Errorf("Expected no_val=false, got %v", result["no_val"])
	}
}

func TestYAMLToJSON_NullValues(t *testing.T) {
	yamlData := []byte("null_val: null\ntilde_val: ~\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if result["null_val"] != nil {
		t.Errorf("Expected null_val=nil, got %v", result["null_val"])
	}
	if result["tilde_val"] != nil {
		t.Errorf("Expected tilde_val=nil, got %v", result["tilde_val"])
	}
}

func TestYAMLToJSON_QuotedStrings(t *testing.T) {
	yamlData := []byte("double: \"hello world\"\nsingle: 'hello world'\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if result["double"] != "hello world" {
		t.Errorf("Expected double='hello world', got %v", result["double"])
	}
	if result["single"] != "hello world" {
		t.Errorf("Expected single='hello world', got %v", result["single"])
	}
}

func TestYAMLToJSON_Float(t *testing.T) {
	yamlData := []byte("pi: 3.14\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if v, ok := result["pi"].(float64); !ok || v != 3.14 {
		t.Errorf("Expected pi=3.14, got %v", result["pi"])
	}
}

func TestYAMLToJSON_Empty(t *testing.T) {
	_, err := YAMLToJSON([]byte(""))
	if err == nil {
		t.Error("Expected error for empty YAML")
	}
}

func TestYAMLToJSON_CommentsAndEmptyLines(t *testing.T) {
	yamlData := []byte("# This is a comment\nkey: value\n\n# Another comment\nother: 42\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if result["key"] != "value" {
		t.Errorf("Expected key='value', got %v", result["key"])
	}
}

func TestYAMLToJSON_DocumentSeparator(t *testing.T) {
	yamlData := []byte("---\nkey: value\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)
	if result["key"] != "value" {
		t.Errorf("Expected key='value', got %v", result["key"])
	}
}

func TestYAMLToJSON_OnOff(t *testing.T) {
	yamlData := []byte("on_val: on\noff_val: off\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	json.Unmarshal(jsonData, &result)

	if result["on_val"] != true {
		t.Errorf("Expected on_val=true, got %v", result["on_val"])
	}
	if result["off_val"] != false {
		t.Errorf("Expected off_val=false, got %v", result["off_val"])
	}
}

func TestYAMLToJSON_MultilineString(t *testing.T) {
	yamlData := []byte("text: |\n  line one\n  line two\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}
	_ = jsonData
}

func TestLoadYAMLSpec(t *testing.T) {
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /test:
    get:
      summary: Test
`)

	spec, err := LoadYAMLSpec(yamlData)
	if err != nil {
		t.Fatalf("LoadYAMLSpec error: %v", err)
	}
	if spec.OpenAPI != "3.0.0" {
		t.Errorf("Expected openapi='3.0.0', got %s", spec.OpenAPI)
	}
	if spec.Info.Title != "Test API" {
		t.Errorf("Expected title='Test API', got %s", spec.Info.Title)
	}
}

func TestLoadYAMLSpec_Invalid(t *testing.T) {
	// Empty YAML should error
	_, err := LoadYAMLSpec([]byte(""))
	if err == nil {
		t.Error("Expected error for empty YAML")
	}
}

func TestIsYAML(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"key: value\n", true},
		{"nested:\n  child: val\n", true},
		{"- item1\n- item2\n", true},
		{"---\nkey: value\n", true},
		{"plain text without yaml markers", false},
		{"", false},
		{"# just a comment\n", false},
	}

	for _, tc := range tests {
		got := IsYAML([]byte(tc.input))
		if got != tc.want {
			t.Errorf("IsYAML(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestSimpleYAMLUnmarshal(t *testing.T) {
	yamlData := []byte("name: test\ncount: 42\n")
	var result struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}
	err := SimpleYAMLUnmarshal(yamlData, &result)
	if err != nil {
		t.Fatalf("SimpleYAMLUnmarshal error: %v", err)
	}
	if result.Name != "test" {
		t.Errorf("Expected name='test', got '%s'", result.Name)
	}
}

func TestCountIndent(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"no indent", 0},
		{"  two spaces", 2},
		{"    four spaces", 4},
		{"\ttab", 2},
		{"  \t  mixed", 6},
	}

	for _, tc := range tests {
		got := countIndent(tc.line)
		if got != tc.want {
			t.Errorf("countIndent(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestParseYAMLValue(t *testing.T) {
	tests := []struct {
		input string
		want  any
	}{
		{"", ""},
		{`"quoted"`, "quoted"},
		{`'single'`, "single"},
		{"true", true},
		{"false", false},
		{"yes", true},
		{"no", false},
		{"on", true},
		{"off", false},
		{"null", nil},
		{"~", nil},
		{"42", int64(42)},
		{"3.14", 3.14},
		{"|multiline", ""},
		{">folded", ""},
		{"hello", "hello"},
	}

	for _, tc := range tests {
		got := parseYAMLValue(tc.input)
		if got != tc.want {
			t.Errorf("parseYAMLValue(%q) = %v (%T), want %v (%T)",
				tc.input, got, got, tc.want, tc.want)
		}
	}
}

func TestParseYAMLLine(t *testing.T) {
	tests := []struct {
		line        string
		key         string
		value       string
		isArrayItem bool
	}{
		{"key: value", "key", "value", false},
		{"nested:", "nested", "", false},
		{"- item", "", "item", true},
		{"- key: value", "key", "value", true},
		{"- nested:", "nested", "", true},
	}

	for _, tc := range tests {
		k, v, arr := parseYAMLLine(tc.line)
		if k != tc.key || v != tc.value || arr != tc.isArrayItem {
			t.Errorf("parseYAMLLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, k, v, arr, tc.key, tc.value, tc.isArrayItem)
		}
	}
}

// ============================================================================
// Layer: LoadSchema with all HTTP methods
// ============================================================================

func TestLayer_LoadSchema_AllMethods(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/test": {
				Get:     &Operation{Summary: "GET"},
				Post:    &Operation{Summary: "POST"},
				Put:     &Operation{Summary: "PUT"},
				Delete:  &Operation{Summary: "DELETE"},
				Patch:   &Operation{Summary: "PATCH"},
				Head:    &Operation{Summary: "HEAD"},
				Options: &Operation{Summary: "OPTIONS"},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "allmethods.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		route := layer.GetRoute(method, "/test")
		if route == nil {
			t.Errorf("Expected route for %s /test", method)
		}
	}
}

// ============================================================================
// Layer: LoadSchema with common parameters + operation parameters merge
// ============================================================================

func TestLayer_LoadSchema_CommonAndOperationParams(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/test": {
				Parameters: []Parameter{
					{Name: "common", In: "query", Schema: &Schema{Type: "string"}},
				},
				Get: &Operation{
					Summary: "Test",
					Parameters: []Parameter{
						{Name: "op_param", In: "query", Schema: &Schema{Type: "integer"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "params.json", data)

	layer := NewLayer(DefaultConfig())
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	route := layer.GetRoute("GET", "/test")
	if route == nil {
		t.Fatal("Expected route")
	}
	if len(route.Parameters) != 2 {
		t.Errorf("Expected 2 params (common + op), got %d", len(route.Parameters))
	}
}

// ============================================================================
// NewLayer with nil config
// ============================================================================

func TestNewLayer_NilConfig(t *testing.T) {
	layer := NewLayer(nil)
	// DefaultConfig has Enabled=false
	if layer.enabled {
		t.Error("Expected disabled (DefaultConfig has Enabled=false)")
	}
	if layer.Name() != "apivalidation" {
		t.Errorf("Expected name 'apivalidation', got '%s'", layer.Name())
	}
}

// ============================================================================
// Layer: compileOperation with request body
// ============================================================================

func TestLayer_CompileOperation_BodySchema(t *testing.T) {
	apTrue := true
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/data": {
				Post: &Operation{
					Summary: "Post data",
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type:                 "object",
									AdditionalProperties: &apTrue,
									Properties: map[string]*Schema{
										"key": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "bodyspec.json", data)

	cfg := DefaultConfig()
	cfg.StrictMode = false
	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	route := layer.GetRoute("POST", "/data")
	if route == nil {
		t.Fatal("Expected route for POST /data")
	}
	if route.BodySchema == nil {
		t.Fatal("Expected BodySchema to be set")
	}
	if !route.BodySchema.AdditionalProperties {
		t.Error("Expected AdditionalProperties=true")
	}
}

// ============================================================================
// Full Process pipeline with YAML schema loaded from file
// ============================================================================

func TestLayer_Process_WithYAMLSpec(t *testing.T) {
	yamlContent := `openapi: "3.0.0"
info:
  title: YAML API
  version: "1.0"
paths:
  /hello:
    get:
      summary: Say hello
`
	specPath := writeTestFile(t, "api.yaml", []byte(yamlContent))

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = false

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load YAML schema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/hello",
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid GET /hello, got block. Findings: %v", result.Findings)
	}
}

// ============================================================================
// Process: body with no content-type header defaults to application/json
// ============================================================================

func TestLayer_Process_BodyNoContentType(t *testing.T) {
	layer := setupLayerWithSpec(t)

	body := `{"name":"Alice","email":"alice@example.com"}`
	ctx := &engine.RequestContext{
		Method:  "PUT",
		Path:    "/users/42",
		Headers: map[string][]string{},
		Body:    []byte(body),
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid body without Content-Type, got block. Findings: %v", result.Findings)
	}
}

// ============================================================================
// Process: validate path params with invalid value
// ============================================================================

func TestLayer_Process_InvalidPathParam(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/items/{id}": {
				Get: &Operation{
					Summary: "Get item",
					Parameters: []Parameter{
						{Name: "id", In: "path", Required: true, Schema: &Schema{
							Type:    "string",
							Pattern: "^[0-9]+$",
						}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "pathparam.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.BlockOnViolation = true
	cfg.ViolationScore = 40

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/items/abc",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for non-numeric path param, got %v. Findings: %v", result.Action, result.Findings)
	}
}

// ============================================================================
// Process: validate query params
// ============================================================================

func TestLayer_Process_QueryParamsMultipleValues(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/search": {
				Get: &Operation{
					Summary: "Search",
					Parameters: []Parameter{
						{Name: "q", In: "query", Required: true, Schema: &Schema{Type: "string"}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "query.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.BlockOnViolation = false
	cfg.ViolationScore = 20

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/search",
		Headers: map[string][]string{},
		QueryParams: map[string][]string{
			"q": {"test query"},
		},
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid query param, got block. Findings: %v", result.Findings)
	}
}

// ============================================================================
// extractPathParam: path mismatch
// ============================================================================

func TestExtractPathParam_MismatchedStaticPart(t *testing.T) {
	layer := NewLayer(DefaultConfig())

	result := layer.extractPathParam("/api/users/123", "/api/items/{id}", "id")
	if result != "" {
		t.Errorf("Expected empty for mismatched static part, got '%s'", result)
	}
}

// ============================================================================
// Strict mode with no specs
// ============================================================================

func TestLayer_Process_StrictModeNoSpecs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = true
	cfg.BlockOnViolation = true
	cfg.ViolationScore = 50

	layer := NewLayer(cfg)

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/anything",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block in strict mode with no specs, got %v", result.Action)
	}
	if result.Score != 50 {
		t.Errorf("Expected score 50, got %d", result.Score)
	}
}

// ============================================================================
// Stats with loaded specs
// ============================================================================

func TestLayer_GetStats_WithRoutes(t *testing.T) {
	layer := setupLayerWithSpec(t)
	stats := layer.GetStats()

	if stats.SpecsLoaded != 1 {
		t.Errorf("Expected 1 spec, got %d", stats.SpecsLoaded)
	}
	if stats.RoutesDefined == 0 {
		t.Error("Expected routes to be defined")
	}
}

// ============================================================================
// Schema Validation: validate* called with wrong data type (early return)
// ============================================================================

func TestValidate_StringNonStringData(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "string", MinLength: ptrInt(5)}

	result := ValidationResult{Valid: true}
	validator.validateString(123, schema, "field", &result)
	if !result.Valid {
		t.Error("Expected no errors from validateString with non-string data")
	}
}

func TestValidate_ArrayNonArrayData(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "array", MinItems: ptrInt(1)}

	result := ValidationResult{Valid: true}
	validator.validateArray("not-an-array", schema, "field", &result)
	if !result.Valid {
		t.Error("Expected no errors from validateArray with non-array data")
	}
}

func TestValidate_ObjectNonObjectData(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "object", Required: []string{"name"}}

	result := ValidationResult{Valid: true}
	validator.validateObject("not-an-object", schema, "field", &result)
	if !result.Valid {
		t.Error("Expected no errors from validateObject with non-object data")
	}
}

func TestValidate_NumberNonNumericData(t *testing.T) {
	validator := NewSchemaValidator(true)
	min := 10.0
	schema := &Schema{Type: "number", Minimum: &min}

	result := ValidationResult{Valid: true}
	validator.validateNumber("not-a-number", schema, "field", &result)
	if !result.Valid {
		t.Error("Expected no errors from validateNumber with non-numeric data")
	}
}

// ============================================================================
// matchPatternSafe
// ============================================================================

func TestMatchPatternSafe(t *testing.T) {
	re := regexp.MustCompile(`^[a-z]+$`)
	if !matchPatternSafe(re, "hello") {
		t.Error("Expected 'hello' to match ^[a-z]+$")
	}
	if matchPatternSafe(re, "Hello123") {
		t.Error("Expected 'Hello123' not to match ^[a-z]+$")
	}
}

// ============================================================================
// Format: email edge cases
// ============================================================================

func TestValidate_Format_EmailInvalid(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "string", Format: "email"}

	result := validator.Validate("no-at-sign", schema, "email")
	if result.Valid {
		t.Error("Expected invalid for missing @ in email")
	}

	result = validator.Validate("@nodomain", schema, "email")
	if result.Valid {
		t.Error("Expected invalid for missing local part")
	}
}

// ============================================================================
// Full body validation with additional properties in strict mode
// ============================================================================

func TestLayer_Process_BodyAdditionalPropertiesStrict(t *testing.T) {
	apFalse := false
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/data": {
				Post: &Operation{
					Summary: "Post data",
					RequestBody: &RequestBody{
						Required: true,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type:                 "object",
									AdditionalProperties: &apFalse,
									Properties: map[string]*Schema{
										"name": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "strict.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = true
	cfg.BlockOnViolation = true
	cfg.ViolationScore = 40

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	body := `{"name":"test","extra":"not allowed"}`
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/data",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(body),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for additional property in strict mode, got %v. Findings: %v", result.Action, result.Findings)
	}
}

// ============================================================================
// Score calculation
// ============================================================================

func TestValidate_ScoreCalculation(t *testing.T) {
	validator := NewSchemaValidator(true)

	schema := &Schema{
		Type:     "object",
		Required: []string{"a", "b", "c"},
	}

	data := map[string]any{}
	result := validator.Validate(data, schema, "root")

	if result.Valid {
		t.Error("Expected invalid for missing required fields")
	}
	if result.Score != 30 {
		t.Errorf("Expected score 30, got %d", result.Score)
	}
}

// ============================================================================
// Process: body with invalid JSON but short body
// ============================================================================

func TestLayer_Process_InvalidJSONShortBody(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method: "PUT",
		Path:   "/users/42",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte("{bad}"),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for invalid JSON, got %v", result.Action)
	}
	if len(result.Findings) > 0 {
		if result.Findings[0].MatchedValue == "" {
			t.Error("Expected MatchedValue to be set for invalid JSON")
		}
	}
}

// ============================================================================
// Process: body validation errors with data representation
// ============================================================================

func TestLayer_Process_BodyValidationErrors(t *testing.T) {
	layer := setupLayerWithSpec(t)

	body := `{"name":"Alice","email":"not-email","extra":"field"}`
	ctx := &engine.RequestContext{
		Method: "PUT",
		Path:   "/users/42",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(body),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for invalid body, got %v. Findings: %v", result.Action, result.Findings)
	}
}

// ============================================================================
// Process: body with no body schema on route
// ============================================================================

func TestLayer_Process_NoBodySchema(t *testing.T) {
	layer := setupLayerWithSpec(t)

	ctx := &engine.RequestContext{
		Method:  "DELETE",
		Path:    "/users/42",
		Headers: map[string][]string{},
		Body:    []byte(`{"irrelevant":"data"}`),
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for DELETE with no body schema, got block. Findings: %v", result.Findings)
	}
}

// ============================================================================
// validateHeaders
// ============================================================================

func TestLayer_Process_HeaderValidation(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/test": {
				Get: &Operation{
					Summary: "Test",
					Parameters: []Parameter{
						{Name: "X-Api-Key", In: "header", Required: true, Schema: &Schema{
							Type:    "string",
							Pattern: "^[a-zA-Z0-9]{32}$",
						}},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "headers.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.BlockOnViolation = true
	cfg.ViolationScore = 40

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
		Headers: map[string][]string{
			"X-Api-Key": {"abcdefghijklmnopqrstuvwxyz123456"},
		},
	}
	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for valid header, got block. Findings: %v", result.Findings)
	}

	ctx = &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
		Headers: map[string][]string{
			"X-Api-Key": {"short"},
		},
	}
	result = layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for invalid header format, got %v. Findings: %v", result.Action, result.Findings)
	}
}

// ============================================================================
// Edge case: body is empty but not required
// ============================================================================

func TestLayer_Process_BodyNotRequired(t *testing.T) {
	spec := OpenAPISpec{
		OpenAPI: "3.0.0",
		Info:    Info{Title: "Test", Version: "1.0"},
		Paths: map[string]PathItem{
			"/test": {
				Post: &Operation{
					Summary: "Test",
					RequestBody: &RequestBody{
						Required: false,
						Content: map[string]MediaType{
							"application/json": {
								Schema: &Schema{
									Type: "object",
									Properties: map[string]*Schema{
										"name": {Type: "string"},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(spec)
	specPath := writeTestFile(t, "optbody.json", data)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.BlockOnViolation = true

	layer := NewLayer(cfg)
	err := layer.LoadSchema(SchemaSource{Path: specPath, Type: "openapi"})
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}

	ctx := &engine.RequestContext{
		Method:  "POST",
		Path:    "/test",
		Headers: map[string][]string{},
		Body:    []byte{},
	}

	result := layer.Process(ctx)
	if result.Action == engine.ActionBlock {
		t.Errorf("Expected pass for empty body when not required, got block. Findings: %v", result.Findings)
	}
}

// ============================================================================
// Format validation for all types
// ============================================================================

func TestValidateFormat_AllCases(t *testing.T) {
	validator := NewSchemaValidator(true)

	cases := []struct {
		format  string
		valid   string
		invalid string
	}{
		{"email", "user@example.com", "bad"},
		{"uri", "http://example.com", "noturl"},
		{"url", "https://example.com", "noturl"},
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", "notuuid"},
		{"date-time", "2024-01-15T10:30:00Z", "notdatetime"},
		{"date", "2024-01-15", "notdate"},
		{"ipv4", "192.168.1.1", "999.999.999.999"},
		{"ipv6", "::1", "notipv6"},
		{"hostname", "example.com", strings.Repeat("a", 254)},
		{"unknown-format", "anything", ""},
	}

	for _, tc := range cases {
		if !validator.validateFormat(tc.valid, tc.format) {
			t.Errorf("validateFormat(%q, %q) = false, want true", tc.valid, tc.format)
		}
		if tc.invalid != "" && validator.validateFormat(tc.invalid, tc.format) {
			t.Errorf("validateFormat(%q, %q) = true, want false", tc.invalid, tc.format)
		}
	}
}

func TestValidate_FormatURI_Invalid(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "string", Format: "uri"}

	result := validator.Validate("not-a-uri", schema, "url")
	if result.Valid {
		t.Error("Expected invalid for non-URL with uri format")
	}
}

func TestValidate_FormatUUID_Invalid(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "string", Format: "uuid"}

	result := validator.Validate("not-a-uuid", schema, "id")
	if result.Valid {
		t.Error("Expected invalid for non-UUID")
	}
}

func TestValidate_FormatDateTime_Invalid(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "string", Format: "date-time"}

	result := validator.Validate("not-a-datetime", schema, "dt")
	if result.Valid {
		t.Error("Expected invalid for bad date-time format")
	}
}

// ============================================================================
// YAML deep nesting
// ============================================================================

func TestYAMLToJSON_DeepNesting(t *testing.T) {
	yamlData := []byte("level1:\n  level2:\n    level3: deep\n")
	jsonData, err := YAMLToJSON(yamlData)
	if err != nil {
		t.Fatalf("YAMLToJSON error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	l1 := result["level1"].(map[string]any)
	l2 := l1["level2"].(map[string]any)
	if l2["level3"] != "deep" {
		t.Errorf("Expected level3='deep', got %v", l2["level3"])
	}
}

// Ensure fmt is used
var _ = fmt.Sprintf
