package apivalidation

import "testing"

// TestValidate_CombinatorsApplyToNonObjectData pins the hoist of the
// allOf/anyOf/oneOf loops out of validateObject into Validate. The combinators
// previously ran only for object-shaped instances, so a top-level oneOf/anyOf
// (the standard OpenAPI union-body shape) was silently unenforced for string,
// number, boolean, and array payloads: any violating non-object body validated
// as clean while the backend still parsed it.
func TestValidate_CombinatorsApplyToNonObjectData(t *testing.T) {
	validator := NewSchemaValidator(false)
	minLen := 5

	anyOfStringInteger := &Schema{AnyOf: []*Schema{
		{Type: "string"},
		{Type: "integer"},
	}}
	oneOfObjectArray := &Schema{OneOf: []*Schema{
		{Type: "object", Properties: map[string]*Schema{
			"a": {Type: "string"},
		}, Required: []string{"a"}},
		{Type: "array", Items: &Schema{Type: "integer"}},
	}}
	allOfStringConstraints := &Schema{AllOf: []*Schema{
		{Type: "string", MinLength: &minLen},
		{Type: "string", Pattern: "^[a-z]+$"},
	}}

	// Combinator violations on non-object data must be flagged.
	invalid := []struct {
		name   string
		schema *Schema
		data   any
	}{
		{"anyOf vs 3.14 matches neither branch", anyOfStringInteger, 3.14},
		{"oneOf vs [\"x\"] matches neither branch", oneOfObjectArray, []any{"x"}},
		{"allOf vs \"abc\" violates the minLength branch", allOfStringConstraints, "abc"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			result := validator.Validate(tc.data, tc.schema, "body")
			if result.Valid {
				t.Fatalf("expected invalid, got errors: %v", result.Errors)
			}
		})
	}

	// Matching data — including the object payloads covered by the original
	// object-only tests — must stay valid.
	valid := []struct {
		name   string
		schema *Schema
		data   any
	}{
		{"anyOf vs 42 matches the integer branch", anyOfStringInteger, 42.0},
		{"anyOf vs \"hello\" matches the string branch", anyOfStringInteger, "hello"},
		{"allOf vs \"abcde\" matches both branches", allOfStringConstraints, "abcde"},
		{"object anyOf (email branch) keeps working", &Schema{Type: "object", AnyOf: []*Schema{
			{Type: "object", Properties: map[string]*Schema{
				"email": {Type: "string"},
			}, Required: []string{"email"}},
			{Type: "object", Properties: map[string]*Schema{
				"phone": {Type: "string"},
			}, Required: []string{"phone"}},
		}}, map[string]any{"email": "a@b.com"}},
		{"object allOf (both branches) keeps working", &Schema{Type: "object", AllOf: []*Schema{
			{Type: "object", Properties: map[string]*Schema{
				"name": {Type: "string"},
			}, Required: []string{"name"}},
			{Type: "object", Properties: map[string]*Schema{
				"age": {Type: "integer"},
			}, Required: []string{"age"}},
		}}, map[string]any{"name": "Alice", "age": 30.0}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			result := validator.Validate(tc.data, tc.schema, "body")
			if !result.Valid {
				t.Fatalf("expected valid, got errors: %v", result.Errors)
			}
		})
	}
}
