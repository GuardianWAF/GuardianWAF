package apivalidation

// Regression tests for round 17/25: validateEnum must use deep equality.
// The pre-fix implementation compared enum values with == — JSON-decoded
// objects (map[string]any) and arrays ([]any) are uncomparable types, so
// validating an object-shaped payload against an object-valued enum (JSON
// Schema explicitly allows object/array enum members) PANICKED at runtime
// ("comparing uncomparable types"), killing the request goroutine on the
// API-validation enforcement path. Scalar enums must keep working.

import (
	"testing"
)

func validateEnumSafe(t *testing.T, data any, schema *Schema) (result ValidationResult, panicked bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	v := NewSchemaValidator(false)
	result = v.Validate(data, schema, "body")
	return result, false
}

func TestEnumObjectValuesDeepEquality(t *testing.T) {
	schema := &Schema{
		Type: "object",
		Enum: []any{
			map[string]any{"status": "ok"},
			map[string]any{"status": "maintenance"},
		},
	}

	// Matching object payload: valid, and must not panic.
	result, panicked := validateEnumSafe(t, map[string]any{"status": "ok"}, schema)
	if panicked {
		t.Fatalf("validating an object payload against an object-valued enum panicked — validateEnum compared with == and map[string]any is an uncomparable type")
	}
	if !result.Valid {
		t.Fatalf("a payload matching an object enum member was reported invalid: %+v", result.Errors)
	}

	// Mismatching object payload: invalid, still no panic.
	mismatch, panicked := validateEnumSafe(t, map[string]any{"status": "error"}, schema)
	if panicked {
		t.Fatalf("the mismatching object payload also panicked the validator")
	}
	if mismatch.Valid {
		t.Fatalf("a payload NOT in the enum was reported valid")
	}
}

func TestEnumArrayValuesDeepEquality(t *testing.T) {
	schema := &Schema{
		Enum: []any{
			[]any{"a", "b"},
		},
	}

	result, panicked := validateEnumSafe(t, []any{"a", "b"}, schema)
	if panicked {
		t.Fatalf("validating an array payload against an array-valued enum panicked — []any is uncomparable with ==")
	}
	if !result.Valid {
		t.Fatalf("a payload matching the array enum member was reported invalid: %+v", result.Errors)
	}
}

func TestEnumScalarControls(t *testing.T) {
	schema := &Schema{Enum: []any{"alpha", "beta"}}

	match, panicked := validateEnumSafe(t, "alpha", schema)
	if panicked {
		t.Fatalf("scalar enums must never panic")
	}
	if !match.Valid {
		t.Fatalf("a matching scalar enum value was reported invalid: %+v", match.Errors)
	}

	mismatch, _ := validateEnumSafe(t, "gamma", schema)
	if mismatch.Valid {
		t.Fatalf("a non-enum value was reported valid")
	}
}
