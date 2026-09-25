package apivalidation

// Regression (round 2026-09-24-r31-uniqueitems): Schema.UniqueItems was
// declared (schema.go) and parsed from specs but never referenced by any
// validator — validateArray enforced MinItems/MaxItems/Items and silently
// skipped uniqueness. A spec declaring uniqueItems: true validated duplicate
// items as clean. The keyword is now enforced with pairwise
// reflect.DeepEqual (JSON Schema deep equality — the validateEnum doctrine:
// decoded map/[]any elements are uncomparable with ==).

import "testing"

func uniqueItemsStrSchema() *Schema {
	return &Schema{Type: "array", UniqueItems: true, Items: &Schema{Type: "string"}}
}

func uniqueItemsObjSchema() *Schema {
	return &Schema{Type: "array", UniqueItems: true}
}

func TestUniqueItemsEnforced(t *testing.T) {
	v := NewSchemaValidator(false)

	cases := []struct {
		name      string
		schema    *Schema
		value     []any
		wantValid bool
	}{
		{"distinct strings", uniqueItemsStrSchema(), []any{"a", "b"}, true},
		{"duplicate strings", uniqueItemsStrSchema(), []any{"a", "a"}, false},
		{"deep-equal objects", uniqueItemsObjSchema(), []any{map[string]any{"x": float64(1)}, map[string]any{"x": float64(1)}}, false},
		{"distinct objects", uniqueItemsObjSchema(), []any{map[string]any{"x": float64(1)}, map[string]any{"x": float64(2)}}, true},
	}

	for _, tc := range cases {
		result := v.Validate(tc.value, tc.schema, "body")
		if result.Valid != tc.wantValid {
			t.Fatalf("%s: got Valid=%v, want %v (errors: %v)", tc.name, result.Valid, tc.wantValid, result.Errors)
		}
	}
}

func TestUniqueItemsNotEnforcedWhenFalse(t *testing.T) {
	v := NewSchemaValidator(false)
	schema := &Schema{Type: "array", UniqueItems: false, Items: &Schema{Type: "string"}}
	result := v.Validate([]any{"a", "a"}, schema, "body")
	if !result.Valid {
		t.Fatalf("UniqueItems=false must not enforce uniqueness: %v", result.Errors)
	}
}
