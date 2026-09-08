package apivalidation

import "testing"

// Regression: validateObject's unknown-key check (additionalProperties:false
// and strict mode) lived INSIDE the `if schema.Properties != nil` guard, so a
// closed-object schema without a properties map — {type: object,
// additionalProperties: false} — flagged nothing, and strict mode was equally
// blind. JSON Schema treats that shape as "no keys allowed".
func TestObjectAdditionalPropertiesWithoutProperties(t *testing.T) {
	v := NewSchemaValidator(false)

	schema := &Schema{
		Type:                 "object",
		AdditionalProperties: boolPtr(false),
	}

	result := v.Validate(map[string]any{"evil": "payload"}, schema, "body")

	if result.Valid {
		t.Fatalf("FAIL: unknown key passed additionalProperties:false with nil properties map (errors: %v)", result.Errors)
	}
	found := false
	for _, e := range result.Errors {
		if e.Type == "additionalProperties" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: no additionalProperties error among %v", result.Errors)
	}
}

func TestStrictModeUnknownKeysWithoutProperties(t *testing.T) {
	v := NewSchemaValidator(true)

	schema := &Schema{Type: "object"}

	result := v.Validate(map[string]any{"evil": "payload"}, schema, "body")

	if result.Valid {
		t.Fatalf("FAIL: strict mode passed an unknown key with nil properties map (errors: %v)", result.Errors)
	}
}

func TestObjectDefinedPropertiesStillValidate(t *testing.T) {
	v := NewSchemaValidator(false)

	schema := &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"name": {Type: "string"},
		},
		AdditionalProperties: boolPtr(false),
	}

	bad := v.Validate(map[string]any{"name": 42}, schema, "body")
	if bad.Valid {
		t.Fatalf("FAIL: type violation on a defined property passed")
	}

	extra := v.Validate(map[string]any{"name": "ok", "evil": 1}, schema, "body")
	if extra.Valid {
		t.Fatalf("FAIL: unknown key passed with properties map present")
	}

	good := v.Validate(map[string]any{"name": "ok"}, schema, "body")
	if !good.Valid {
		t.Fatalf("FAIL: valid object rejected (errors: %v)", good.Errors)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// The non-strict default: with strict mode off and additionalProperties
// unset, JSON Schema's default (additionalProperties: true) applies — an
// unknown key is allowed on a property-less object schema.
func TestObjectUnknownKeyAllowedNonStrictNoProps(t *testing.T) {
	validator := NewSchemaValidator(false)

	schema := &Schema{Type: "object"}
	data := map[string]any{"key": "value"}
	result := validator.Validate(data, schema, "obj")
	if !result.Valid {
		t.Fatalf("FAIL: non-strict mode flagged an unknown key on a property-less object schema: %v", result.Errors)
	}
}
