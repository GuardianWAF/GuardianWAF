package apivalidation

import (
	"encoding/json"
	"math"
	"testing"
)

func TestIntegerSchemaAcceptsFiniteWholeJSONNumbers(t *testing.T) {
	validator := NewSchemaValidator(true)
	schema := &Schema{Type: "integer"}
	for _, tc := range []struct {
		json string
		want bool
	}{
		{"42", true},
		{"0", true},
		{"-1", true},
		{"1.5", false},
		{"100000000000000000000", true},
		{"-100000000000000000000", true},
		{"9223372036854775808", true},
		{"1e308", true},
	} {
		t.Run(tc.json, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(tc.json), &value); err != nil {
				t.Fatal(err)
			}
			got := validator.Validate(value, schema, "amount")
			if got.Valid != tc.want {
				t.Fatalf("valid=%v, want %v; errors=%v", got.Valid, tc.want, got.Errors)
			}
		})
	}
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if isInteger(value) || validator.Validate(value, schema, "amount").Valid {
			t.Fatalf("non-finite value %v accepted as an integer", value)
		}
	}
}
