package crs

import (
	"testing"
	"time"
)

// TestVariableResolver_TimeFormat pins the ModSecurity semantics of the TIME*
// transaction variables. These previously used PHP-style date() specifiers
// ("H:i:s", "Y", "m", "d", "H", "i", "s") as Go time.Format layouts; Go's
// reference layout has no such placeholders, so every variable resolved to
// its own literal format string and any rule conditioned on TIME* evaluated
// against garbage.
func TestVariableResolver_TimeFormat(t *testing.T) {
	tx := NewTransaction()
	// Deterministic timestamp: 2025-06-15 14:30:09 UTC.
	tx.Timestamp = time.Date(2025, 6, 15, 14, 30, 9, 0, time.UTC)
	vr := NewVariableResolver(tx)

	tests := []struct {
		name string
		want string
	}{
		{"TIME", "14:30:09"},
		{"TIME_YEAR", "2025"},
		{"TIME_MON", "06"}, // zero-padded month boundary
		{"TIME_DAY", "15"},
		{"TIME_HOUR", "14"},
		{"TIME_MIN", "30"},
		{"TIME_SEC", "09"}, // zero-padded second boundary
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals, err := vr.Resolve(RuleVariable{Name: tt.name})
			if err != nil {
				t.Fatalf("Resolve(%s) error: %v", tt.name, err)
			}
			if len(vals) != 1 || vals[0] != tt.want {
				t.Errorf("Resolve(%s) = %v; want [%s]", tt.name, vals, tt.want)
			}
		})
	}
}
